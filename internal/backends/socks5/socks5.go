// Package socks5 implements a SOCKS5 proxy backend.
//
// The backend itself doesn't tunnel traffic at the IP layer; instead it
// publishes a Steering with ProxyURL set, and the engine arranges for the
// launched app (or an upstream redirector like redsocks/tun2socks) to use
// that proxy. For browsers this is honored via launch flags; for arbitrary
// apps the engine layers tun2socks on top.
package socks5

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/backends/proxychain"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
)

type Backend struct {
	host string
	port int
	user string
	pass string

	mu       sync.Mutex
	relay    *proxychain.Relay // non-nil when chained
	relayURL string
}

func init() {
	backends.Register(profile.BackendSOCKS5, func(b profile.Backend) (backends.Backend, error) {
		host, port := b.Host, b.Port
		if len(b.HostPool) > 0 {
			pick := b.HostPool[poolPick(len(b.HostPool))]
			h, p, err := splitHostPort(pick)
			if err != nil {
				return nil, fmt.Errorf("socks5 pool entry %q: %w", pick, err)
			}
			host, port = h, p
		}
		if host == "" || port == 0 {
			return nil, fmt.Errorf("socks5: host and port required (or set host_pool)")
		}
		return &Backend{host: host, port: port, user: b.Username, pass: b.Password}, nil
	})
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, p, nil
}

func poolPick(n int) int {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return 0
	}
	v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return int(v % uint64(n))
}

func (b *Backend) Kind() profile.BackendKind { return profile.BackendSOCKS5 }

func (b *Backend) Start(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	// Rewrite localhost → an address that reaches the HOST's loopback from
	// inside the netns. Veil profiles run inside a per-profile netns;
	// "127.0.0.1" / "localhost" there is the netns's own loopback, not the
	// user's machine. The common case for these literals is "I'm running an
	// SSH dynamic forward (ssh -D) on my laptop and want Veil to send
	// through it", i.e. the user means the HOST loopback.
	//
	// Two uplinks resolve the host loopback differently:
	//   - bridge (legacy): the host-side veth IP is a real host address and
	//     0.0.0.0-bound host listeners pick it up — use HostGatewayFrom.
	//   - pasta (zero-cap): pasta maps the host's 127.0.0.1 to its gateway
	//     address, a different subnet than the inner veth, so the veth
	//     gateway would NOT reach it — use HostLoopbackFrom, which the
	//     engine sets to pasta's gateway on that path.
	// Prefer the loopback address when present, else fall back to the veth
	// gateway. (A loopback proxy reachable inside the netns proper needs no
	// rewrite either way.)
	dialHost := b.host
	switch dialHost {
	case "127.0.0.1", "::1", "localhost":
		target := backends.HostLoopbackFrom(ctx)
		if target == "" {
			target = backends.HostGatewayFrom(ctx)
		}
		if target != "" {
			logger.L().Debug("socks5: rewriting localhost to host",
				"original", dialHost, "rewritten", target)
			dialHost = target
		}
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(b.port))

	// Pure single-hop (no preceding proxy hop): verify the SOCKS5 server
	// is reachable, then publish our own URL for the app to use.
	if prev == nil || prev.ProxyURL == "" {
		d := &net.Dialer{Timeout: 5 * time.Second}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 reach %s: %w", addr, err)
		}
		_ = c.Close()
		myURL := &url.URL{Scheme: "socks5", Host: addr}
		if b.user != "" {
			myURL.User = url.UserPassword(b.user, b.pass)
		}
		return &backends.Steering{ProxyURL: myURL.String()}, nil
	}

	// Chained after another proxy hop: route every connection
	// app -> relay -> PREV -> THIS socks5 -> target. The relay dials THIS
	// server *through* prev and then speaks SOCKS5 to it for the final
	// target. (The old code forwarded through prev only and never used
	// this server, so the real exit was prev — a silent wrong exit.) The
	// server is reached through prev, not directly, so we don't pre-dial.
	dialer, err := dialThroughPrev(prev.ProxyURL, addr, b.user, b.pass)
	if err != nil {
		return nil, fmt.Errorf("socks5 chain dialer: %w", err)
	}
	r, listenAddr, err := proxychain.StartWithDialer("127.0.0.1:0", dialer, "chain:"+prev.ProxyURL+"=>"+addr)
	if err != nil {
		return nil, fmt.Errorf("chain relay: %w", err)
	}
	b.mu.Lock()
	b.relay = r
	b.relayURL = "socks5://" + listenAddr
	b.mu.Unlock()
	logger.L().Info("socks5 chained via relay", "listen", listenAddr, "upstream", prev.ProxyURL, "final", addr)
	return &backends.Steering{ProxyURL: b.relayURL}, nil
}

// dialThroughPrev builds a dialer that reaches a target by connecting to
// THIS socks5 server (thisAddr) THROUGH the previous proxy hop (prevURL),
// then doing a SOCKS5 handshake with this server for the target. Data
// path: prev -> this -> target, so this hop is the actual exit.
func dialThroughPrev(prevURL, thisAddr, user, pass string) (proxy.ContextDialer, error) {
	pu, err := url.Parse(prevURL)
	if err != nil {
		return nil, fmt.Errorf("parse prev proxy url: %w", err)
	}
	prevDialer, err := proxychain.BuildUpstreamDialer(pu)
	if err != nil {
		return nil, err
	}
	var auth *proxy.Auth
	if user != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	// proxy.SOCKS5's forward dialer is a proxy.Dialer (Dial); adapt the
	// prev ContextDialer to it.
	d, err := proxy.SOCKS5("tcp", thisAddr, auth, ctxDialerAdapter{prevDialer})
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("composed socks5 dialer is not a ContextDialer")
	}
	return cd, nil
}

// ctxDialerAdapter exposes a ContextDialer as a proxy.Dialer.
type ctxDialerAdapter struct{ d proxy.ContextDialer }

func (a ctxDialerAdapter) Dial(network, addr string) (net.Conn, error) {
	return a.d.DialContext(context.Background(), network, addr)
}

func (b *Backend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relay != nil {
		_ = b.relay.Close()
		b.relay = nil
	}
	return nil
}

func (b *Backend) Status() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.relay != nil {
		return fmt.Sprintf("socks5 %s:%d (chained relay at %s)", b.host, b.port, b.relayURL)
	}
	return fmt.Sprintf("socks5 %s:%d", b.host, b.port)
}

// Endpoints returns the configured SOCKS5 server.
func (b *Backend) Endpoints() []string {
	return []string{fmt.Sprintf("%s:%d", b.host, b.port)}
}
