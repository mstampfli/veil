// Package httpproxy implements an HTTP/HTTPS CONNECT proxy backend.
package httpproxy

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

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
	relay    *proxychain.Relay
	relayURL string
}

func init() {
	backends.Register(profile.BackendHTTP, func(b profile.Backend) (backends.Backend, error) {
		host, port := b.Host, b.Port
		if len(b.HostPool) > 0 {
			pick := b.HostPool[hpPoolPick(len(b.HostPool))]
			h, p, err := net.SplitHostPort(pick)
			if err != nil {
				return nil, fmt.Errorf("http pool entry %q: %w", pick, err)
			}
			port, err = strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("http pool port %q: %w", p, err)
			}
			host = h
		}
		if host == "" || port == 0 {
			return nil, fmt.Errorf("http proxy: host and port required (or set host_pool)")
		}
		return &Backend{host: host, port: port, user: b.Username, pass: b.Password}, nil
	})
}

func hpPoolPick(n int) int {
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

func (b *Backend) Kind() profile.BackendKind { return profile.BackendHTTP }

func (b *Backend) Start(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	// Same localhost rewrite as the SOCKS5 backend — see that file
	// for the full rationale. Short version: 127.0.0.1 inside a
	// per-profile netns means the netns's loopback, not the user's
	// machine. Prefer the host-loopback address (set on the pasta uplink,
	// where pasta maps host 127.0.0.1 to its gateway), else fall back to
	// the host-side veth gateway (bridge/legacy path).
	dialHost := b.host
	switch dialHost {
	case "127.0.0.1", "::1", "localhost":
		target := backends.HostLoopbackFrom(ctx)
		if target == "" {
			target = backends.HostGatewayFrom(ctx)
		}
		if target != "" {
			dialHost = target
		}
	}
	addr := net.JoinHostPort(dialHost, strconv.Itoa(b.port))
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("http proxy reach %s: %w", addr, err)
	}
	_ = c.Close()

	myURL := &url.URL{Scheme: "http", Host: addr}
	if b.user != "" {
		myURL.User = url.UserPassword(b.user, b.pass)
	}

	if prev == nil || prev.ProxyURL == "" {
		return &backends.Steering{ProxyURL: myURL.String()}, nil
	}
	r, listenAddr, err := proxychain.Start("127.0.0.1:0", prev.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("chain relay: %w", err)
	}
	b.mu.Lock()
	b.relay = r
	b.relayURL = "socks5://" + listenAddr
	b.mu.Unlock()
	logger.L().Info("http chained via relay", "listen", listenAddr, "upstream", prev.ProxyURL, "final", myURL.String())
	return &backends.Steering{ProxyURL: b.relayURL}, nil
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
		return fmt.Sprintf("http %s:%d (chained relay at %s)", b.host, b.port, b.relayURL)
	}
	return fmt.Sprintf("http %s:%d", b.host, b.port)
}

// Endpoints returns the configured HTTP proxy server.
func (b *Backend) Endpoints() []string {
	return []string{fmt.Sprintf("%s:%d", b.host, b.port)}
}
