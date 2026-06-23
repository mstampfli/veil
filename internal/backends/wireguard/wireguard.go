// Package wireguard implements a userspace WireGuard backend using
// wireguard-go. It works on Linux (TUN device) and Windows (Wintun).
package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/dohproxy"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
)

type Backend struct {
	cfg     *Config
	tunName string
	cfgPath string // path of the loaded .conf — logged on Start for diagnostics

	mu  sync.Mutex
	dev *device.Device
	t   tun.Device
}

func init() {
	backends.Register(profile.BackendWireGuard, func(b profile.Backend) (backends.Backend, error) {
		path, text, err := pickWGConfig(b)
		if err != nil {
			return nil, err
		}
		cfg, err := ParseConfig(text)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return &Backend{cfg: cfg, cfgPath: path}, nil
	})
}

// pickWGConfig resolves the active config: ConfigData wins, then a
// random pick from ConfigPaths, then ConfigPath. Returns (chosen path,
// config text, err).
func pickWGConfig(b profile.Backend) (string, string, error) {
	if b.ConfigData != "" {
		return "(inline)", b.ConfigData, nil
	}
	if len(b.ConfigPaths) > 0 {
		i := randIndex(len(b.ConfigPaths))
		path := b.ConfigPaths[i]
		data, err := os.ReadFile(path)
		if err != nil {
			return path, "", fmt.Errorf("wireguard read %s: %w", path, err)
		}
		return path, string(data), nil
	}
	if b.ConfigPath != "" {
		data, err := os.ReadFile(b.ConfigPath)
		if err != nil {
			return b.ConfigPath, "", fmt.Errorf("wireguard read %s: %w", b.ConfigPath, err)
		}
		return b.ConfigPath, string(data), nil
	}
	return "", "", fmt.Errorf("wireguard: config required (set config_path or config_paths)")
}

// randIndex returns a uniform random integer in [0, n).
func randIndex(n int) int {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return int(v % uint64(n))
}

func (b *Backend) Kind() profile.BackendKind { return profile.BackendWireGuard }

// nextTUNName picks a unique TUN/Wintun device name. Random per-launch
// suffix avoids collisions with leftover devices from a previous Veil
// run that crashed before cleanup. Linux interface names are limited to
// 15 characters, so we use 8 hex chars after "veilwg" (= 14 chars).
func nextTUNName() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to PID-based name if /dev/urandom is unavailable.
		return fmt.Sprintf("veilwg%05d", os.Getpid()%100000)
	}
	return "veilwg" + hex.EncodeToString(b[:])
}

var _ sync.Mutex // reserved

func (b *Backend) Start(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev != nil {
		return b.steering(prev), nil
	}

	// Defensive sweep: a previous run's Stop() may have timed out
	// before wireguard-go's Device.Close() returned, leaving a
	// "veilwg*" tun device leaked in the host namespace. The next
	// CreateTUN() with a new random suffix won't collide on the name,
	// but the kernel runs out of tun device slots if these accumulate
	// across crashes / hung stops. Sweep them up here.
	cleanLeakedVeilWG()

	// Resolve any hostname Endpoints via DoH BEFORE handing the
	// config to wireguard-go. Otherwise wireguard-go's UAPI parser
	// resolves them via Go's net.Resolver → host's /etc/resolv.conf
	// → real ISP sees a plaintext DNS query for the VPN provider's
	// hostname. With this DoH pre-pass the resolution travels as
	// HTTPS to a known DoH provider's IP literal — ISP sees only an
	// opaque TLS connection.
	for i, peer := range b.cfg.Peers {
		if peer.Endpoint == "" {
			continue
		}
		host, port, err := splitHostPort(peer.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("wireguard: parse endpoint %q: %w", peer.Endpoint, err)
		}
		if net.ParseIP(host) != nil {
			continue // already an IP literal, nothing to resolve
		}
		ips, err := dohproxy.ResolveDirect(host, "")
		if err != nil {
			return nil, fmt.Errorf("wireguard: DoH resolve %q failed: %w (refusing to fall back to host DNS which would leak the VPN endpoint hostname to ISP)", host, err)
		}
		newEP := net.JoinHostPort(ips[0].String(), port)
		logger.L().Info("wireguard: resolved endpoint via DoH",
			"hostname", host, "ip", ips[0].String())
		b.cfg.Peers[i].Endpoint = newEP
	}

	name := nextTUNName()
	mtu := b.cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	// Nested mode: a previous hop already published a TUN, so this
	// tunnel's UDP socket must dial through that tunnel rather than
	// the host's default route. We do that by binding wireguard-go's
	// UDP socket inside the user namespace.
	nested := prev != nil && prev.TUNDevice != ""

	var t tun.Device
	var dev *device.Device

	bringUp := func() error {
		var err error
		t, err = tun.CreateTUN(name, mtu)
		if err != nil {
			return fmt.Errorf("create tun: %w", err)
		}
		lg := device.NewLogger(device.LogLevelError, fmt.Sprintf("(veil/%s) ", name))
		dev = device.NewDevice(t, conn.NewDefaultBind(), lg)
		uapi, err := b.cfg.UAPIConfig()
		if err != nil {
			dev.Close()
			return err
		}
		if err := dev.IpcSet(uapi); err != nil {
			dev.Close()
			return fmt.Errorf("wireguard IpcSet: %w", err)
		}
		if err := dev.Up(); err != nil {
			dev.Close()
			return fmt.Errorf("wireguard up: %w", err)
		}
		return nil
	}

	if nested {
		ns := backends.NamespaceFrom(ctx)
		if ns != "" {
			if err := runDeviceInNetns(ns, bringUp); err != nil {
				return nil, err
			}
		} else {
			if err := bringUp(); err != nil {
				return nil, err
			}
		}
	} else {
		if err := bringUp(); err != nil {
			return nil, err
		}
	}

	// Gate readiness on a completed handshake when we can observe one.
	// dev.Up() only brings the device administratively up; the actual
	// cryptographic handshake lands asynchronously a moment later. Without
	// this wait Start returns while the data path is still dead, the engine
	// moves the TUN and launches the app immediately, and the app's first
	// connections are blackholed — the ~10-26% cold-start failures.
	waitForHandshake(ctx, dev, b.cfg, name)

	b.dev = dev
	b.t = t
	b.tunName = name
	return b.steering(prev), nil
}

// waitForHandshake blocks until a peer completes its WireGuard handshake
// (last_handshake_time_sec > 0) or a bounded deadline elapses.
//
// We can only reliably observe readiness when a peer has PersistentKeepalive
// set: wireguard-go then sends a handshake initiation proactively on Up, so
// last_handshake_time_sec becomes non-zero on its own. Without keepalive the
// handshake is lazy (triggered by the app's first packet), so there is nothing
// to poll for short of injecting traffic — there we return immediately and keep
// the original low-latency behavior rather than burning the whole window.
//
// On timeout we proceed anyway (best-effort): a keepalive peer whose handshake
// has not landed in this window is almost certainly unreachable, the kill
// switch fails closed, and blocking Start further would just turn a slow tunnel
// into a hard launch failure. The poll is adaptive — it returns the instant the
// handshake lands (typically well under a second), so it adds no fixed latency.
func waitForHandshake(ctx context.Context, dev *device.Device, cfg *Config, name string) {
	proactive := false
	for _, p := range cfg.Peers {
		if p.PersistentKeepalive > 0 {
			proactive = true
			break
		}
	}
	if !proactive {
		return
	}
	deadline := time.Now().Add(8 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if handshakeComplete(dev) {
			logger.L().Info("wireguard: handshake complete, data path ready", "dev", name)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Now().After(deadline) {
				logger.L().Warn("wireguard: no handshake within readiness window; launching anyway (best-effort)", "dev", name)
				return
			}
		}
	}
}

// handshakeComplete reports whether any peer has a non-zero last-handshake
// timestamp, reading the device's current UAPI state.
func handshakeComplete(dev *device.Device) bool {
	uapi, err := dev.IpcGet()
	if err != nil {
		return false
	}
	return handshakeFromUAPI(uapi)
}

// handshakeFromUAPI parses wireguard-go IpcGet output and reports whether any
// peer reports last_handshake_time_sec > 0. Split out as a pure function so the
// parse is unit-testable without a live device.
func handshakeFromUAPI(uapi string) bool {
	for _, line := range strings.Split(uapi, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "last_handshake_time_sec=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return true
		}
	}
	return false
}

// runDeviceInNetns locks the OS thread, switches to nsName, runs fn,
// then switches back. UDP sockets created by fn remain bound to the
// network namespace they were created in, even after thread switches
// back — that's the key trick for WG-over-WG.
func runDeviceInNetns(nsName string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cur, err := netns.Get()
	if err != nil {
		return err
	}
	defer cur.Close()
	target, err := netns.GetFromName(nsName)
	if err != nil {
		return fmt.Errorf("netns %q: %w", nsName, err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return err
	}
	defer netns.Set(cur)
	return fn()
}

func (b *Backend) steering(prev *backends.Steering) *backends.Steering {
	s := &backends.Steering{
		TUNDevice: b.tunName,
		Subnet:    "0.0.0.0/0",
		DNS:       append([]string(nil), b.cfg.DNS...),
	}
	for _, a := range b.cfg.Addresses {
		s.Addresses = append(s.Addresses, a.String())
	}
	// Nested mode: pin /32 routes for our peers' endpoints via the
	// previous TUN so our UDP packets to them get encrypted by the
	// outer tunnel rather than looping back through this one.
	if prev != nil && prev.TUNDevice != "" {
		for _, peer := range b.cfg.Peers {
			if peer.Endpoint == "" {
				continue
			}
			host, _, err := splitHostPort(peer.Endpoint)
			if err != nil {
				continue
			}
			if net.ParseIP(host) == nil {
				// Skip hostname endpoints in pinned-route mode —
				// resolving here would use the host's resolver and
				// leak the VPN provider's hostname to your ISP. The
				// engine's pre-launch DoH resolution (in app.go
				// resolveWGEndpoints) substitutes IP literals into
				// the config before we get here, so reaching this
				// branch means that pre-pass didn't run or failed.
				continue
			}
			s.PinnedRoutes = append(s.PinnedRoutes, host+"/32")
		}
	}
	return s
}

func splitHostPort(addr string) (string, string, error) {
	return net.SplitHostPort(addr)
}

func (b *Backend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dev != nil {
		b.dev.Close()
		b.dev = nil
	}
	b.t = nil
	return nil
}

func (b *Backend) Status() string {
	if b.dev == nil {
		return "wireguard stopped"
	}
	return fmt.Sprintf("wireguard up on %s", b.tunName)
}

// TUNName returns the TUN device name for stats lookup.
func (b *Backend) TUNName() string { return b.tunName }

// Endpoints returns each peer's Endpoint (host:port).
func (b *Backend) Endpoints() []string {
	out := make([]string, 0, len(b.cfg.Peers))
	for _, p := range b.cfg.Peers {
		if p.Endpoint != "" {
			out = append(out, p.Endpoint)
		}
	}
	return out
}
