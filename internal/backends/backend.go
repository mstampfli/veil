// Package backends defines the Backend interface and shared types.
//
// A Backend is one hop in a profile's chain. The engine layer (Linux netns
// or Windows Wintun+WFP) decides *how* to attach the backend to the launched
// process; the backend itself only knows how to bring its tunnel up/down and
// describe how traffic should be steered into it.
package backends

import (
	"context"
	"fmt"

	"github.com/mstampfli/veil/internal/profile"
)

// Steering describes how a backend wants traffic routed to it.
type Steering struct {
	// ProxyURL: when non-empty, downstream backends should connect to this
	// proxy URL (e.g. "socks5://127.0.0.1:9050") to reach the next hop or
	// the public internet. Used for proxy-style backends and Tor.
	ProxyURL string

	// TUNDevice: name of a TUN/Wintun interface this backend created.
	TUNDevice string

	// Addresses to assign to TUNDevice inside the namespace, e.g.
	// ["10.5.0.2/32"]. Required for WireGuard-style tunnels.
	Addresses []string

	// Gateway / Subnet: when TUNDevice is set, the engine routes Subnet
	// (default 0.0.0.0/0) through it. Gateway is optional; for WG-style
	// TUNs it's left empty and the route is "dev <tun>" only.
	Gateway string
	Subnet  string

	// DNS servers the namespace should use while this backend is active.
	DNS []string

	// PinnedRoutes are CIDRs that must continue to route via the
	// PREVIOUS hop's TUN device, even after this hop's TUN takes the
	// default route. For nested WG, this is the inner WG peer's
	// endpoint IP — without this, inner WG would loop back through
	// itself when trying to reach its own peer. Each entry is a CIDR
	// (e.g. "203.0.113.5/32").
	PinnedRoutes []string
}

// Backend is the per-hop tunnel implementation.
type Backend interface {
	// Kind returns the profile.BackendKind this implements.
	Kind() profile.BackendKind

	// Start brings the backend up. Implementations must be idempotent and
	// safe to call once per profile run. The returned Steering tells the
	// engine how to route traffic into this hop.
	Start(ctx context.Context, prev *Steering) (*Steering, error)

	// Stop tears the backend down. Must be safe to call even if Start
	// failed mid-way.
	Stop() error

	// Status returns a short human-readable status string.
	Status() string
}

// EndpointReporter is implemented by backends that have a known remote
// endpoint (VPN server, proxy, etc.) so the GUI can geo-locate it for
// the dashboard map. Each entry is either "host" or "host:port".
type EndpointReporter interface {
	Endpoints() []string
}

// New returns a Backend implementation for the given profile.Backend.
// Engines must call this to materialize each hop.
//
// The implementation registry is populated by the per-backend packages via
// init() / Register so this file stays free of platform imports.
type Constructor func(b profile.Backend) (Backend, error)

var registry = map[profile.BackendKind]Constructor{}

// Register installs a Constructor for a backend kind. Called from each
// backend package's init().
func Register(k profile.BackendKind, c Constructor) {
	registry[k] = c
}

// New constructs the backend for a profile.Backend, using the registered
// constructor for that kind.
func New(b profile.Backend) (Backend, error) {
	c, ok := registry[b.Kind]
	if !ok {
		return nil, fmt.Errorf("backend %q not registered (build tags?)", b.Kind)
	}
	return c(b)
}
