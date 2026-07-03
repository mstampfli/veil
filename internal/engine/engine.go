// Package engine isolates a profile's execution. The Linux engine uses
// network namespaces, veth pairs, iptables/nftables and per-namespace
// resolv.conf. The Windows engine uses Wintun + WFP per-PID filtering
// and proxy injection for proxy backends.
package engine

import (
	"context"
	"os"
	"sync"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/profile"
	veilrun "github.com/mstampfli/veil/internal/runtime"
)

// Session is a running profile.
type Session struct {
	Profile  *profile.Profile
	Backends []backends.Backend
	Final    *backends.Steering
	// Engine-specific opaque state.
	State any
}

// IPInfo is the result of ExternalIPInfo: external IP + geo + org as
// reported by ipinfo.io (or whatever provider is configured), fetched
// through the profile's own network.
type IPInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	City     string `json:"city,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
	Loc      string `json:"loc,omitempty"`
	Org      string `json:"org,omitempty"`
	Postal   string `json:"postal,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

// Engine isolates and launches profiles for the host platform.
type Engine interface {
	// Up creates the isolation primitives, starts each backend in chain
	// order, and returns a Session ready for Launch.
	Up(ctx context.Context, p *profile.Profile) (*Session, error)

	// Launch starts the configured app inside the session's isolation.
	// Returns the OS pid of the launched process.
	Launch(s *Session) (pid int, err error)

	// Down tears down the session: kills processes, stops backends,
	// removes namespaces / firewall rules / TUN devices.
	Down(s *Session) error

	// ExternalIP queries the apparent public IP from inside the session's
	// network. Used by `veil ip <profile>`.
	ExternalIP(ctx context.Context, s *Session) (string, error)

	// ExternalIPInfo returns IP + geo (where supported) via the profile's
	// own network — never via the host's default route.
	ExternalIPInfo(ctx context.Context, s *Session) (IPInfo, error)

	// Doctor performs platform-specific preflight checks.
	Doctor(ctx context.Context) ([]Check, error)

	// TrafficStats returns cumulative tx/rx byte counters for the
	// session's primary egress interface (TUN if a tunnel is active,
	// otherwise the veth peer).
	TrafficStats(s *Session) (TrafficStats, error)

	// ProbeLeaks runs network-namespace-internal leak probes against
	// the live session. Returns one ProbeResult per check. See
	// probe_linux.go for the test set.
	ProbeLeaks(ctx context.Context, s *Session) []ProbeResult

	// BrowserProbeIP drives the running browser via its remote-control
	// protocol (CDP for Chromium-family, Marionette for Firefox) to
	// fetch target and return the loaded page body. The browser makes
	// the actual HTTPS request — exit observers see a vanilla browser
	// visit, not a Veil-initiated probe. Used by the GUI's IP / drift
	// / geo-lookup buttons so every "tell me about the chain" probe
	// goes through the persona-shaped browser, never raw curl.
	BrowserProbeIP(ctx context.Context, s *Session, target string) (string, error)

	// TorNewCircuit signals SIGNAL NEWNYM to the session's Tor backend
	// (if any) so subsequent connections build new circuits. Existing
	// streams stay on their old circuits. Returns an error if the
	// session has no Tor backend or the control port is unreachable.
	TorNewCircuit(s *Session) error

	// TorCircuitStatus returns the raw `GETINFO circuit-status`
	// reply from the session's Tor control port. Caller parses with
	// tor.ParseCircuits. Goes through netns, so works under both
	// host-engine and userns-engine paths.
	TorCircuitStatus(s *Session) (string, error)

	// TorRelayIP returns the IP address of the relay with the given
	// fingerprint, looked up via Tor's control-port `GETINFO ns/id/
	// <fp>` (consensus data, no extra network requests). Empty string
	// + nil error if the relay isn't in the consensus.
	TorRelayIP(s *Session, fingerprint string) (string, error)
}

// TrafficStats are the byte counters for a session.
type TrafficStats struct {
	Iface     string `json:"iface"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	RxPackets uint64 `json:"rx_packets"`
}

// Check is a single doctor check result.
type Check struct {
	Name    string
	OK      bool
	Detail  string
	Warning bool
}

// Active returns the engine for the host platform.
//
// Implementations live in engine_linux.go / engine_windows.go / engine_darwin.go
// each guarded by a build tag. The result is memoized so all callers share
// one engine instance, which is required for cross-session bookkeeping
// (subnet allocations, TUN device names, kill-switch tracking).
//
// First call also runs RecoverStale() to clean up state left by prior
// crashes (orphan netns, stale veth pairs, dead session metadata).
//
// When VEIL_USERNS_ENGINE=1 is set in the environment AND the
// platform is Linux, Active returns the user-ns parent-side engine
// instead of the legacy root-required linuxEngine. Default unset =
// no behavior change.
func Active() Engine {
	activeOnce.Do(func() {
		if os.Getenv("VEIL_USERNS_ENGINE") == "1" {
			if e, ok := tryUsernsEngine(); ok {
				activeEngine = e
				// The userns engine has no host netns/veth to sweep, but
				// dead session metadata must still be reaped here or
				// `veil list`/`status` report ghost sessions forever:
				// RecoverStale (below) reaps them for the root engine but
				// is skipped on this path. Pure file ops, live sessions
				// kept.
				_ = veilrun.ReapDead()
				return
			}
		}
		activeEngine = active()
		RecoverStale()
	})
	return activeEngine
}

var (
	activeOnce   sync.Once
	activeEngine Engine
)
