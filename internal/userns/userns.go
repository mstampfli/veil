// Package userns wraps the dance of forking a child into an
// unprivileged user namespace + network namespace + (where supported)
// time namespace.
//
// The child process — typically a re-exec of the current Veil binary
// with a special subcommand — runs as if it were root inside the
// namespaces but is the original unprivileged user as far as the
// host kernel is concerned. From inside, CAP_NET_ADMIN works (so
// iptables/NFQUEUE/netlink-veth-config are usable), but creating a
// veth pair where one end attaches to a host device still needs
// CAP_NET_ADMIN on the host — that's what cmd/veil-bridge handles.
//
// Cross-platform note: this package compiles to no-ops on Windows /
// macOS so engine_*.go files can import it unconditionally. The Linux
// implementation lives in userns_linux.go.

package userns

// MarkerEnv is the environment variable a child process should check
// at startup to know it has been spawned as the user-ns child of a
// Veil parent. Set to "1" by Spawn; absent in normal invocations.
const MarkerEnv = "VEIL_USERNS_CHILD"

// IsChild reports whether the current process was spawned by Spawn.
// Use this in main() to dispatch into the engine subcommand path
// instead of the normal CLI / GUI path.
func IsChild() bool {
	return getenv(MarkerEnv) == "1"
}

// SupportLevel describes what the host kernel can offer in this
// configuration.
type SupportLevel int

const (
	// SupportNone — kernel doesn't even support unprivileged user
	// namespaces (e.g. distro disables CONFIG_USER_NS, or sysctl
	// kernel.unprivileged_userns_clone=0). Caller should fall back
	// to the legacy pkexec-as-root engine path.
	SupportNone SupportLevel = iota
	// SupportUserNet — user-ns + net-ns work. Time-ns may not be
	// creatable inside user-ns on this kernel (Linux <5.6). Engine
	// runs without per-profile time isolation but everything else.
	SupportUserNet
	// SupportFull — user-ns + net-ns + time-ns all work inside an
	// unprivileged user namespace. Linux 5.6+.
	SupportFull
)

func (s SupportLevel) String() string {
	switch s {
	case SupportNone:
		return "none"
	case SupportUserNet:
		return "user+net"
	case SupportFull:
		return "user+net+time"
	default:
		return "unknown"
	}
}
