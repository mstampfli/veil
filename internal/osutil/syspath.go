package osutil

import (
	"os"
	"strings"
)

// EnsureIPTablesLock points iptables/iptables-nft at a writable
// lock file path. iptables-nft locks /run/xtables.lock by default
// for any modifying operation; /run is root-owned 0755 and we
// don't have CAP_DAC_OVERRIDE, so the open() fails — and iptables
// reports "Permission denied (you must be root)", masking the
// real cause. Redirecting to /tmp (world-writable, on tmpfs)
// fixes it for every iptables invocation we exec.
//
// Idempotent. Safe even when running as actual root (no behavior
// change vs. the default lock path).
func EnsureIPTablesLock() {
	if os.Getenv("XTABLES_LOCKFILE") == "" {
		_ = os.Setenv("XTABLES_LOCKFILE", "/tmp/veil-xtables.lock")
	}
}

// EnsureSysPath augments PATH so /sbin and /usr/sbin are present,
// regardless of how the current process was launched.
//
// Why: when a binary is started from a desktop launcher / .desktop
// entry / pkexec / systemd unit, PATH often lacks sbin entries —
// those used to be "root-only" by convention. But on modern
// distributions, common networking tools (ip, iptables, conntrack,
// wg, etc.) live in /usr/sbin, and Veil shells out to several of
// them. Without this fix, calls fail with "executable not found in
// $PATH" even though the binary exists.
//
// Idempotent: existing entries aren't duplicated.
func EnsureSysPath() {
	cur := os.Getenv("PATH")
	if cur == "" {
		// Empty PATH (e.g. inherited from a context that wiped env)
		// would split to a single "" entry, which is nonsense. Seed
		// with the standard Filesystem Hierarchy Standard locations.
		cur = "/usr/local/bin:/usr/bin:/bin"
	}
	parts := strings.Split(cur, ":")
	have := make(map[string]bool, len(parts))
	for _, p := range parts {
		have[p] = true
	}
	add := []string{"/usr/local/sbin", "/usr/sbin", "/sbin"}
	out := append([]string(nil), parts...)
	for _, p := range add {
		if !have[p] {
			out = append(out, p)
		}
	}
	_ = os.Setenv("PATH", strings.Join(out, ":"))
}
