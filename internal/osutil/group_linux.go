package osutil

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

// EnsureVeilGroup re-execs the current process under the `veil`
// supplementary group when:
//   - the veil group exists in /etc/group
//   - the invoking user is a member of veil per /etc/group
//   - the CURRENT process credentials don't include the veil GID
//     (because the desktop session was started before usermod -aG
//     veil ran — supplementary groups are evaluated at login time)
//
// Without this, opening /dev/net/tun fails with EACCES even though
// the udev rule and group membership are correctly set up — the
// classic "you have to log out and back in" trap.
//
// Implementation: re-exec via `sg veil -c "<self> <args>"`. sg
// (substitute group, from shadow-utils — present on every Linux
// distro that has usermod) starts a new session with veil added to
// supplementary groups. Non-interactive, no terminal needed.
//
// Returns nil and continues normally when:
//   - we're already in the veil group
//   - veil group doesn't exist (setup hasn't been run — preflight
//     emits its own actionable error later)
//   - user isn't a member of veil group (same)
//   - sg isn't available (degraded distro; preflight fires later)
//   - we've already re-execed once (sentinel env var prevents loop)
//
// Calls os.Exit(0) on successful re-exec — the new process replaces
// us. Callers must invoke this BEFORE any other initialization that
// would be lost on re-exec.
func EnsureVeilGroup() {
	// Sentinel: prevents re-exec loop if sg fails for any reason.
	if os.Getenv("VEIL_VEIL_GROUP_REEXEC") == "1" {
		return
	}

	veilGid, ok := lookupGid("veil")
	if !ok {
		return // no veil group = setup not run; preflight will tell user
	}

	// Already in veil group?
	gids, err := os.Getgroups()
	if err != nil {
		return
	}
	for _, g := range gids {
		if g == veilGid {
			return
		}
	}

	// Listed as a member in /etc/group?
	cur, err := user.Current()
	if err != nil {
		return
	}
	if !userInGroup(cur.Username, "veil") {
		return // user genuinely not in group; setup install will add them
	}

	// sg available?
	sg, err := exec.LookPath("sg")
	if err != nil {
		return
	}

	// Re-exec under veil group. Build the command line back from
	// argv preserving quoting safety via shell-escape on each arg.
	self, err := os.Executable()
	if err != nil {
		return
	}
	parts := []string{shellQuote(self)}
	for _, a := range os.Args[1:] {
		parts = append(parts, shellQuote(a))
	}
	cmdLine := strings.Join(parts, " ")

	// Inherit env + sentinel.
	env := append(os.Environ(), "VEIL_VEIL_GROUP_REEXEC=1")

	// Use exec(3) syscall directly so the current PID is preserved —
	// matters for systemd / desktop-environment process tracking.
	if err := syscall.Exec(sg, []string{sg, "veil", "-c", cmdLine}, env); err != nil {
		// Couldn't exec — fall through and let preflightTUN report.
		fmt.Fprintln(os.Stderr, "veil: sg veil reexec failed:", err)
	}
}

func lookupGid(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}

// userInGroup checks /etc/group's member list for the named group
// rather than going through getgrouplist(), because getgrouplist
// can read from cached nsswitch sources that haven't picked up the
// usermod yet. /etc/group is the source of truth.
func userInGroup(username, group string) bool {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] != group {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			if strings.TrimSpace(m) == username {
				return true
			}
		}
	}
	return false
}

// shellQuote single-quotes s for safe inclusion in `sg veil -c "..."`.
// Replaces embedded single quotes with the standard '\'' construct.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
