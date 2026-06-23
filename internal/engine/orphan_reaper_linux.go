//go:build linux

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mstampfli/veil/internal/logger"
	veilrun "github.com/mstampfli/veil/internal/runtime"
)

func execLookOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// ReapOrphanUsernsChildren walks /proc looking for veil userns
// children whose parent process is gone (parent PID = 1 = init/
// systemd, the orphan reparent target). SIGKILLs each one so its
// /dev/input/event* EVIOCGRAB, /dev/net/tun, netns, and veth fds
// are released before we try to spin up a new session.
//
// Why this is safe to call at startup:
//   - We only target processes with VEIL_USERNS_CHILD=1 in environ.
//     Anything else is left alone.
//   - We require PPID == 1 (re-parented to init) so we don't kill
//     a userns child of an actively-running sibling veil-gui — the
//     user might genuinely have two profiles up concurrently.
//   - SIGKILL is the contract for these children anyway (they're
//     spawned with Pdeathsig=SIGKILL); we're just compensating for
//     the fact that the kernel only delivers Pdeathsig on
//     IMMEDIATE-parent death and not, say, when a veil-gui crashes
//     hard enough that its userns child got pre-emptively orphaned
//     to init via a race in the death path.
func reapOrphanUsernsChildren() {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	killed := 0
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		// Skip self — if we ARE the userns child running this reap
		// (which we shouldn't be, but defensively), don't kill us.
		if pid == os.Getpid() {
			continue
		}

		// Filter to veil userns children.
		envBytes, err := os.ReadFile("/proc/" + p.Name() + "/environ")
		if err != nil {
			continue
		}
		isVeilChild := false
		for _, e := range strings.Split(string(envBytes), "\x00") {
			if strings.HasPrefix(e, "VEIL_USERNS_CHILD=") {
				isVeilChild = true
				break
			}
		}
		if !isVeilChild {
			continue
		}

		// Check parent — only kill if reparented to init (orphaned).
		statBytes, err := os.ReadFile("/proc/" + p.Name() + "/stat")
		if err != nil {
			continue
		}
		ppid := parsePPIDFromStat(string(statBytes))
		if ppid != 1 {
			// Has a live parent (likely a sibling veil-gui running
			// another profile). Don't touch.
			continue
		}

		logger.L().Warn("reaping orphan veil userns child",
			"pid", pid, "reason", "ppid=1 (parent gone)")
		_ = syscall.Kill(pid, syscall.SIGKILL)
		killed++
	}
	if killed > 0 {
		// Brief settle for kernel to reap and release device fds /
		// netns / veth before subsequent engine.Up tries to claim them.
		time.Sleep(300 * time.Millisecond)
		// Also nudge any leftover veil veth / netns clean-up.
		cleanupOrphanNetnsAndVeth()
	}
	// Reap orphan Tor processes too — they're the heaviest leftover
	// (each ~30-60 MB resident + open netns + iptables + control
	// port). Pdeathsig is set on Tor's exec but doesn't fire on a
	// hard veil-gui SIGKILL race; without an explicit reap users
	// accumulate many orphans which then make new launches sluggish.
	reapOrphanTors()

	// Reap dead session metadata too. `veil clean` routes here in
	// non-root mode, and its help text promises to remove records of
	// sessions whose owning process is gone; without this the registry
	// keeps reporting ghosts in `veil list`/`status`. Live sessions are
	// kept by the liveness check inside ReapDead.
	for _, p := range veilrun.ReapDead() {
		logger.L().Info("removed stale session record", "profile", p)
	}
}

// reapOrphanTors walks /proc and SIGKILLs every Veil-spawned tor
// process whose parent is init (orphaned). Two cmdline shapes match:
//
//   - legacy:  tor -f /tmp/veil-tor-<random>/torrc --quiet
//   - current: tor -f <profileDataDir>/tor/torrc --quiet
//
// The current path lives under the user's veil data dir, so we
// require both "veil/data/" AND "/tor/torrc" to match — that pair
// can't credibly appear outside Veil and won't snare system Tor.
func reapOrphanTors() {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	killed := 0
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		cmdlineBytes, err := os.ReadFile("/proc/" + p.Name() + "/cmdline")
		if err != nil {
			continue
		}
		cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		if !isVeilTorCmdline(cmdline) {
			continue
		}
		statBytes, err := os.ReadFile("/proc/" + p.Name() + "/stat")
		if err != nil {
			continue
		}
		if parsePPIDFromStat(string(statBytes)) != 1 {
			continue
		}
		logger.L().Warn("reaping orphan Tor", "pid", pid, "cmdline", cmdline)
		_ = syscall.Kill(pid, syscall.SIGKILL)
		killed++
	}
	if killed > 0 {
		time.Sleep(200 * time.Millisecond)
		// Legacy tempdirs only — persistent per-profile dirs hold the
		// cache we want to keep across launches and we don't touch them.
		if entries, err := os.ReadDir("/tmp"); err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "veil-tor-") {
					_ = os.RemoveAll("/tmp/" + e.Name())
				}
			}
		}
	}
}

// isVeilTorCmdline returns true for either the legacy /tmp/veil-tor-*
// tempdir cmdline or the current per-profile <data>/veil/data/*/tor/
// cmdline. False for system tor and for unrelated tor invocations.
func isVeilTorCmdline(cmdline string) bool {
	if strings.Contains(cmdline, "/tmp/veil-tor-") {
		return true
	}
	return strings.Contains(cmdline, "veil/data/") &&
		strings.Contains(cmdline, "/tor/torrc")
}

// parsePPIDFromStat extracts the PPID from /proc/<pid>/stat. Format:
//
//	pid (comm) state ppid pgrp ...
//
// where comm can contain whitespace + parens — find the LAST ')' and
// then take field index 1 (0-indexed) afterward = state, 2 = ppid.
func parsePPIDFromStat(s string) int {
	end := strings.LastIndexByte(s, ')')
	if end < 0 || end+1 >= len(s) {
		return 0
	}
	rest := strings.Fields(s[end+1:])
	if len(rest) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(rest[1])
	return ppid
}

// cleanupOrphanNetnsAndVeth removes lingering veil-* network
// namespaces and host-side veth links left behind by SIGKILL'd
// userns children.
func cleanupOrphanNetnsAndVeth() {
	// /run/netns is bind-mount controlled by `ip netns add`. List
	// all veil-* entries; each may belong to a child we just killed.
	if entries, err := os.ReadDir("/run/netns"); err == nil {
		for _, e := range entries {
			n := e.Name()
			if !strings.HasPrefix(n, "veil-") {
				continue
			}
			// nsfs mountpoint left over after SIGKILL. Try to umount
			// + rm. Best-effort — if it's still in use we'll learn
			// next launch.
			path := filepath.Join("/run/netns", n)
			_ = syscall.Unmount(path, 0)
			_ = os.Remove(path)
		}
	}
	// Host-side veth links: when the userns child is SIGKILLed the
	// kernel reaps its end of the veth (peer in netns is gone with
	// the netns), but the HOST-side veth (named like veilXXXX or
	// vetha-* per bridge.go) sometimes lingers in DOWN state.
	// Subsequent launches collide on the deterministic name and
	// fail with "RTNETLINK answers: File exists". Walk
	// /sys/class/net and remove any veil-prefixed link whose peer
	// is not present (best signal of orphan).
	cleanupOrphanVeths()
}

// cleanupOrphanVeths walks /sys/class/net and removes veth interfaces
// whose names match Veil's bridge.vethNames pattern (host-side begins
// with "vetha-" — see cmd/veil-bridge/main.go::vethNames). Only
// removes those whose peer index points at a now-gone netns.
func cleanupOrphanVeths() {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		// Match the veth-host prefixes the bridge uses. See
		// cmd/veil-bridge/main.go::vethNames — host side is
		// "vetha-<8hex>" in the current scheme. Be conservative: also
		// match "veil" prefix since older builds used that.
		if !strings.HasPrefix(name, "vetha-") && !strings.HasPrefix(name, "veil") {
			continue
		}
		// Best-effort delete via `ip link delete`. If the peer is
		// in a still-live netns this will succeed and gracefully
		// remove BOTH ends. If the link is in use by an active
		// session it'll fail with EBUSY — leave it alone.
		out, err := execIPCommand("link", "delete", name)
		if err == nil {
			logger.L().Info("reaped orphan veth", "name", name)
		} else {
			// EBUSY = active session owns it; ENODEV = race, gone.
			// Don't log as warn unless it's neither.
			if !strings.Contains(out, "Cannot find") &&
				!strings.Contains(out, "device or resource busy") {
				logger.L().Warn("orphan veth cleanup",
					"name", name, "out", out, "err", err)
			}
		}
	}
}

// execIPCommand wraps a single `ip <args...>` exec, returning combined
// output + error. Kept here (not in the reaper's main file) so
// orphan_reaper_other.go doesn't need to stub it.
func execIPCommand(args ...string) (string, error) {
	cmd := os.Getenv("VEIL_IP_BIN")
	if cmd == "" {
		cmd = "ip"
	}
	out, err := execLookOutput(cmd, args...)
	return string(out), err
}
