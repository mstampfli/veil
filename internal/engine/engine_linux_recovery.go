//go:build linux

package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mstampfli/veil/internal/logger"
	veilrun "github.com/mstampfli/veil/internal/runtime"
)

// cleanupOrphan removes a leftover veil-* netns + its veth from a previous
// run. Best-effort: any error is logged and ignored so engine.Up still
// proceeds.
//
// Refuses to clean a namespace whose corresponding runtime.Session is
// alive — that would tear down a sibling Veil process's session.
func cleanupOrphan(nsName string) {
	if strings.HasPrefix(nsName, "veil-") {
		profile := strings.TrimPrefix(nsName, "veil-")
		if sess, err := veilrun.Load(profile); err == nil && veilrun.IsAlive(sess) {
			logger.L().Warn("skip cleanup: namespace owned by live session",
				"ns", nsName, "pid", sess.PID, "profile", profile)
			return
		}
	}
	if out, err := exec.Command("ip", "netns", "del", nsName).CombinedOutput(); err == nil {
		logger.L().Info("removed orphan netns", "ns", nsName)
		_ = out
	}
	_ = os.RemoveAll(filepath.Join("/etc/netns", nsName))
}

// CleanupAllOrphans removes all veil-* namespaces whose owning session
// is dead (or has no session record at all). Live sessions are skipped.
//
// Called at engine init and by `veil clean`. Safe to run with other
// Veil processes active — they're protected by the liveness check.
func CleanupAllOrphans() {
	out, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "veil-") {
			cleanupOrphan(fields[0])
		}
	}
	// Reap dead session metadata so `veil status` doesn't list ghosts.
	if dead, err := veilrun.Stale(); err == nil {
		for _, s := range dead {
			_ = veilrun.Remove(s.Profile)
			logger.L().Info("removed stale session record",
				"profile", s.Profile, "pid", s.PID)
		}
	}
}

// RecoverStale is called at engine startup to clean state left from
// prior Veil crashes before launching new profiles. Stricter than
// CleanupAllOrphans: also reaps orphan veth pairs whose namespace is
// gone, so subsequent veth creation doesn't EEXIST-fail.
func RecoverStale() {
	CleanupAllOrphans()
	out, err := exec.Command("ip", "-o", "link", "show", "type", "veth").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if i := strings.Index(name, "@"); i > 0 {
			name = name[:i]
		}
		if !strings.HasPrefix(name, "veil-h-") {
			continue
		}
		profile := strings.TrimPrefix(name, "veil-h-")
		if sess, err := veilrun.Load(profile); err == nil && veilrun.IsAlive(sess) {
			continue
		}
		_ = exec.Command("ip", "link", "del", name).Run()
	}
}
