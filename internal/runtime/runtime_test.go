package runtime

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// deadPID returns a PID that has already exited (so it is reliably not
// alive). PID reuse within the microseconds before the assertion is
// negligible for a test.
func deadPID(t *testing.T) int {
	t.Helper()
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		c = exec.Command("sleep", "0")
		if err := c.Run(); err != nil {
			t.Skipf("cannot spawn a throwaway process: %v", err)
		}
	}
	return c.Process.Pid
}

func reaped(list []string, name string) bool {
	for _, p := range list {
		if p == name {
			return true
		}
	}
	return false
}

// TestReapDead_RemovesDeadKeepsAlive proves the non-root metadata reap
// drops dead session records and keeps live ones. This is the reap that
// engine.Active (userns) and `veil clean` rely on so `veil list`/`status`
// stop reporting ghost sessions.
func TestReapDead_RemovesDeadKeepsAlive(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	alive := &Session{Profile: "alive-prof", PID: os.Getpid(), StartedAt: time.Now()}
	dead := &Session{Profile: "dead-prof", PID: deadPID(t), StartedAt: time.Now()}
	if err := Save(alive); err != nil {
		t.Fatal(err)
	}
	if err := Save(dead); err != nil {
		t.Fatal(err)
	}

	got := ReapDead()

	if !reaped(got, "dead-prof") {
		t.Errorf("dead session not reaped; reaped=%v", got)
	}
	if reaped(got, "alive-prof") {
		t.Errorf("live session wrongly reaped; reaped=%v", got)
	}
	if _, err := Load("dead-prof"); err == nil {
		t.Error("dead-prof record still on disk after reap")
	}
	if _, err := Load("alive-prof"); err != nil {
		t.Errorf("alive-prof record wrongly removed: %v", err)
	}
}

// TestIsAlive locks the liveness primitive the display fix and the reap
// both depend on.
func TestIsAlive(t *testing.T) {
	if !IsAlive(&Session{PID: os.Getpid()}) {
		t.Error("current process reported not alive")
	}
	if IsAlive(&Session{PID: deadPID(t)}) {
		t.Error("dead pid reported alive")
	}
	if IsAlive(nil) {
		t.Error("nil session reported alive")
	}
	if IsAlive(&Session{PID: 0}) {
		t.Error("pid 0 reported alive")
	}
}
