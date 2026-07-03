//go:build linux || darwin

package engine

import (
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/mstampfli/veil/internal/audit"
	"github.com/mstampfli/veil/internal/logger"
)

// crashGuardOnce makes InstallCrashGuard idempotent — multiple binaries
// (CLI + GUI loaded together via test harness, etc.) calling it won't
// install duplicate handlers.
var crashGuardOnce sync.Once

// ReapOrphanUsernsChildren is the public hook for cmd/veil-gui /
// cmd/veil to call at startup to clean up veil userns children
// orphaned by a crashed parent (PPID=1). See orphan_reaper_linux.go
// for the actual logic.
func ReapOrphanUsernsChildren() { reapOrphanUsernsChildren() }

// InstallCrashGuard registers OS signal handlers and a Go panic
// recovery hook so that abnormal Veil termination still runs:
//
//   - audit.Crash with stack trace
//   - CleanupAllOrphans to release netns/veth/iptables state owned
//     by this process (other live Veil processes are skipped via
//     liveness check)
//
// Called from main() of veil and veil-gui binaries. Idempotent.
//
// Signals handled:
//   - SIGINT, SIGTERM: normal shutdown — handled by signal.NotifyContext
//     in the binary; we don't re-handle them here. We DO handle:
//   - SIGQUIT (Ctrl-\): user-initiated dump
//   - SIGSEGV, SIGABRT, SIGBUS: program-fault — write crash report
//     before the runtime kills us
//
// Note: Go's runtime catches SIGSEGV/SIGABRT/SIGBUS internally for its
// own panic propagation; we install handlers via os.Signal which
// receive the second copy after Go's runtime is done. This is enough
// to write a crash report in time for most cases.
func InstallCrashGuard() {
	crashGuardOnce.Do(func() {
		// 1. Async-signal handler for fatal signals.
		ch := make(chan os.Signal, 4)
		signal.Notify(ch,
			syscall.SIGQUIT,
			syscall.SIGABRT,
		)
		go func() {
			sig := <-ch
			audit.Crash("signal: "+sig.String(), "", "", map[string]any{
				"signal": sig.String(),
				"stack":  string(debug.Stack()),
			})
			logger.L().Error("crash guard fired", "signal", sig.String())
			CleanupAllOrphans()
			// Re-raise default handler so the process exits with the
			// expected status code.
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig.(syscall.Signal))
		}()
	})
}

// RunWithCrashGuard wraps a function with panic recovery that emits a
// crash report. Use it around Engine.Up / Engine.Launch in callers
// that care about post-mortem state.
func RunWithCrashGuard(label string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			audit.Crash("panic in "+label, "", "", map[string]any{
				"panic": r,
				"stack": string(debug.Stack()),
			})
			logger.L().Error("panic recovered", "label", label, "value", r)
			CleanupAllOrphans()
			panic(r) // re-raise
		}
	}()
	return fn()
}
