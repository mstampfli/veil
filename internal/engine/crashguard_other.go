//go:build !linux && !darwin

package engine

import (
	"runtime/debug"

	"github.com/mstampfli/veil/internal/audit"
	"github.com/mstampfli/veil/internal/logger"
)

// InstallCrashGuard: Windows has different signal semantics; for now
// we only install the Go panic recovery hook (no SIGABRT handler).
func InstallCrashGuard() {}

// ReapOrphanUsernsChildren is a no-op on non-Linux/Darwin — the
// userns engine path is Linux-only.
func ReapOrphanUsernsChildren() {}

// RunWithCrashGuard wraps a function with panic recovery + crash report
// emission. Same as the *nix version minus signal handling.
func RunWithCrashGuard(label string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			audit.Crash("panic in "+label, "", "", map[string]any{
				"panic": r,
				"stack": string(debug.Stack()),
			})
			logger.L().Error("panic recovered", "label", label, "value", r)
			CleanupAllOrphans()
			panic(r)
		}
	}()
	return fn()
}
