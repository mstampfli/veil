//go:build !linux

package gui

// ShutdownSocketPath is a no-op stub on non-Linux — Windows / macOS
// don't have the same uid-cross-boundary problem because veil-gui on
// those platforms doesn't run as a separate uid from the launching
// user. Window close + native task-manager kill work normally there.
const ShutdownSocketPath = ""

// StartShutdownSocket is a no-op on non-Linux platforms.
func (a *App) StartShutdownSocket() {}

// removeShutdownSocketIfPresent is a no-op on non-Linux.
func removeShutdownSocketIfPresent() error { return nil }
