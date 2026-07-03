//go:build !linux

package engine

// User-ns engine is Linux-only. tryUsernsEngine on other platforms
// always returns false so Active() falls back to the platform engine.
func tryUsernsEngine() (Engine, bool) { return nil, false }
