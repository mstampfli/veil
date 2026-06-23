//go:build !linux

package osutil

// EnsureVeilGroup is a no-op on non-Linux platforms — Windows uses
// a different privilege model and macOS isn't a Veil target.
func EnsureVeilGroup() {}
