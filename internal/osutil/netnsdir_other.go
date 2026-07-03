//go:build !linux

package osutil

// EnsureNetnsRuntimeDir is a no-op on non-Linux platforms — only the
// Linux user-ns engine path uses /run/netns.
func EnsureNetnsRuntimeDir() {}
