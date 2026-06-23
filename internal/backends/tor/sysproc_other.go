//go:build !linux

package tor

import "syscall"

// torSysProcAttr is a no-op on non-Linux platforms: Pdeathsig is
// Linux-only and Setpgid is unavailable on Windows, so the Linux
// parent-death / process-group handling does not apply here. The tor
// backend's managed path is Linux-only at runtime (it relies on
// `ip netns exec`); this stub exists so the package still COMPILES on
// Windows/macOS, where it is imported by those engines' backend registry.
func torSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
