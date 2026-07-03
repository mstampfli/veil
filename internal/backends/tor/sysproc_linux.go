//go:build linux

package tor

import "syscall"

// torSysProcAttr returns the SysProcAttr used when spawning the managed
// Tor process on Linux:
//   - Pdeathsig SIGKILL: kill Tor if the parent (engine) dies, so a
//     crashed/SIGKILL'd veil process doesn't leave orphan Tor instances
//     holding netns + iptables + control port.
//   - Setpgid: put `ip netns exec -> tor` in its own group so signaling
//     the leader tears the whole group down together.
func torSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
		Setpgid:   true,
	}
}
