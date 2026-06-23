//go:build linux

package wireguard

// Defensive cleanup of leaked veilwg* tun devices.
//
// wireguard-go's Device.Close() can hang on socket teardown; if our
// engine.Down() abandons it after the per-backend timeout, the tun
// device stays in the host namespace until process exit (or until we
// sweep it). Across many start/stop cycles these accumulate and
// eventually exhaust the kernel's tun device slots — at which point
// subsequent launches fail with "create tun: device or resource busy"
// or similar.
//
// This sweep runs at every WG Start — finds any device whose name
// starts with our well-known prefix "veilwg", deletes it. Best-effort:
// errors are silently swallowed, the actual CreateTUN call below will
// surface any real failure.

import (
	"net"
	"os/exec"
	"strings"
)

func cleanLeakedVeilWG() {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "veilwg") {
			// `ip link del <name>` works for tun devices regardless
			// of whether userspace handles are still open — kernel
			// closes the underlying file descriptor.
			_ = exec.Command("ip", "link", "del", iface.Name).Run()
		}
	}
}
