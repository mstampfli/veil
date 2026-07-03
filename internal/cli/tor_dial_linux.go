//go:build linux

package cli

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netns"

	"github.com/mstampfli/veil/internal/backends/tor"
)

// dialThroughNetns connects to addr from inside the netns by locking the
// OS thread, switching netns, dialing, switching back. Returns a Control
// wrapping the connection.
func dialThroughNetns(nsName, addr, cookiePath string) (*tor.Control, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("tor control dial needs root (try sudo)")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cur, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer cur.Close()
	target, err := netns.GetFromName(nsName)
	if err != nil {
		return nil, fmt.Errorf("netns %q: %w", nsName, err)
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return nil, err
	}
	defer netns.Set(cur)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s in netns %s: %w", addr, nsName, err)
	}
	return tor.WrapControl(conn, cookiePath)
}
