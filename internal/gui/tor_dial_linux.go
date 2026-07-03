//go:build linux

package gui

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netns"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/engine"
)

// dialTorControlForGUI opens a connection to a Tor control port that
// lives inside a session's namespace. On Linux we have to enter the
// namespace before dialing.
func dialTorControlForGUI(s *engine.Session, port int, cookie string) (*tor.Control, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("tor control needs root")
	}
	nsName := nsNameFromSession(s)
	if nsName == "" {
		// Tor is on host (no namespace) — direct dial.
		return tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
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
		return nil, err
	}
	defer target.Close()
	if err := netns.Set(target); err != nil {
		return nil, err
	}
	defer netns.Set(cur)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	return tor.WrapControl(conn, cookie)
}
