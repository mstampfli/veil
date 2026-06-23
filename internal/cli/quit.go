package cli

import (
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"
)

// QuitCmd: `veil quit` — connect to the running veil-gui's shutdown
// socket and trigger a clean teardown. Avoids the "process is owned
// by root via pkexec, my normal user can't pkill" trap.
//
// Linux only — Windows/macOS don't have the cross-uid problem because
// veil-gui doesn't elevate the same way; the window-close button or
// task-manager kill works there.
func QuitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quit",
		Short: "Stop the running veil-gui (sends shutdown via local socket)",
		Long: `Sends a shutdown signal to the running veil-gui via its user-
accessible Unix socket. Useful when veil-gui was launched via pkexec
or sudo and your normal-user pkill can't reach it across the uid
boundary.

The socket is at /tmp/veil-gui.sock. veil-gui chowns it to the user
that ran sudo/pkexec on startup, so this command works without
needing root.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := net.DialTimeout("unix", "/tmp/veil-gui.sock", 2*time.Second)
			if err != nil {
				return fmt.Errorf("veil-gui doesn't appear to be running (no shutdown socket at /tmp/veil-gui.sock): %w", err)
			}
			_ = c.Close()
			fmt.Println("shutdown signal sent")
			return nil
		},
	}
}
