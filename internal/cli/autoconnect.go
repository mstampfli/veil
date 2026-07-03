package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/osutil"
)

// AutoConnectCmd: veil autoconnect enable/disable/list <profile>
//
// Generates ~/.config/systemd/user/veil-<profile>.service that runs the
// profile at user login.
func AutoConnectCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "autoconnect",
		Short: "Manage systemd user units that auto-launch profiles at login",
	}
	c.AddCommand(
		&cobra.Command{
			Use:   "enable <profile>",
			Short: "Generate and enable a systemd --user unit for this profile",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return enableAutoconnect(args[0])
			},
		},
		&cobra.Command{
			Use:   "disable <profile>",
			Short: "Disable and remove the systemd unit for this profile",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return disableAutoconnect(args[0])
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List enabled auto-connect profiles",
			RunE: func(cmd *cobra.Command, args []string) error {
				return listAutoconnect()
			},
		},
	)
	return c
}

func systemdUserDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

const unitTemplate = `[Unit]
Description=Veil profile: %s
After=graphical-session.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/sudo -n /usr/local/bin/veil run %s
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=default.target
`

func enableAutoconnect(name string) error {
	dir, err := systemdUserDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "veil-"+name+".service")
	body := fmt.Sprintf(unitTemplate, name, name)
	if err := osutil.WriteFileAtomic(path, []byte(body), 0o644); err != nil {
		return err
	}
	fmt.Println("Wrote", path)
	fmt.Println("Now run:")
	fmt.Println("  systemctl --user daemon-reload")
	fmt.Println("  systemctl --user enable --now veil-" + name + ".service")
	fmt.Println()
	fmt.Println("Note: the unit calls `sudo -n veil run`, so you must have")
	fmt.Println("passwordless sudo configured (run `sudo veil setup` once).")
	return nil
}

func disableAutoconnect(name string) error {
	dir, err := systemdUserDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "veil-"+name+".service")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("Removed", path)
	fmt.Println("Now run:")
	fmt.Println("  systemctl --user disable veil-" + name + ".service 2>/dev/null || true")
	fmt.Println("  systemctl --user daemon-reload")
	return nil
}

func listAutoconnect() error {
	dir, err := systemdUserDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "veil-") && strings.HasSuffix(n, ".service") {
			fmt.Println(strings.TrimSuffix(strings.TrimPrefix(n, "veil-"), ".service"))
		}
	}
	return nil
}
