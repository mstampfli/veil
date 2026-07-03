package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/runtime"
)

// TorStatusCmd: veil tor-status <profile>
func TorStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tor-status <profile>",
		Short: "Show Tor circuit info for a running profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctrl, err := dialTorControl(args[0])
			if err != nil {
				return err
			}
			defer ctrl.Close()
			out, err := ctrl.CircuitStatus()
			if err != nil {
				return err
			}
			if out == "" {
				fmt.Println("(no circuits)")
			} else {
				fmt.Println(out)
			}
			return nil
		},
	}
}

// TorNewCircuitCmd: veil tor-newcircuit <profile>
func TorNewCircuitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tor-newcircuit <profile>",
		Short: "Force Tor to build new circuits for subsequent connections",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctrl, err := dialTorControl(args[0])
			if err != nil {
				return err
			}
			defer ctrl.Close()
			if err := ctrl.NewCircuit(); err != nil {
				return err
			}
			fmt.Println("New circuit signal sent.")
			return nil
		},
	}
}

func dialTorControl(profileName string) (*tor.Control, error) {
	rs, err := runtime.Load(profileName)
	if err != nil {
		return nil, fmt.Errorf("profile %q is not running (%w)", profileName, err)
	}
	if rs.TorCtrlPort == 0 {
		return nil, fmt.Errorf("profile %q has no Tor control port — is the chain using tor?", profileName)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", rs.TorCtrlPort)
	// The control port is bound inside the namespace. Reach it from
	// outside by exec'ing curl through `ip netns exec`. For simplicity
	// (and because Tor's control protocol is line-oriented), we use the
	// Go control client by dialing into the namespace via an in-netns
	// socat or netcat. To avoid that dependency, we instead spawn a
	// small "ip netns exec" wrapper that forwards stdin/stdout. Easier:
	// since the namespace's 127.0.0.1 is a separate stack, we use a
	// per-call dial through `nsenter` with the netns from
	// /var/run/netns/<name>.
	return dialThroughNetns(rs.NetnsName, addr, rs.TorCookie)
}
