package cli

// `veil dohproxy` runs the bundled DoH proxy in the foreground.
// Spawned by the engine inside a profile's netns when the profile has
// dns_proxy: true. Listens on the given local addr (UDP+TCP), accepts
// wire-format DNS queries, forwards as DoH POST to the upstream URL.
//
// Hidden subcommand — not intended for direct user invocation; the
// engine wires it up via "ip netns exec <ns> veil dohproxy --listen
// 127.0.0.1:N --upstream URL".

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/dohproxy"
)

func DoHProxyCmd() *cobra.Command {
	var listen, upstream, readyFile string
	c := &cobra.Command{
		Use:    "dohproxy",
		Short:  "(internal) Run the bundled DNS-to-DoH proxy",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Log to a file the moment we enter RunE, before any
			// validation. If this never fires, the issue is upstream
			// of subcommand dispatch (cobra parsing, init() hangs,
			// binary not actually running, etc).
			if f, err := os.OpenFile("/tmp/veil-dohproxy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
				fmt.Fprintf(f, "[cli RunE] pid=%d listen=%q upstream=%q ready=%q args=%v\n",
					os.Getpid(), listen, upstream, readyFile, args)
				f.Close()
			}
			if listen == "" || upstream == "" {
				return fmt.Errorf("--listen and --upstream are required")
			}
			ctx, stop := signal.NotifyContext(context.Background(),
				os.Interrupt, syscall.SIGTERM)
			defer stop()
			return dohproxy.Run(ctx, listen, upstream, readyFile)
		},
	}
	c.Flags().StringVar(&listen, "listen", "127.0.0.1:53", "address:port to listen on (UDP + TCP)")
	c.Flags().StringVar(&upstream, "upstream", "", "DoH endpoint URL (must be IP literal, e.g. https://194.242.2.2/dns-query)")
	c.Flags().StringVar(&readyFile, "ready-file", "", "path to touch once both listeners are bound (engine reads as the start signal)")
	return c
}
