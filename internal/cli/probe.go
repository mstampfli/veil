package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/engine"
)

// profileProbeCmd: veil profile probe <name>
//
// Brings the profile up, runs leak probes inside the namespace
// (DNS connectivity, IPv6 isolation, listening sockets), tears down,
// reports the table.
func profileProbeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "probe <profile>",
		Short: "Run network leak probes against a profile (DNS, IPv6, listening sockets)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}
			eng := engine.Active()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			sess, err := eng.Up(ctx, p)
			if err != nil {
				return err
			}
			defer eng.Down(sess)

			results := eng.ProbeLeaks(ctx, sess)
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROBE\tOK\tDETAIL")
			anyFail := false
			for _, r := range results {
				ok := "ok"
				if !r.OK {
					ok = "FAIL"
					anyFail = true
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Name, ok, r.Detail)
			}
			tw.Flush()
			if anyFail {
				return fmt.Errorf("one or more probes failed")
			}
			return nil
		},
	}
}
