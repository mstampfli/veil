package cli

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/persona"
)

// driftCmd: veil profile drift <name>
//
// Brings the profile up, fetches the actual exit IP / city / ASN /
// country, then diffs against the persona's claimed values + any
// require_exit_* fields. Prints a table of (claimed, observed, match)
// so the operator can see at a glance whether persona consistency is
// holding.
//
// Use this before a high-stakes session to verify nothing has drifted.
func profileDriftCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "drift <profile>",
		Short: "Compare live exit info against the profile's persona/locked-endpoint expectations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := license.RequirePro("profile drift"); err != nil {
				return err
			}
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}

			// Resolve the persona name (forge if needed).
			personaName := p.Persona
			if p.ForgePersona && personaName == "" {
				personaName = p.Name
			}
			var pers *persona.Persona
			if personaName != "" {
				if ps, err := persona.DefaultStore(); err == nil {
					pers, _ = ps.Load(personaName)
					if pers == nil && p.ForgePersona {
						pers, _ = ps.ForgeAndStore(personaName)
					}
				}
			}

			// Bring up the profile, fetch live IP info.
			eng := engine.Active()
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			sess, err := eng.Up(ctx, p)
			if err != nil {
				return err
			}
			defer eng.Down(sess)

			info, err := eng.ExternalIPInfo(ctx, sess)
			if err != nil {
				return err
			}

			// Build the comparison table.
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "FIELD\tCLAIMED\tOBSERVED\tMATCH")

			// Country: persona.Country vs info.Country
			countryWant := strings.ToUpper(p.RequireExitCountry)
			if countryWant == "" && pers != nil {
				countryWant = strings.ToUpper(pers.Country)
			}
			row(tw, "country", countryWant, strings.ToUpper(info.Country))

			// City
			row(tw, "city", p.RequireExitCity, info.City)

			// ASN
			gotASN := ""
			if i := strings.Index(info.Org, " "); i > 0 {
				gotASN = info.Org[:i]
			}
			row(tw, "asn", p.RequireExitASN, gotASN)

			// IP (exact)
			row(tw, "ip", p.RequireExitIP, info.IP)

			// Timezone (persona vs ipinfo)
			tzWant := ""
			if pers != nil {
				tzWant = pers.Timezone
			}
			row(tw, "timezone", tzWant, info.Timezone)

			tw.Flush()
			return nil
		},
	}
}

// row prints a comparison row. Unset claims display as "—" and always
// match (we can't tell drift from "no claim made").
func row(tw *tabwriter.Writer, label, want, got string) {
	wantDisp := want
	if wantDisp == "" {
		wantDisp = "—"
	}
	gotDisp := got
	if gotDisp == "" {
		gotDisp = "—"
	}
	match := "ok"
	switch {
	case want == "":
		match = "(no claim)"
	case strings.EqualFold(want, got):
		match = "ok"
	default:
		match = "DRIFT"
	}
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", label, wantDisp, gotDisp, match)
}
