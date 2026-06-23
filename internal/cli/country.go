package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/geoip"
	"github.com/mstampfli/veil/internal/profile"
)

// profileCountryCmd: veil profile country <name>
//
// Pre-flight, OFFLINE: reads the chain's first-hop config to find
// the endpoint IP, then looks it up in the local GeoIP database.
//
// IMPORTANT: this is INFORMATIONAL ONLY. The endpoint IP is the
// SERVER we connect to — for commercial VPNs, also the exit, but
// NOT GUARANTEED. Real verification happens at first launch when
// the actual exit IP is queried through the live chain.
//
// If GeoIP database isn't installed, says so honestly. If the
// endpoint is a hostname (not an IP), says so — DNS resolution is
// deliberately skipped to avoid leaking the lookup.
func profileCountryCmd() *cobra.Command {
	var codeOnly bool
	c := &cobra.Command{
		Use:   "country <name>",
		Short: "Pre-flight: show profile's likely exit country (offline)",
		Long: `Reads the first chain hop's endpoint from its config file
and looks up the country in the local GeoIP database. Fully
offline — no chain comes up, no external API calls.

This is INFORMATIONAL: the endpoint IP is the server we connect
to. For typical commercial VPNs (Mullvad, Proton, IVPN, etc.),
the same server is also the exit, so endpoint country = exit
country. For multi-hop or NAT'd-egress setups, they differ — in
which case the actual exit country is verified on first launch
and saved to the profile.

If the endpoint is a hostname (e.g. de.mullvad.net), DNS is NOT
resolved here — we don't want to leak the lookup. The country
will instead be captured on first launch.

Examples:
  veil profile country my-mullvad-de
  veil profile country my-mullvad-de --code-only   # for shell scripting`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}

			// If we already have a verified ground-truth, prefer it.
			if !p.VerifiedAt.IsZero() && p.VerifiedCountry != "" {
				if codeOnly {
					fmt.Println(p.VerifiedCountry)
					return nil
				}
				fmt.Printf("%s — verified %s (IP %s, country %s, last confirmed %s)\n",
					p.Name, "✓", p.VerifiedIP, p.VerifiedCountry,
					p.VerifiedAt.Format("2006-01-02 15:04 MST"))
				return nil
			}

			ei, err := p.ReadFirstHopEndpoint()
			if err == profile.ErrUnknown {
				if codeOnly {
					fmt.Println("")
					return nil
				}
				fmt.Printf("%s — endpoint unknown until first launch (Tor or similar dynamic-exit chain)\n", p.Name)
				return nil
			}
			if err != nil {
				return err
			}

			if !ei.IsIP {
				if codeOnly {
					fmt.Println("")
					return nil
				}
				fmt.Printf("%s — endpoint is hostname %q (DNS skipped for opsec; country will be captured on first launch)\n",
					p.Name, ei.Host)
				return nil
			}

			if !geoip.IsAvailable() {
				if codeOnly {
					fmt.Println("")
					return nil
				}
				fmt.Printf("%s — endpoint IP %s, but GeoIP database not installed\n", p.Name, ei.Host)
				fmt.Printf("        run `sudo veil setup --install-geoip` to enable offline country preview,\n")
				fmt.Printf("        or just launch the profile — country will be captured on first launch.\n")
				return nil
			}

			country, ok := geoip.LookupString(ei.Host)
			if !ok {
				if codeOnly {
					fmt.Println("")
					return nil
				}
				fmt.Printf("%s — endpoint IP %s not in GeoIP database (country UNKNOWN — verify on first launch)\n",
					p.Name, ei.Host)
				return nil
			}

			if codeOnly {
				fmt.Println(country)
				return nil
			}
			fmt.Printf("%s — endpoint %s → likely exit country: %s (UNVERIFIED — first launch will confirm)\n",
				p.Name, ei.Host, country)
			return nil
		},
	}
	c.Flags().BoolVar(&codeOnly, "code-only", false,
		"output only the ISO country code (or empty line) — for shell pipelines")
	return c
}
