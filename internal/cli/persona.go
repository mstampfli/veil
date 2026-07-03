package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/persona"
)

// PersonaCmd: veil persona list/show/new/forge/delete.
func PersonaCmd() *cobra.Command {
	c := &cobra.Command{Use: "persona", Short: "Manage browser personas (UA, locale, TZ, screen)"}
	c.AddCommand(personaListCmd(), personaShowCmd(), personaNewCmd(), personaForgeCmd(), personaDeleteCmd())
	return c
}

// personaForgeCmd: deterministically generate a realistic, unique
// persona from a name and save it to the store. Same name → same
// persona forever. Different names produce statistically uncorrelated
// realistic identities (different OS, browser, screen, GPU, etc.).
//
// This is the "anti-detect" path: each profile auto-forges its own
// persona so two profiles look like two different real people.
func personaForgeCmd() *cobra.Command {
	var country string
	c := &cobra.Command{
		Use:   "forge <name>",
		Short: "Generate a deterministic, realistic, unique persona from a name",
		Long: `Forge produces a unique-but-plausible browser identity from a name.
Same name always yields the same persona; different names produce
statistically uncorrelated personas drawn from real-world frequency
distributions (OS, browser, screen res, hardware, GPU, locale).

Use this to give every profile its own "real person" identity instead
of sharing a bundled persona across profiles.

The --country flag pins the persona's locale + timezone + claimed
country to a specific value so the persona aligns with where your
VPN/Tor exit actually lives. Recommended whenever you control your
exit country.

Examples:
  veil persona forge work-twitter
  veil persona forge work-twitter --country DE   # German persona
  veil persona forge eu-account --country FR    # French persona`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := license.RequirePro("persona forge"); err != nil {
				return err
			}
			s, err := persona.DefaultStore()
			if err != nil {
				return err
			}
			name := args[0]
			var p *persona.Persona
			if country != "" {
				p = persona.ForgeWith(name, persona.ForgeOptions{Country: country})
				if p == nil {
					return fmt.Errorf("forge: empty result")
				}
				if err := s.Save(p); err != nil {
					return err
				}
			} else {
				p, err = s.ForgeAndStore(name)
				if err != nil {
					return err
				}
			}
			fmt.Printf("forged persona %q\n", p.Name)
			fmt.Printf("  UA:     %s\n", p.UserAgent)
			fmt.Printf("  OS:     %s (%s)\n", p.Platform, p.OSCPU)
			fmt.Printf("  screen: %dx%d @%.2fx\n", p.ScreenWidth, p.ScreenHeight, p.DevicePixelRatio)
			fmt.Printf("  hw:     %d cores, %d GB\n", p.HardwareConcurrency, p.DeviceMemory)
			fmt.Printf("  locale: %s, tz=%s, country=%s\n", p.Locale, p.Timezone, p.Country)
			fmt.Printf("  engine: %s\n", p.Engine)
			fmt.Printf("  webgl:  %s / %s\n", p.WebGLUnmaskedVendor, p.WebGLUnmaskedRenderer)
			return nil
		},
	}
	c.Flags().StringVar(&country, "country", "",
		"Pin persona to ISO 3166-1 alpha-2 country (DE/US/JP/...) — overrides random locale pick")
	return c
}

func personaListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all personas",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := persona.DefaultStore()
			if err != nil {
				return err
			}
			ps, err := s.LoadAll()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tDESCRIPTION\tPLATFORM\tLOCALE")
			for _, p := range ps {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.Description, p.Platform, p.Locale)
			}
			return tw.Flush()
		},
	}
}

func personaShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a persona",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := persona.DefaultStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(p, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
}

func personaNewCmd() *cobra.Command {
	var ua, lang, locale, tz, platform string
	var w, h, hc int
	var dpr float64
	c := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a custom persona",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := license.RequirePro("persona system"); err != nil {
				return err
			}
			s, err := persona.DefaultStore()
			if err != nil {
				return err
			}
			p := &persona.Persona{
				Name: args[0],
				UserAgent: ua, AcceptLanguage: lang, Locale: locale,
				Timezone: tz, Platform: platform,
				ScreenWidth: w, ScreenHeight: h, DevicePixelRatio: dpr,
				HardwareConcurrency: hc,
			}
			if err := s.Save(p); err != nil {
				return err
			}
			fmt.Println("Created", p.Name)
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&ua, "ua", "", "User-Agent")
	f.StringVar(&lang, "accept-language", "", "Accept-Language header")
	f.StringVar(&locale, "locale", "", "libc locale (e.g. en_US.UTF-8)")
	f.StringVar(&tz, "tz", "", "IANA timezone")
	f.StringVar(&platform, "platform", "", "navigator.platform string")
	f.IntVar(&w, "screen-w", 0, "screen width")
	f.IntVar(&h, "screen-h", 0, "screen height")
	f.Float64Var(&dpr, "dpr", 0, "device pixel ratio")
	f.IntVar(&hc, "hw-concurrency", 0, "navigator.hardwareConcurrency")
	return c
}

func personaDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a persona",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := persona.DefaultStore()
			if err != nil {
				return err
			}
			return s.Delete(args[0])
		},
	}
}
