package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/profile"
)

// profileVerifyOnceCmd: veil profile verify-once <name>
//
// Opt-in single ipinfo probe for multi-hop profiles where local
// verification can't see the actual exit. Brings the chain up, runs
// ONE ipinfo query, captures the result, saves to the profile, tears
// the chain down.
//
// After this, the profile has VerifiedIP / VerifiedCountry set, and
// subsequent launches enforce locally without ever probing again.
//
// We are honest about the leak: ipinfo will see this exit IP at this
// time, in their access logs. The user explicitly consents.
func profileVerifyOnceCmd() *cobra.Command {
	var skipPrompt bool
	c := &cobra.Command{
		Use:   "verify-once <profile>",
		Short: "Single-shot exit-IP probe for multi-hop profiles (logged at ipinfo)",
		Long: `Brings the profile chain up, runs ONE HTTPS query through it to
ipinfo.io to discover the actual exit IP + country, captures the
result into the profile, and tears the chain down.

After this, the profile has its exit pinned LOCALLY. Subsequent
launches verify the kernel's tunnel state matches the saved values
and never probe ipinfo again.

LEAK NOTE: ipinfo will record one access from this exit IP at this
time. That single log entry could be subpoenaed and correlated with
later persona traffic from the same exit. For investigation-grade
opsec, decide whether this one-time leak is acceptable for your
threat model.

Use this for multi-hop chains where local verification can't see
the exit (entry server != exit server). Single-hop profiles don't
need this — Veil reads the peer IP from the kernel locally.

Examples:
  veil profile verify-once mullvad-multihop-de
  veil profile verify-once my-profile -y         # skip confirmation`,
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
			if !p.ChainIsMultihop() {
				fmt.Fprintln(os.Stderr,
					"warning: this profile is single-hop — verify-once isn't needed.")
				fmt.Fprintln(os.Stderr,
					"         Single-hop profiles already verify locally on every launch.")
			}

			if !skipPrompt {
				fmt.Println("This will:")
				fmt.Println("  1. Bring the profile's chain up")
				fmt.Println("  2. Run ONE HTTPS query to ipinfo.io through the chain")
				fmt.Println("  3. Save the observed exit IP + country to the profile")
				fmt.Println("  4. Tear the chain down")
				fmt.Println()
				fmt.Println("ipinfo.io will log: your exit IP, the timestamp, this query.")
				fmt.Println("That log entry is correlatable with later persona traffic")
				fmt.Println("if anyone subpoenas ipinfo.")
				fmt.Println()
				fmt.Print("Continue? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				ans, _ := reader.ReadString('\n')
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
					return fmt.Errorf("aborted")
				}
			}

			eng := engine.Active()
			ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
			defer cancel()
			sess, err := eng.Up(ctx, p)
			if err != nil {
				return err
			}
			defer eng.Down(sess)

			info, err := eng.ExternalIPInfo(ctx, sess)
			if err != nil {
				return fmt.Errorf("probe failed: %w", err)
			}

			gotASN := ""
			if i := strings.Index(info.Org, " "); i > 0 {
				gotASN = info.Org[:i]
			}
			p.VerifiedIP = info.IP
			p.VerifiedCountry = strings.ToUpper(info.Country)
			p.VerifiedAt = time.Now().UTC()
			if p.RequireExitIP == "" {
				p.RequireExitIP = info.IP
			}
			if p.RequireExitASN == "" {
				p.RequireExitASN = gotASN
			}
			if p.GeoVerificationMode == "" {
				p.GeoVerificationMode = "probe-once"
			}
			if err := s.Save(p); err != nil {
				return fmt.Errorf("save: %w", err)
			}

			fmt.Println()
			fmt.Printf("✓ Verified %q\n", p.Name)
			fmt.Printf("  exit IP:      %s\n", p.VerifiedIP)
			fmt.Printf("  exit country: %s\n", p.VerifiedCountry)
			if gotASN != "" {
				fmt.Printf("  exit ASN:     %s (%s)\n", gotASN, info.Org)
			}
			fmt.Printf("  city:         %s\n", info.City)
			fmt.Println()
			fmt.Println("Saved to profile. Subsequent launches verify locally — no more probes.")
			return nil
		},
	}
	c.Flags().BoolVarP(&skipPrompt, "yes", "y", false, "skip leak-acknowledgment prompt")
	_ = profile.ErrUnknown // silence import-cycle hint
	return c
}
