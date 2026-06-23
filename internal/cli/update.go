package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/updater"
)

// UpdateCmd: veil update [--check] [--force]
//
// Self-updates veil from GitHub releases (free edition) or, for a licensed
// Pro build, from the configured licensed feed (VEIL_UPDATE_URL). Network is
// contacted only when this command runs.
func UpdateCmd() *cobra.Command {
	var check, force bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Update veil to the latest release",
		Long: `Check for and install the latest veil release.

The free edition pulls public releases from GitHub. A licensed Pro build
pulls from the configured feed (set VEIL_UPDATE_URL) and also refreshes the
local revocation list. Downloads are verified against a baked Ed25519 release
key before the running binary is replaced.

  veil update --check   report current vs latest, do not install
  veil update           download and install if a newer release exists
  veil update --force    install even if not newer (re-install / downgrade)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Make the updater agree with cli.Version on "current".
			updater.SetCurrentVersion(Version)

			fmt.Printf("Current version: %s\n", Version)

			ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
			defer cancel()

			rel, err := updater.CheckLatest(ctx)
			if err != nil {
				return fmt.Errorf("checking for updates: %w", err)
			}
			fmt.Printf("Latest version:  %s\n", rel.Version)

			// Pro builds also refresh the offline revocation list while online.
			if license.ProEdition() && license.LoadFromDefault().IsPro() {
				if rerr := updater.RefreshRevocations(ctx); rerr != nil {
					fmt.Fprintf(os.Stderr, "warning: could not refresh revocation list: %v\n", rerr)
				}
			}

			upToDate := !updater.Newer(rel.Version, Version)

			if check {
				if upToDate {
					fmt.Println("already up to date")
				} else {
					fmt.Printf("update available: %s -> %s (run 'veil update' to install)\n", Version, rel.Version)
				}
				return nil
			}

			if upToDate && !force {
				fmt.Println("already up to date")
				return nil
			}

			fmt.Printf("Downloading %s...\n", rel.AssetName)
			var lastPct int = -1
			opts := updater.Options{
				Force: force,
				Progress: func(done, total int64) {
					if total <= 0 {
						return
					}
					pct := int(done * 100 / total)
					if pct != lastPct && pct%5 == 0 {
						lastPct = pct
						fmt.Printf("\r  %d%%", pct)
					}
				},
			}
			if err := updater.Apply(ctx, rel, opts); err != nil {
				fmt.Println()
				return err
			}
			fmt.Printf("\nupdated to %s; restart veil\n", rel.Version)
			return nil
		},
	}
	c.Flags().BoolVar(&check, "check", false, "report current vs latest, do not install")
	c.Flags().BoolVar(&force, "force", false, "install even if not newer (re-install or downgrade)")
	return c
}
