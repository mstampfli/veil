// veil — per-app tunnel isolation CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	_ "github.com/mstampfli/veil/internal/backends/all"
	"github.com/mstampfli/veil/internal/cli"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/osutil"
)

func main() {
	// Augment PATH so ip/iptables/etc. found in /sbin are visible
	// even when launched from contexts (.desktop, systemd) that ship
	// a minimal PATH.
	osutil.EnsureSysPath()
	osutil.EnsureIPTablesLock()
	// Auto-elevate group membership when the user is on /etc/group's
	// veil list but their current session predates the usermod. Avoids
	// the "log out and log back in" trap on /dev/net/tun. No-op when
	// already in veil group or membership is genuinely missing.
	osutil.EnsureVeilGroup()

	// User-ns child re-exec dispatch — see cmd/veil-gui/main.go for
	// the rationale. Same env-var detection covers the CLI binary too
	// since cmd/veil is the canonical re-exec target for non-GUI
	// flows (CLI Up/Down).
	engine.MaybeRunUsernsChild()
	// Reap orphan veil userns children before any engine.Up.
	engine.ReapOrphanUsernsChildren()

	logger.Init()
	logger.L().Info("veil starting", "version", cli.Version)
	root := &cobra.Command{
		Use:   "veil",
		Short: "Per-app tunnel isolation",
		Long:  "Veil routes any app through any tunnel — WireGuard, OpenVPN, SOCKS5, HTTP proxy, Tor — with isolated profiles. Local. No telemetry.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		cli.ListCmd(),
		cli.RunCmd(),
		cli.StopCmd(),
		cli.StatusCmd(),
		cli.IPCmd(),
		cli.ShellCmd(),
		cli.DoctorCmd(),
		cli.SetupCmd(),
		cli.ProfileCmd(),
		cli.LicenseCmd(),
		cli.UninstallCmd(),
		cli.VersionCmd(),
		cli.UpdateCmd(),
		cli.SelftestCmd(),
		cli.LogsCmd(),
		cli.CleanCmd(),
		cli.TorStatusCmd(),
		cli.TorNewCircuitCmd(),
		cli.StatsCmd(),
		cli.AutoConnectCmd(),
		cli.PersonaCmd(),
		cli.MITMCmd(),
		cli.QuitCmd(),
		cli.DoHProxyCmd(),
		cli.BugReportCmd(),
	)

	// Show license tier in long help.
	st := license.LoadFromDefault()
	root.Long += fmt.Sprintf("\n\nLicense: %s", st.Tier)
	root.Long += "\n\nFound a bug? Please report it: run `veil bug-report` (or open an" +
		"\nissue at https://github.com/mstampfli/veil/issues). Bug reports are" +
		"\nwelcome and genuinely help."

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
