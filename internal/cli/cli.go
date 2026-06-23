// Package cli implements all veil CLI subcommands.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/chain"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/launcher"
	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
	"github.com/mstampfli/veil/internal/runtime"
)

func loggerPath() string                 { return logger.LogPath() }
func loggerTail(n int64) (string, error) { return logger.Tail(n) }

// torBackendIn finds the *tor.Backend in a session if any. We import the
// tor package only for the type assertion.
func torBackendIn(s *engine.Session) *tor.Backend {
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			return t
		}
	}
	return nil
}

// collectTUNs returns TUN device names from a session's backends so the
// runtime state can record them for traffic-stats lookup.
func collectTUNs(s *engine.Session) []string {
	var out []string
	for _, b := range s.Backends {
		if w, ok := b.(interface{ TUNName() string }); ok {
			if n := w.TUNName(); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

// Version is set at build time via -ldflags "-X .../cli.Version=..."
var Version = "dev"

func loadStore() (*profile.Store, error) {
	return profile.DefaultStore()
}

// ListCmd: veil list
func ListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all profiles and their status",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			profs, err := s.LoadAll()
			if err != nil {
				return err
			}
			running, _ := runtime.LoadAll()
			runMap := map[string]*runtime.Session{}
			for _, r := range running {
				runMap[r.Profile] = r
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tCHAIN\tAPP\tSTATUS")
			for _, p := range profs {
				app := p.App.Binary
				if p.App.Preset != "" {
					app = p.App.Preset
				}
				status := "stopped"
				// A registry record can outlive its process (crash /
				// SIGKILL skips the teardown that removes it), so confirm
				// the PID is actually alive before reporting "running" —
				// otherwise dead sessions show as running forever.
				if r, ok := runMap[p.Name]; ok && runtime.IsAlive(r) {
					status = "running (pid " + strconv.Itoa(r.PID) + ")"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, chain.Summary(p.Chain), app, status)
			}
			return tw.Flush()
		},
	}
}

// RunCmd: veil run <profile> [-- <cmd>...]
func RunCmd() *cobra.Command {
	var detach bool
	cmd := &cobra.Command{
		Use:   "run <profile> [-- <cmd>...]",
		Short: "Launch a profile (and optionally override the app to run)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if detach {
				// Fail closed instead of silently tearing down. The
				// user-namespace engine ties the profile's netns to THIS
				// process (it owns the helper child over an RPC
				// socketpair), so returning early would destroy the
				// tunnel — which is exactly what --detach used to do
				// without telling anyone. Point at the paths that work.
				return fmt.Errorf("--detach is not supported: this process owns the profile's network namespace, so returning would tear it down. Background it instead — `veil run %s &` — or install a login unit with `veil autoconnect`", args[0])
			}
			s, err := loadStore()
			if err != nil {
				return err
			}
			p, err := s.Load(args[0])
			if err != nil {
				return err
			}
			// Honor --
			if cmd.ArgsLenAtDash() > 0 {
				dashArgs := args[cmd.ArgsLenAtDash():]
				if len(dashArgs) > 0 {
					p.App.Preset = ""
					p.App.Binary = dashArgs[0]
					p.App.Args = dashArgs[1:]
				}
			}
			p.PropagateExitConstraints()
			p.PropagateAntiFingerprintMITM()
			if w := p.GeoCoherenceWarning(); w != "" {
				fmt.Fprintf(os.Stderr, "[veil] warning: %s\n", w)
			}
			geoPreflight(p)
			if err := launcher.Resolve(p); err != nil {
				return err
			}

			// License gate: free tier limits.
			lic := license.LoadFromDefault()
			caps := license.CapsFor(lic.Tier)
			profs, _ := s.LoadAll()
			if caps.MaxProfiles > 0 && len(profs) > caps.MaxProfiles {
				return fmt.Errorf("free tier limited to %d profiles (you have %d). Get Pro to lift the limit.", caps.MaxProfiles, len(profs))
			}

			eng := engine.Active()
			ctx := cmd.Context()
			fmt.Fprintf(os.Stderr, "[veil] starting profile %q (%s)...\n", p.Name, chain.Summary(p.Chain))
			sess, err := eng.Up(ctx, p)
			if err != nil {
				return err
			}
			defer func() {
				fmt.Fprintln(os.Stderr, "[veil] tearing down...")
				_ = eng.Down(sess)
				_ = runtime.Remove(p.Name)
			}()

			pid, err := eng.Launch(sess)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "[veil] launched %s (pid %d) inside profile %q\n", p.App.Binary, pid, p.Name)

			rs := &runtime.Session{
				Profile:   p.Name,
				PID:       pid,
				StartedAt: time.Now(),
				Chain:     chain.Summary(p.Chain),
				NetnsName: "veil-" + p.Name,
			}
			rs.TUNDevices = collectTUNs(sess)
			if t := torBackendIn(sess); t != nil {
				port, cookie := t.ControlInfo()
				rs.TorCtrlPort = port
				rs.TorCookie = cookie
			}
			_ = runtime.Save(rs)

			<-ctx.Done()
			return nil
		},
	}
	cmd.Flags().BoolVar(&detach, "detach", false, "(unsupported) to background a profile use `veil run <profile> &` or `veil autoconnect`")
	return cmd
}

// StopCmd: veil stop <profile>
func StopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <profile>",
		Short: "Stop a running profile and tear down its tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := runtime.Load(args[0])
			if err != nil {
				return err
			}
			if err := runtime.SignalStop(r); err != nil {
				return err
			}
			_ = runtime.Remove(args[0])
			fmt.Printf("Stopped %s\n", args[0])
			return nil
		},
	}
}

// StatusCmd: veil status
func StatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show all running profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			running, err := runtime.LoadAll()
			if err != nil {
				return err
			}
			// Skip records whose process is gone (crash / SIGKILL leaves
			// a stale record behind) so this only lists truly running
			// profiles, not ghosts.
			var alive []*runtime.Session
			for _, r := range running {
				if runtime.IsAlive(r) {
					alive = append(alive, r)
				}
			}
			if len(alive) == 0 {
				fmt.Println("(no running profiles)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE\tPID\tCHAIN\tSTARTED")
			for _, r := range alive {
				fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", r.Profile, r.PID, r.Chain, r.StartedAt.Format(time.Kitchen))
			}
			return tw.Flush()
		},
	}
}

// IPCmd: veil ip <profile> [--geo]
func IPCmd() *cobra.Command {
	var geo bool
	c := &cobra.Command{
		Use:   "ip <profile>",
		Short: "Show the external IP as seen from the profile's network",
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
			info, err := eng.ExternalIPInfo(ctx, sess)
			if err != nil {
				return err
			}
			if geo {
				fmt.Printf("IP:       %s\nHost:     %s\nCity:     %s\nRegion:   %s\nCountry:  %s\nOrg:      %s\nTimezone: %s\n",
					info.IP, info.Hostname, info.City, info.Region, info.Country, info.Org, info.Timezone)
			} else if info.City != "" || info.Country != "" {
				loc := info.City
				if info.Country != "" {
					if loc != "" {
						loc += ", "
					}
					loc += info.Country
				}
				fmt.Printf("%s  (%s)\n", info.IP, loc)
			} else {
				fmt.Println(info.IP)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&geo, "geo", false, "show full geo info (country, city, ISP)")
	return c
}

// ShellCmd: veil shell <profile>
func ShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell <profile>",
		Short: "Drop into a shell inside the profile's network",
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
			p.App.Preset = "shell"
			p.App.Binary = ""
			p.App.Args = nil
			p.PropagateExitConstraints()
			p.PropagateAntiFingerprintMITM()
			if w := p.GeoCoherenceWarning(); w != "" {
				fmt.Fprintf(os.Stderr, "[veil] warning: %s\n", w)
			}
			geoPreflight(p)
			if err := launcher.Resolve(p); err != nil {
				return err
			}
			eng := engine.Active()
			ctx := cmd.Context()
			sess, err := eng.Up(ctx, p)
			if err != nil {
				return err
			}
			defer eng.Down(sess)
			_, err = eng.Launch(sess)
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		},
	}
}

// DoctorCmd: veil doctor
func DoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run preflight checks for required system features",
		RunE: func(cmd *cobra.Command, args []string) error {
			eng := engine.Active()
			checks, err := eng.Doctor(cmd.Context())
			if err != nil {
				return err
			}
			anyFail := false
			for _, c := range checks {
				mark := "✓"
				if !c.OK {
					mark = "✗"
					if !c.Warning {
						anyFail = true
					}
				}
				if c.Warning {
					mark = "⚠"
				}
				fmt.Printf("  %s %s", mark, c.Name)
				if c.Detail != "" {
					fmt.Printf(" — %s", c.Detail)
				}
				fmt.Println()
			}
			if anyFail {
				return fmt.Errorf("required checks failed")
			}
			return nil
		},
	}
}

// CleanCmd: veil clean — emergency cleanup of orphan veil-* namespaces
// and any veil-* veth devices. Useful after a crash.
//
// Note: with the stale-recovery system added in v0.x, Veil now auto-
// cleans orphan state on engine.Up. This command is mostly for the
// "I want to nuke ALL veil state right now" use case.
func CleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Tear down all orphan Veil namespaces / veth pairs (auto-skips live sessions)",
		Long: `Removes any veil-<profile> network namespaces and veil-h-<profile>
veth pairs whose owning Veil process is no longer running.

Live sessions of OTHER Veil processes are detected via PID liveness
check and skipped — safe to run with concurrent Veil instances active.

Veil also runs this cleanup automatically on every engine.Up() so
manually invoking 'clean' is rarely needed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Non-root user-ns path: orphan netns / veth live inside the
			// userns child processes' private mount namespaces, not on
			// the host, so the host-level orphan sweep neither applies
			// nor is permitted. Reap orphan userns children instead —
			// killing a child whose owning Veil died tears down its
			// private namespaces automatically. Best-effort, no error.
			if os.Geteuid() != 0 {
				engine.ReapOrphanUsernsChildren()
				fmt.Println("Reaped orphan Veil user-ns children (non-root cleanup).")
				return nil
			}
			engine.CleanupAllOrphans()
			fmt.Println("Cleaned up Veil orphan state.")
			return nil
		},
	}
}

// StatsCmd: veil stats <profile>
func StatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats <profile>",
		Short: "Show traffic byte/packet counters for a running profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rs, err := runtime.Load(args[0])
			if err != nil {
				return fmt.Errorf("profile %q not running", args[0])
			}
			iface := rs.IfaceVeth
			if len(rs.TUNDevices) > 0 {
				iface = rs.TUNDevices[len(rs.TUNDevices)-1]
			}
			if iface == "" {
				return fmt.Errorf("profile %q has no recorded interface", args[0])
			}
			read := func(field string) uint64 {
				out, _ := exec.Command("ip", "netns", "exec", rs.NetnsName, "cat",
					"/sys/class/net/"+iface+"/statistics/"+field).Output()
				v, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
				return v
			}
			tx, rx := read("tx_bytes"), read("rx_bytes")
			fmt.Printf("Interface:  %s\nTX:         %s (%d packets)\nRX:         %s (%d packets)\n",
				iface, humanBytes(tx), read("tx_packets"), humanBytes(rx), read("rx_packets"))
			return nil
		},
	}
}

func humanBytes(n uint64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// LogsCmd: veil logs [--tail N] [--path]
func LogsCmd() *cobra.Command {
	var path bool
	var tailBytes int64
	c := &cobra.Command{
		Use:   "logs",
		Short: "Show recent veil log output (or its file path)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if path {
				p := loggerPath()
				if p == "" {
					return fmt.Errorf("logger not initialized")
				}
				fmt.Println(p)
				return nil
			}
			t, err := loggerTail(tailBytes)
			if err != nil {
				return err
			}
			fmt.Print(t)
			return nil
		},
	}
	c.Flags().BoolVar(&path, "path", false, "print log file path and exit")
	c.Flags().Int64Var(&tailBytes, "tail", 64*1024, "tail this many bytes")
	return c
}

// VersionCmd: veil version
func VersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show veil version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("veil", Version)
			edition := "free"
			if license.ProEdition() {
				edition = "pro"
			}
			fmt.Println("edition:", edition)
			// Surface the baked per-buyer build watermark. This also keeps
			// it ALIVE: BuildLicensee is set via -ldflags -X, and if nothing
			// reads it the linker's dead-code pass drops the symbol, so the
			// -X value silently vanishes and a leaked build can't be traced.
			// Reading it here forces retention (and gives a trace command:
			// run `veil version` on a leaked binary to see the buyer).
			if license.BuildLicensee != "" {
				fmt.Println("build watermark:", license.BuildLicensee)
			}
			st := license.LoadFromDefault()
			if st.Valid && st.Email != "" {
				fmt.Println("licensee:", st.Email)
			}
			if st.ID != "" {
				fmt.Println("license id:", st.ID)
			}
			return nil
		},
	}
}

// LicenseCmd: veil license install <file>, veil license show
func LicenseCmd() *cobra.Command {
	c := &cobra.Command{Use: "license", Short: "License management"}
	c.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current license status",
		RunE: func(cmd *cobra.Command, args []string) error {
			s := license.LoadFromDefault()
			b, _ := json.MarshalIndent(map[string]any{
				"tier":    s.Tier.String(),
				"valid":   s.Valid,
				"email":   s.Email,
				"reason":  s.Reason,
				"expires": s.Expires,
			}, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "install <file>",
		Short: "Install a license token from a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := os.UserConfigDir()
			if err != nil {
				return err
			}
			dst := filepath.Join(cfg, "veil", "license.jwt")
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, []byte(strings.TrimSpace(string(data))), 0o600); err != nil {
				return err
			}
			fmt.Println("Installed to", dst)
			s := license.LoadFromDefault()
			fmt.Println("Tier:", s.Tier, "valid:", s.Valid, "reason:", s.Reason)
			return nil
		},
	})
	return c
}
