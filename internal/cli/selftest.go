package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/chain"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/launcher"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
)

// SelftestCmd: veil selftest <profile> | --all
//
// Brings the profile up, fetches the external IP, counts kill-switch
// rules, then tears down. Reports a pass/fail summary — works for any
// chain (direct, proxy, tunnel, multi-hop).
func SelftestCmd() *cobra.Command {
	var timeoutSec int
	var allProfiles bool
	c := &cobra.Command{
		Use:   "selftest [profile]",
		Short: "Bring a profile up, verify connectivity, tear down",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := loadStore()
			if err != nil {
				return err
			}
			var names []string
			switch {
			case allProfiles:
				names, err = s.List()
				if err != nil {
					return err
				}
			case len(args) == 1:
				names = []string{args[0]}
			default:
				return fmt.Errorf("either pass a profile name or --all")
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE\tCHAIN\tIP\tRULES\tELAPSED\tRESULT")
			pass, fail := 0, 0
			for _, name := range names {
				p, err := s.Load(name)
				if err != nil {
					fmt.Fprintf(tw, "%s\t-\t-\t-\t-\tload: %v\n", name, err)
					fail++
					continue
				}
				if err := chain.Validate(p.Chain); err != nil {
					fmt.Fprintf(tw, "%s\t%s\t-\t-\t-\tvalidate: %v\n",
						name, chain.Summary(p.Chain), err)
					fail++
					continue
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(timeoutSec)*time.Second)
				start := time.Now()
				ip, rules, err := selftestOne(ctx, p)
				cancel()
				elapsed := time.Since(start).Round(time.Millisecond)
				if err != nil {
					fmt.Fprintf(tw, "%s\t%s\t-\t%d\t%v\tFAIL: %v\n",
						name, chain.Summary(p.Chain), rules, elapsed, err)
					fail++
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%v\tOK\n",
					name, chain.Summary(p.Chain), ip, rules, elapsed)
				pass++
			}
			_ = tw.Flush()
			fmt.Printf("\n%d passed, %d failed\n", pass, fail)
			if fail > 0 {
				return fmt.Errorf("%d profile(s) failed", fail)
			}
			return nil
		},
	}
	c.Flags().IntVar(&timeoutSec, "timeout", 120, "per-profile timeout in seconds")
	c.Flags().BoolVar(&allProfiles, "all", false, "selftest every profile in the store")
	return c
}

func selftestOne(ctx context.Context, p *profile.Profile) (string, int, error) {
	// Selftest verifies the network chain (IP hiding / leaks), not the
	// behavioral defenses. behavioral_jitter / mouse_jitter EVIOCGRAB the
	// host's REAL keyboard/mouse (input devices aren't namespaced) and
	// re-emit with delay, which lags the whole desktop while the profile
	// is up — unacceptable for an automated connectivity check that the
	// operator isn't typing into. Disable them for the selftest run only
	// (the in-memory profile copy is not persisted).
	p.BehavioralJitter = false
	p.MouseJitter = false
	// Apply the same pre-launch normalization the run/GUI paths use, so
	// selftest exercises the real config (e.g. forge_country -> exit
	// pinning for coherence).
	p.PropagateExitConstraints()
	p.PropagateAntiFingerprintMITM()
	if err := launcher.Resolve(p); err != nil {
		return "", 0, fmt.Errorf("resolve preset: %w", err)
	}
	eng := engine.Active()
	logger.L().Info("selftest.up", "profile", p.Name, "chain", chain.Summary(p.Chain))
	sess, err := eng.Up(ctx, p)
	if err != nil {
		return "", 0, fmt.Errorf("up: %w", err)
	}
	defer func() {
		if err := eng.Down(sess); err != nil {
			logger.L().Warn("selftest.down failed", "profile", p.Name, "err", err)
		} else {
			logger.L().Info("selftest.down", "profile", p.Name)
		}
	}()

	ip, err := eng.ExternalIP(ctx, sess)
	if err != nil {
		return "", 0, fmt.Errorf("ip: %w", err)
	}
	return ip, countKillSwitchRules("veil-" + p.Name), nil
}

// countKillSwitchRules counts the number of explicit OUTPUT/INPUT rules
// in the namespace's filter table. Useful as a sanity check that the
// kill switch was actually installed.
func countKillSwitchRules(nsName string) int {
	out, err := exec.Command("ip", "netns", "exec", nsName, "iptables", "-S").Output()
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "-A OUTPUT") || strings.HasPrefix(line, "-A INPUT") {
			count++
		}
	}
	return count
}
