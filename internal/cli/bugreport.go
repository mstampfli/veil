package cli

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// IssuesNewURL is the GitHub "new issue" endpoint for the public repo.
const IssuesNewURL = "https://github.com/mstampfli/veil/issues/new"

// BugReportCmd: veil bug-report — collect local diagnostics and build a
// pre-filled GitHub issue. Consistent with the no-telemetry guarantee: NOTHING
// is sent automatically. We only gather environment facts and hand you a ready
// link + text to file the report yourself.
func BugReportCmd() *cobra.Command {
	var open bool
	c := &cobra.Command{
		Use:   "bug-report",
		Short: "Report a bug — builds a pre-filled GitHub issue (nothing is sent automatically)",
		Long: "Collects local environment details (version, OS, kernel) and produces a\n" +
			"ready-to-file GitHub issue. veil has no telemetry: nothing leaves your\n" +
			"machine unless you choose to open and submit the link.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := bugReportBody()
			u := IssuesNewURL + "?title=" + url.QueryEscape("[bug] ") + "&labels=bug&body=" + url.QueryEscape(body)
			fmt.Println("Thanks for reporting a bug — it genuinely helps make veil better.")
			fmt.Println()
			fmt.Println("veil has no telemetry, so nothing is sent automatically. Review the")
			fmt.Println("details below and open this link to file the report on GitHub:")
			fmt.Println()
			fmt.Println("  " + u)
			fmt.Println()
			fmt.Println("--- prefilled report (also embedded in the link) ---")
			fmt.Println(body)
			if open {
				if err := openInBrowser(u); err != nil {
					fmt.Println("\n(could not open a browser automatically — copy the link above)")
				}
			} else {
				fmt.Println("\nTip: re-run with --open to launch this in your browser.")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&open, "open", false, "open the pre-filled report in your browser")
	return c
}

// bugReportBody renders the markdown issue template with local diagnostics.
func bugReportBody() string {
	var b strings.Builder
	b.WriteString("## What happened?\n\n<!-- describe the bug -->\n\n")
	b.WriteString("## What did you expect?\n\n<!-- expected behavior -->\n\n")
	b.WriteString("## Steps to reproduce\n\n1. \n2. \n\n")
	b.WriteString("## Environment\n\n")
	fmt.Fprintf(&b, "- veil version: %s\n", Version)
	fmt.Fprintf(&b, "- OS/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "- kernel: %s\n", kernelVersion())
	b.WriteString("\n## `veil doctor` output\n\n```\n")
	b.WriteString(doctorSummary())
	b.WriteString("```\n\n")
	b.WriteString("## Logs (optional)\n\n")
	b.WriteString("<!-- paste relevant lines from `veil logs <profile>` if applicable -->\n")
	return b.String()
}

// kernelVersion returns `uname -sr`, best-effort.
func kernelVersion() string {
	out, err := exec.Command("uname", "-sr").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// doctorSummary runs `veil doctor` against the current binary, best-effort, so
// the report includes the environment checks that most often explain a bug.
func doctorSummary() string {
	self, err := exec.LookPath("veil")
	if err != nil {
		if self, err = exec.LookPath("/proc/self/exe"); err != nil {
			return "(run `veil doctor` and paste the output)\n"
		}
	}
	out, _ := exec.Command(self, "doctor").CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "(run `veil doctor` and paste the output)\n"
	}
	return s + "\n"
}

// openInBrowser opens a URL with the platform handler (best-effort).
func openInBrowser(u string) error {
	var bin string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		bin, args = "open", []string{u}
	case "windows":
		bin, args = "cmd", []string{"/c", "start", u}
	default:
		bin, args = "xdg-open", []string{u}
	}
	return exec.Command(bin, args...).Start()
}
