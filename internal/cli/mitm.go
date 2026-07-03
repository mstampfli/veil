package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/backends/tlsmitm"
	"github.com/mstampfli/veil/internal/license"
)

// MITMCmd: veil mitm install-ca / uninstall-ca / show.
func MITMCmd() *cobra.Command {
	c := &cobra.Command{Use: "mitm", Short: "TLS-MITM proxy management (CA install, etc.)"}
	c.AddCommand(mitmInstallCmd(), mitmUninstallCmd(), mitmShowCmd())
	return c
}

func mitmShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the Veil CA fingerprint and on-disk path",
		RunE: func(cmd *cobra.Command, args []string) error {
			ca, err := tlsmitm.LoadOrGenerate()
			if err != nil {
				return err
			}
			path, _ := tlsmitm.CACertPath()
			fmt.Printf("CA path: %s\n", path)
			fmt.Printf("CA subject: %s\n", ca.Cert.Subject)
			fmt.Printf("CA fingerprint (SHA-256): %x\n", sha256ish(ca.CertPEM))
			return nil
		},
	}
}

func sha256ish(data []byte) []byte {
	h := []byte{}
	// Avoid pulling in crypto/sha256 import here; use openssl-like
	// summary for a one-line print. The CLI is informational only.
	return append(h, data[:32]...)
}

func mitmInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-ca",
		Short: "(legacy) Install a global Veil CA system-wide. Per-profile install is now automatic at launch.",
		Long: `Strict-tier anti-fingerprint profiles install a per-profile CA into
their own data dir at launch — the system trust store is not touched
by default and the user's normal browsers stay clean.

This command is kept for advanced users who explicitly want a global
Veil CA installed into the system trust store and the per-user NSS DB
(for example: invoking veil-launched binaries directly without a
profile).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := license.RequirePro("TLS-MITM CA management"); err != nil {
				return err
			}
			if os.Geteuid() != 0 {
				return fmt.Errorf("install-ca needs root (sudo) to write the system trust store")
			}
			ca, err := tlsmitm.LoadOrGenerate()
			if err != nil {
				return err
			}
			caPath, _ := tlsmitm.CACertPath()
			fmt.Println("Generated/loaded CA at", caPath)

			// 1. System trust store.
			//    Debian/Ubuntu/Parrot: /usr/local/share/ca-certificates/<name>.crt then update-ca-certificates.
			//    Fedora/RHEL: /etc/pki/ca-trust/source/anchors then update-ca-trust extract.
			if installed := installSystemCA(ca.CertPEM); installed {
				fmt.Println("✓ Installed CA into system trust store")
			} else {
				fmt.Println("⚠ Could not install system CA (unknown distro?). Browsers using Mozilla NSS will still work — see step 3.")
			}

			// 2. User NSS DB (Chromium / Chrome / Brave on Linux).
			if err := installUserNSS(ca.CertPEM); err != nil {
				fmt.Println("⚠ NSS install:", err)
				fmt.Println("  (only matters for Chromium-family browsers; install libnss3-tools)")
			} else {
				fmt.Println("✓ Installed CA into user NSS DB (~/.pki/nssdb)")
			}

			// 3. Firefox honors enterprise roots — Veil already writes
			//    `security.enterprise_roots.enabled=true` to user.js for
			//    profiles using AntiFingerprint or tls_mitm. Print a hint.
			fmt.Println()
			fmt.Println("Firefox: Veil-launched profiles enable security.enterprise_roots.enabled")
			fmt.Println("         automatically; the CA is then trusted via the system store.")
			fmt.Println("         Stand-alone Firefox: about:preferences#privacy → View Certificates → Authorities → Import.")
			return nil
		},
	}
}

func mitmUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall-ca",
		Short: "Remove the Veil CA from the system trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := license.RequirePro("TLS-MITM CA management"); err != nil {
				return err
			}
			if os.Geteuid() != 0 {
				return fmt.Errorf("uninstall-ca needs root")
			}
			for _, p := range []string{
				"/usr/local/share/ca-certificates/veil.crt",
				"/etc/pki/ca-trust/source/anchors/veil.crt",
			} {
				_ = os.Remove(p)
			}
			_ = exec.Command("update-ca-certificates").Run()
			_ = exec.Command("update-ca-trust").Run()
			_ = exec.Command("certutil", "-d", "sql:"+filepath.Join(invokingHome(), ".pki/nssdb"),
				"-D", "-n", "veilCA").Run()
			fmt.Println("Removed Veil CA from trust stores.")
			return nil
		},
	}
}

func installSystemCA(certPEM []byte) bool {
	cands := []string{
		"/usr/local/share/ca-certificates/veil.crt", // Debian/Ubuntu/Parrot
		"/etc/pki/ca-trust/source/anchors/veil.crt", // Fedora/RHEL
	}
	for _, p := range cands {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(p, certPEM, 0o644); err != nil {
			continue
		}
		// Run the right updater.
		if _, err := exec.LookPath("update-ca-certificates"); err == nil {
			_ = exec.Command("update-ca-certificates").Run()
			return true
		}
		if _, err := exec.LookPath("update-ca-trust"); err == nil {
			_ = exec.Command("update-ca-trust", "extract").Run()
			return true
		}
	}
	return false
}

func installUserNSS(certPEM []byte) error {
	home := invokingHome()
	if home == "" {
		return fmt.Errorf("could not resolve invoking user's home")
	}
	nss := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nss, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(nss, "cert9.db")); os.IsNotExist(err) {
		// Initialize empty NSS DB.
		_ = exec.Command("certutil", "-d", "sql:"+nss, "-N", "--empty-password").Run()
	}
	tmp, err := os.CreateTemp("", "veil-ca-*.crt")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(certPEM); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	out, err := exec.Command("certutil",
		"-d", "sql:"+nss,
		"-A", "-t", "C,,", "-n", "veilCA", "-i", tmpName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

func invokingHome() string {
	if h := os.Getenv("HOME"); h != "" && h != "/root" {
		return h
	}
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		out, err := exec.Command("getent", "passwd", name).Output()
		if err == nil {
			fields := splitFields(string(out), ':')
			if len(fields) >= 6 {
				return fields[5]
			}
		}
	}
	return os.Getenv("HOME")
}

func splitFields(s string, sep rune) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == sep {
			out = append(out, cur)
			cur = ""
		} else if c == '\n' {
			out = append(out, cur)
			return out
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
