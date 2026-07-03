package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/osutil"
)

// SetupCmd: veil setup — interactive system configuration.
func SetupCmd() *cobra.Command {
	var assumeYes bool
	var installGeoIP bool
	var installHelpers bool
	c := &cobra.Command{
		Use:   "setup",
		Short: "Interactive first-run system setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			if installGeoIP {
				return runInstallGeoIP()
			}
			if installHelpers {
				return runInstallHelpers()
			}
			return runSetup(cmd.Context(), assumeYes)
		},
	}
	c.Flags().BoolVarP(&assumeYes, "yes", "y", false, "answer yes to all prompts")
	c.Flags().BoolVar(&installGeoIP, "install-geoip", false, "download DB-IP free GeoIP databases (Country + ASN) into the user config dir; CC-BY-4.0, no signup required")
	c.Flags().BoolVar(&installHelpers, "install-helpers", false, "install veil-bridge with cap_net_admin + udev rule for /dev/net/tun (one-time, requires root) — needed for the user-namespaced engine path")
	return c
}

// UninstallCmd: veil uninstall — clean up all Veil-created system state.
func UninstallCmd() *cobra.Command {
	var purge bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove all Veil system state (firewall rules, sysctl, namespaces)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(purge)
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also delete user config (~/.config/veil)")
	return c
}

func ask(prompt string, def bool) bool {
	suffix := " [y/N]: "
	if def {
		suffix = " [Y/n]: "
	}
	fmt.Print(prompt + suffix)
	rd := bufio.NewReader(os.Stdin)
	ans, _ := rd.ReadString('\n')
	ans = strings.TrimSpace(strings.ToLower(ans))
	if ans == "" {
		return def
	}
	return strings.HasPrefix(ans, "y")
}

func runSetup(ctx context.Context, yes bool) error {
	if runtime.GOOS == "windows" {
		fmt.Println("Veil setup on Windows: ensure you have admin rights.")
		fmt.Println("Veil v1 uses HTTP_PROXY env injection for proxy backends and Wintun for")
		fmt.Println("WireGuard. No system configuration is required for proxy backends.")
		fmt.Println()
		fmt.Println("Run `veil doctor` to verify.")
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("setup must be run as root: sudo veil setup")
	}

	fmt.Println("Veil setup assistant")
	fmt.Println()

	// 1. ip_forward
	if yes || ask("[1/4] Enable net.ipv4.ip_forward (write /etc/sysctl.d/99-veil.conf)?", true) {
		if err := osutil.WriteFileAtomic("/etc/sysctl.d/99-veil.conf",
			[]byte("net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n"), 0o644); err != nil {
			return err
		}
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
		fmt.Println("  ✓ Enabled")
	}

	// 2. firewall preflight (we install rules dynamically per session, but warn about Docker)
	if _, err := exec.LookPath("docker"); err == nil {
		fmt.Println("[2/4] Docker detected — Veil will insert FORWARD rules at top of chain when running.")
	} else {
		fmt.Println("[2/4] Docker not detected — firewall handling is straightforward.")
	}

	// 3. optional binaries
	if yes || ask("[3/4] Suggest optional packages (tor, openvpn, dbus-x11, wireguard-tools)?", true) {
		fmt.Println("  Recommended (Debian/Parrot): sudo apt install tor openvpn dbus-x11 wireguard-tools")
		fmt.Println("  Recommended (Fedora/RHEL):   sudo dnf install tor openvpn dbus-x11 wireguard-tools")
		fmt.Println("  Recommended (Arch):           sudo pacman -S tor openvpn dbus wireguard-tools")
	}

	// 4. sudoers
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user != "" && (yes || ask(fmt.Sprintf("[4/4] Configure passwordless sudo for user %q? (writes /etc/sudoers.d/veil)", user), false)) {
		bin, err := os.Executable()
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s ALL=(root) NOPASSWD: %s\n", user, bin)
		// CRITICAL: sudoers MUST be atomic — partial write =
		// corrupted sudoers = sudo refuses to run = locked out.
		if err := osutil.WriteFileAtomic("/etc/sudoers.d/veil", []byte(line), 0o440); err != nil {
			return err
		}
		fmt.Println("  ✓ Wrote /etc/sudoers.d/veil")
	}

	fmt.Println()
	eng := engine.Active()
	checks, _ := eng.Doctor(ctx)
	for _, c := range checks {
		mark := "✓"
		if !c.OK {
			mark = "✗"
		}
		if c.Warning {
			mark = "⚠"
		}
		fmt.Printf("  %s %s — %s\n", mark, c.Name, c.Detail)
	}
	fmt.Println()
	fmt.Println("Setup complete. Try: veil profile new test --backend direct --preset shell  &&  veil run test")
	return nil
}

// runInstallHelpers installs veil-bridge with cap_net_admin and the
// /dev/net/tun udev rule. Equivalent to what install-desktop.sh does
// during package install, but available as a CLI command for tarball
// installs and CI pipelines. Requires root.
func runInstallHelpers() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("--install-helpers is Linux-only")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("--install-helpers must be run as root: sudo veil setup --install-helpers")
	}

	// 1. Locate veil-bridge — try sibling-of-veil, then a few standard paths.
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	candidates := []string{
		// Same dir as the running veil binary (tarball case).
		strings.TrimSuffix(exe, "/veil") + "/veil-bridge",
		"/usr/local/libexec/veil-bridge",
		"/usr/libexec/veil-bridge",
		"./bin/veil-bridge",
	}
	var src string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			src = c
			break
		}
	}
	if src == "" {
		return fmt.Errorf("veil-bridge binary not found; expected in one of: %v", candidates)
	}

	dst := "/usr/local/libexec/veil-bridge"
	if err := os.MkdirAll("/usr/local/libexec", 0o755); err != nil {
		return err
	}
	// Skip the copy when src and dst already point at the same
	// inode — install(1) errors out in that case ("are the same
	// file"). Just re-apply the cap below; that's idempotent.
	srcAbs, _ := filepath.Abs(src)
	dstAbs, _ := filepath.Abs(dst)
	if srcAbs == dstAbs {
		fmt.Println("✓ veil-bridge already at", dst)
	} else {
		if err := exec.Command("install", "-m", "0755", src, dst).Run(); err != nil {
			return fmt.Errorf("install veil-bridge: %w", err)
		}
		fmt.Println("✓ installed veil-bridge to", dst)
	}

	// 2. setcap.
	if _, err := exec.LookPath("setcap"); err != nil {
		fmt.Println("⚠ setcap not found (apt: libcap2-bin / dnf: libcap)")
		fmt.Println("  veil-bridge is installed but lacks CAP_NET_ADMIN; the user-ns engine path won't work.")
	} else {
		if err := exec.Command("setcap", "cap_net_admin+ep", dst).Run(); err != nil {
			fmt.Println("⚠ setcap failed:", err)
		} else {
			fmt.Println("✓ granted cap_net_admin+ep to", dst)
		}
	}

	// 3. udev rules for /dev/net/tun + /dev/uinput.
	tunRule := "/etc/udev/rules.d/70-veil-tun.rules"
	if err := os.WriteFile(tunRule, []byte(
		"# Veil — unprivileged access to /dev/net/tun for wireguard-go.\n"+
			`KERNEL=="tun", GROUP="veil", MODE="0660"`+"\n"), 0o644); err != nil {
		return fmt.Errorf("write tun udev rule: %w", err)
	}
	fmt.Println("✓ wrote", tunRule)

	uinputRule := "/etc/udev/rules.d/71-veil-uinput.rules"
	if err := os.WriteFile(uinputRule, []byte(
		"# Veil — unprivileged access to /dev/uinput + /dev/input/event*\n"+
			"# for behavioral_jitter / mouse_jitter (EVIOCGRAB needs group-rw).\n"+
			`KERNEL=="uinput", GROUP="veil", MODE="0660"`+"\n"+
			`KERNEL=="event*", SUBSYSTEM=="input", GROUP="veil", MODE="0660"`+"\n"+
			`KERNEL=="mice", SUBSYSTEM=="input", GROUP="veil", MODE="0660"`+"\n"), 0o644); err != nil {
		return fmt.Errorf("write uinput udev rule: %w", err)
	}
	fmt.Println("✓ wrote", uinputRule)

	// 4. veil group + add invoking user.
	if _, err := exec.Command("getent", "group", "veil").CombinedOutput(); err != nil {
		_ = exec.Command("groupadd", "--system", "veil").Run()
		fmt.Println("✓ created group 'veil'")
	}
	if user := os.Getenv("SUDO_USER"); user != "" && user != "root" {
		_ = exec.Command("usermod", "-aG", "veil", user).Run()
		fmt.Printf("✓ added %s to group 'veil' (re-login to pick up)\n", user)
	}

	// 5. /run/netns AND /etc/netns must exist as bind-mount targets
	// for the user-ns engine path. The child can't create them from
	// inside the namespace (host-uid-0 owns the parent dirs).
	//
	// /run is tmpfs — the directory disappears on every reboot —
	// so just mkdir-ing it now isn't enough. Drop a systemd-tmpfiles
	// entry so it's recreated automatically at boot from now on.
	tmpfilesPath := "/etc/tmpfiles.d/veil-netns.conf"
	tmpfilesContent := "# Veil — recreate per-namespace state dirs on every boot.\n" +
		"# /run is tmpfs; without this entry /run/netns vanishes after\n" +
		"# every reboot and the user-ns engine path fails on first\n" +
		"# launch with '/run/netns missing on host'.\n" +
		"d /run/netns 0755 root root -\n" +
		"d /etc/netns 0755 root root -\n"
	if err := os.MkdirAll("/etc/tmpfiles.d", 0o755); err != nil {
		fmt.Println("⚠ couldn't create /etc/tmpfiles.d:", err)
	} else if err := osutil.WriteFileAtomic(tmpfilesPath, []byte(tmpfilesContent), 0o644); err != nil {
		fmt.Println("⚠ couldn't write", tmpfilesPath, ":", err)
	} else {
		fmt.Println("✓ wrote", tmpfilesPath, "(survives reboot)")
		// Apply now so we don't have to mkdir manually below on
		// distros that ship systemd-tmpfiles.
		_ = exec.Command("systemd-tmpfiles", "--create", tmpfilesPath).Run()
	}
	for _, p := range []string{"/run/netns", "/etc/netns"} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			fmt.Println("⚠ couldn't create", p, ":", err)
		} else {
			fmt.Println("✓ ensured", p, "exists")
		}
	}

	// 6. Reload udev.
	_ = exec.Command("udevadm", "control", "--reload-rules").Run()
	_ = exec.Command("udevadm", "trigger", "/dev/net/tun").Run()
	_ = exec.Command("udevadm", "trigger", "/dev/uinput").Run()
	_ = exec.Command("udevadm", "trigger", "--subsystem-match=input").Run()

	fmt.Println()
	fmt.Println("Helpers installed. Verify with:")
	fmt.Println("    " + dst + " doctor")
	return nil
}

func runUninstall(purge bool) error {
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() != 0 {
			return fmt.Errorf("uninstall must be run as root")
		}
		// Delete sysctl
		_ = os.Remove("/etc/sysctl.d/99-veil.conf")
		// Delete sudoers
		_ = os.Remove("/etc/sudoers.d/veil")
		// Delete tmpfiles.d entry that recreated /run/netns at boot
		_ = os.Remove("/etc/tmpfiles.d/veil-netns.conf")
		// Delete any leftover veil-* netns
		out, _ := exec.Command("ip", "netns", "list").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.HasPrefix(fields[0], "veil-") {
				_ = exec.Command("ip", "netns", "del", fields[0]).Run()
				_ = os.RemoveAll("/etc/netns/" + fields[0])
			}
		}
		fmt.Println("Removed Veil system state.")
	case "windows":
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", `name=all`, `program=*Veil*`).Run()
		fmt.Println("Removed Veil firewall rules.")
	}
	if purge {
		cfg, _ := os.UserConfigDir()
		if cfg != "" {
			_ = os.RemoveAll(cfg + "/veil")
			fmt.Println("Removed user config.")
		}
	}
	return nil
}
