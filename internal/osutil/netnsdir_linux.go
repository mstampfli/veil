package osutil

import (
	"fmt"
	"os"
	"os/exec"
)

// netnsTmpfilesPath is the tmpfiles.d config that recreates
// /run/netns and /etc/netns at boot. /run is a tmpfs and gets
// cleared on every reboot, so without this entry the user-ns
// engine path fails on first launch after every reboot with
// "/run/netns missing on host" until someone runs the install
// helpers again.
const netnsTmpfilesPath = "/etc/tmpfiles.d/veil-netns.conf"

const netnsTmpfilesContent = `# Veil — recreate per-namespace state dirs on every boot.
# /run/netns is required by 'ip netns add'; /etc/netns/<name>/
# is where Veil writes per-namespace resolv.conf so 'ip netns
# exec' can mount-bind it inside the namespace.
d /run/netns 0755 root root -
d /etc/netns 0755 root root -
`

// EnsureNetnsRuntimeDir makes sure /run/netns exists on the host
// before the user-ns engine path tries to bind-mount over it from
// inside the child. /run is tmpfs, so the directory disappears at
// every reboot. This function:
//
//  1. Returns immediately if the dir already exists (the common
//     case, after first launch / install).
//  2. Otherwise tries to install a systemd-tmpfiles.d entry via
//     pkexec — that's a single auth prompt, after which the dir
//     reappears automatically on every subsequent boot.
//  3. Falls back to plain `pkexec mkdir -p /run/netns /etc/netns`
//     when systemd-tmpfiles isn't available; user will be
//     prompted again on next reboot but at least gets unstuck
//     for this session.
//
// Best-effort throughout: any failure here is logged to stderr and
// surfaced later by the engine's own "/run/netns missing" error,
// which is itself actionable. We don't hard-fail GUI startup over
// this because pkexec may be unavailable in some environments
// (CI, headless sessions) where the user runs `veil` directly.
func EnsureNetnsRuntimeDir() {
	if _, err := os.Stat("/run/netns"); err == nil {
		// Already present. Don't reinstall the tmpfiles entry —
		// the install helper does that, and we don't want to
		// pkexec-prompt on every GUI launch.
		return
	}

	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		fmt.Fprintln(os.Stderr,
			"veil: /run/netns missing and pkexec unavailable; "+
				"run: sudo veil setup --install-helpers")
		return
	}

	// Compose a single shell invocation that:
	//   - writes the tmpfiles.d entry (so future boots are fixed),
	//   - applies it now via systemd-tmpfiles --create when present,
	//   - falls back to plain mkdir if systemd-tmpfiles is missing.
	// All steps best-effort; the final mkdir guarantees we're
	// unstuck for this session even if the persistence half fails.
	script := `set -e
mkdir -p /etc/tmpfiles.d
cat > ` + netnsTmpfilesPath + ` <<'EOF'
` + netnsTmpfilesContent + `EOF
chmod 0644 ` + netnsTmpfilesPath + `
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create ` + netnsTmpfilesPath + ` || true
fi
mkdir -p /run/netns /etc/netns
chmod 0755 /run/netns /etc/netns
`
	cmd := exec.Command(pkexec, "sh", "-c", script)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr,
			"veil: pkexec mkdir /run/netns failed:", err,
			"— run: sudo veil setup --install-helpers")
		return
	}
}
