//go:build linux

package engine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mstampfli/veil/internal/logger"
)

// pasta (passt) provides the user-ns engine's netns uplink WITHOUT any
// host capability. Where the legacy path needs a privileged veil-bridge
// helper (cap_net_admin) to create a host veth pair + MASQUERADE, pasta
// runs fully unprivileged: it joins the child's user+net namespace (which
// the engine already owns), configures a synthetic interface inside it,
// and forwards that traffic to the host network over ordinary sockets.
//
// When pasta is available we prefer it — that's the zero-capability path.
// veil-bridge remains the fallback for hosts without pasta.

// pastaIface is the deterministic name of the uplink interface pasta
// creates inside the profile netns. The kill switch and the tor
// source-IP exemption key off this name.
const pastaIface = "veil0"

// PastaPathEnv overrides which pasta binary the engine runs. Mirrors
// VEIL_BRIDGE. See resolvePasta for the full resolution order.
const PastaPathEnv = "VEIL_PASTA"

// managedPastaPath is where install.sh puts the veil-built pasta. Distro passt
// packages vary too much to rely on — too old on Debian 12, and Arch's build
// fails the unprivileged user-ns attach even at a current version — so veil
// builds a known-good pasta here and prefers it for consistent behavior on
// every distro. (Outside /usr/bin it also dodges the distro's path-scoped passt
// AppArmor profile.)
const managedPastaPath = "/usr/local/libexec/veil/pasta"

// resolvePasta picks the pasta binary and reports whether one is available.
// Order: $VEIL_PASTA, the veil-managed build, then "pasta" on PATH.
func resolvePasta() (string, bool) {
	if p := os.Getenv(PastaPathEnv); p != "" {
		_, err := os.Stat(p)
		return p, err == nil
	}
	if _, err := os.Stat(managedPastaPath); err == nil {
		return managedPastaPath, true
	}
	if p, err := exec.LookPath("pasta"); err == nil {
		return p, true
	}
	return "pasta", false
}

// pastaBinary returns the pasta executable to run.
func pastaBinary() string { p, _ := resolvePasta(); return p }

// pastaAvailable reports whether a usable pasta binary is present.
func pastaAvailable() bool { _, ok := resolvePasta(); return ok }

// pastaHelp caches `pasta --help` output so flag probing is cheap and done
// once per process. Older passt (e.g. Debian 12's 0.0~git20230309) lacks
// flags like --map-host-loopback; passing an unknown flag makes pasta exit
// immediately, which would silently break the uplink. We feature-detect
// instead of assuming a version.
var (
	pastaHelpOnce sync.Once
	pastaHelpText string
)

func pastaSupportsFlag(flag string) bool {
	pastaHelpOnce.Do(func() {
		// pasta --help exits non-zero but still prints the option list.
		out, _ := exec.Command(pastaBinary(), "--help").CombinedOutput()
		pastaHelpText = string(out)
	})
	return strings.Contains(pastaHelpText, flag)
}

// startPasta launches pasta attached to the existing network namespace of
// childPID and configures interface pastaIface inside it with the
// synthetic address nsIP and a default route via gwIP. pasta then NATs
// that interface's traffic out to the host network using unprivileged
// sockets.
//
// It runs unprivileged (no caps): pasta setns()es into the child's
// user+net namespace, which the caller created and therefore owns.
//
// pasta IS the datapath, so it must stay alive for the whole session —
// it runs in foreground (-f) as a tracked child process and is killed by
// stopPasta on teardown.
//
// DNS: we pass no --dns-forward (pasta's default is "don't forward"), so
// pasta never proxies the netns's DNS to the host resolver. veil's
// per-netns resolv.conf (written after this, pointing at the in-netns
// chain resolver) and the transparent :53 REDIRECT own DNS regardless —
// any DNS advert pasta writes into the netns resolv.conf is overwritten
// before the launched app runs.
func startPasta(childPID int, nsIP, gwIP string, mtu int) (*exec.Cmd, error) {
	if childPID <= 0 {
		return nil, fmt.Errorf("startPasta: invalid child pid %d", childPID)
	}
	args := []string{
		"-f",           // foreground: we own the lifetime
		"-q",           // no informational banner on stderr
		"--config-net", // configure the namespace interface ourselves
		"-a", nsIP,     // synthetic address (NOT the host's real IP)
		"-g", gwIP, // gateway
		"-I", pastaIface,
	}
	// Map the host's loopback to the gateway address so a profile pointing at
	// a host-loopback proxy (e.g. ssh -D) is reachable. Newer passt needs the
	// explicit flag; older passt (Debian 12) lacks it but maps host loopback
	// to the gateway BY DEFAULT, giving the same result — so only pass the
	// flag when supported, otherwise we'd hit an "unknown option" instant exit.
	if pastaSupportsFlag("--map-host-loopback") {
		args = append(args, "--map-host-loopback", gwIP)
	}
	if mtu > 0 {
		args = append(args, "-m", strconv.Itoa(mtu))
	}
	args = append(args, strconv.Itoa(childPID))

	// pasta is the datapath and must stay alive (-f). If it instead exits
	// almost immediately it rejected its arguments or could not attach; we
	// capture stderr and surface that — with an actionable hint — rather than
	// waiting ~15s for the child's uplink-readiness poll to fail opaquely.
	cmd := exec.Command(pastaBinary(), args...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start pasta uplink: %w", err)
	}
	died := make(chan error, 1)
	go func() { died <- cmd.Wait() }()
	select {
	case werr := <-died:
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" {
			msg = werr.Error()
		}
		return nil, fmt.Errorf("pasta exited immediately: %s%s", msg, pastaFailureHint(msg))
	case <-time.After(400 * time.Millisecond):
		// Still alive — the normal case. The caller owns teardown; the died
		// goroutine reaps when stopPasta kills the process.
		logger.L().Info("pasta uplink started (no host caps)",
			"child_pid", childPID, "iface", pastaIface,
			"ns_ip", nsIP, "gateway", gwIP, "pasta_pid", cmd.Process.Pid)
		return cmd, nil
	}
}

// pastaFailureHint appends remediation guidance for known pasta startup
// failures. The common one on Debian/Ubuntu is an AppArmor profile that
// confines pasta but lacks the `ptrace (read)` rule it needs to attach to the
// engine's user-ns child — pasta reports it as "Couldn't open ... namespace:
// Permission denied". `install.sh` patches this automatically; this hint
// covers source/manual installs that skipped it.
func pastaFailureHint(msg string) string {
	if strings.Contains(msg, "Permission denied") &&
		(strings.Contains(msg, "namespace") || strings.Contains(msg, "ns/")) {
		return " — pasta is likely blocked by its AppArmor profile; add" +
			" 'ptrace (read) peer=unconfined,' to /etc/apparmor.d/usr.bin.passt" +
			" (or re-run veil's install.sh) and reload it"
	}
	return ""
}


// stopPasta terminates a session's pasta uplink. Idempotent. We only signal
// the process: the reaper goroutine started in startPasta is the sole owner of
// cmd.Wait() (calling Wait twice is an error), and Kill unblocks it so it
// reaps. Killing an already-dead process is a harmless ignored error.
func stopPasta(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
