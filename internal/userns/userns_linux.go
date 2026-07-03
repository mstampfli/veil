//go:build linux

package userns

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// CLONE_NEWTIME isn't yet exposed in golang.org/x/sys/unix on all
// versions; declare locally so we're decoupled from upstream
// Cloneflags constants.
const cloneNewtime = 0x00000080

// CLONE_NEWNS — mount namespace. The user-ns child needs its own
// mount-ns so it can mount /run/netns (which `ip netns add` does
// internally) WITHOUT host-side CAP_SYS_ADMIN. Inside our own
// mount-ns we have full mount privilege via the user-ns mapping.
const cloneNewns = 0x00020000

// Detect probes the kernel for what level of user-namespaced
// isolation is achievable on this host. Cheap to call (single
// child fork that exits immediately) — cache the result if you
// need it more than once a launch.
//
// Every level we report assumes mount-ns also (CLONE_NEWNS) — the
// engine inside the child needs a private /run mount to do
// `ip netns add` without host CAP_SYS_ADMIN. CLONE_NEWNS is
// universally supported in user-ns on Linux 3.8+ so this isn't a
// distinguishing axis.
func Detect() SupportLevel {
	if !unprivilegedUserNSAllowed() {
		return SupportNone
	}
	const userNetMount = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | cloneNewns
	if probeNamespaces(userNetMount | cloneNewtime) {
		return SupportFull
	}
	if probeNamespaces(userNetMount) {
		return SupportUserNet
	}
	return SupportNone
}

// unprivilegedUserNSAllowed reads the sysctl that some distros (most
// notably Debian-derived hardened images) set to 0 to forbid users
// from creating user namespaces. When 0 we cannot use this path; the
// engine must fall back to the pkexec-as-root model.
func unprivilegedUserNSAllowed() bool {
	data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err != nil {
		// File not present means the kernel's default policy applies.
		// Mainline Linux defaults to allowed; assume so.
		return true
	}
	return strings.TrimSpace(string(data)) != "0"
}

// probeNamespaces forks a tiny child that calls unshare with the
// requested flags and immediately exits. Success means the kernel
// accepted the combination from an unprivileged caller. The probe
// runs as the current user — no setuid required.
//
// IMPORTANT: we do NOT re-exec /proc/self/exe here. Earlier versions
// did, but that meant the probe child ran the full GUI/CLI startup
// (and on veil-gui specifically, opened a phantom Wails window) before
// it could be told to exit. Using /bin/true (or /usr/bin/true) gives
// us a kernel-side test of the cloneflags via cmd.Start without ever
// exposing the child to any of our own code.
func probeNamespaces(flags int) bool {
	bin := probeBinary()
	if bin == "" {
		return false
	}
	cmd := exec.Command(bin)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(flags),
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	cmd.Env = []string{} // probe child needs no env at all
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return false
	}
	if err := cmd.Wait(); err != nil {
		return false
	}
	return true
}

// probeBinary picks a small, always-installed program for the probe.
// /bin/true and /usr/bin/true both ship in coreutils on every Linux
// distro and exit 0 immediately; either works. Returns "" if neither
// exists (extremely unusual; the host is broken).
func probeBinary() string {
	for _, p := range []string{"/bin/true", "/usr/bin/true"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// HandleProbeAndExit is retained as a compatibility shim for the
// old probe-via-re-exec model. probeNamespaces no longer re-execs
// the host binary, so this is a no-op now. Kept exported so older
// callers don't break — safe to remove in a future cleanup.
func HandleProbeAndExit() bool { return false }

// SpawnConfig describes a child to fork into the namespace stack.
type SpawnConfig struct {
	// Args passed to the child re-exec — argv[0] is conventionally a
	// subcommand the parent binary recognizes (e.g. "engine-internal").
	Args []string

	// Extra env to set on the child in addition to the marker.
	Env []string

	// Stdin/Stdout/Stderr redirection. nil = inherit.
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File

	// IncludeTimeNS asks the kernel for CLONE_NEWTIME. Caller should
	// only set this when Detect() returned SupportFull.
	IncludeTimeNS bool
}

// Spawn re-execs the current binary into the user+net+(maybe-time)
// namespaces with proper uid/gid mapping. Returns the *exec.Cmd so
// the caller can Wait() / Signal() / inspect the child's pid.
//
// The caller is the unprivileged Veil GUI/CLI process. The returned
// child runs as the original user externally, but as uid 0 inside
// the user namespace — which is what gives it CAP_NET_ADMIN to
// configure iptables/NFQUEUE inside its own net-ns.
func Spawn(cfg SpawnConfig) (*exec.Cmd, error) {
	if !unprivilegedUserNSAllowed() {
		return nil, errors.New("kernel.unprivileged_userns_clone=0 (run as root, or enable user namespaces)")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate self: %w", err)
	}

	// Always include CLONE_NEWNS so the child has its own mount
	// namespace — `ip netns add` mounts /run/netns and would
	// otherwise fail with EPERM on the shared host mount-ns.
	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | cloneNewns
	if cfg.IncludeTimeNS {
		flags |= cloneNewtime
	}

	cmd := exec.Command(exe, cfg.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: uintptr(flags),
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		// Pdeathsig: child dies if parent does. Same posture as the
		// rest of Veil's spawned children.
		Pdeathsig: syscall.SIGKILL,
		// Setpgid so the child gets its own process group; matches
		// engine_linux.go's pattern for the browser launch.
		Setpgid: true,
	}
	// Inherit parent's env (so the child has HOME, USER, PATH, etc.
	// — the engine logger writes to $HOME/.config/veil/logs and the
	// existing engine code shells out through PATH). Caller's
	// cfg.Env values win over inherited ones via append-after.
	base := os.Environ()
	cmd.Env = append(append(base, cfg.Env...),
		MarkerEnv+"=1",
		"VEIL_USERNS_LEVEL="+supportLevelString(cfg.IncludeTimeNS),
	)
	// Inherit if the caller didn't specify; nil means "inherit" for
	// exec.Cmd standard streams.
	cmd.Stdin = cfg.Stdin
	cmd.Stdout = cfg.Stdout
	cmd.Stderr = cfg.Stderr
	return cmd, nil
}

func supportLevelString(timeNS bool) string {
	if timeNS {
		return SupportFull.String()
	}
	return SupportUserNet.String()
}

// LevelFromEnv returns the SupportLevel the parent indicated when
// it spawned this child. Useful so the engine inside the namespace
// knows whether to install time-ns features. Returns SupportNone
// outside a userns child.
func LevelFromEnv() SupportLevel {
	switch os.Getenv("VEIL_USERNS_LEVEL") {
	case SupportFull.String():
		return SupportFull
	case SupportUserNet.String():
		return SupportUserNet
	}
	return SupportNone
}

// CurrentPID is a tiny convenience for the engine inside the child
// to report itself to the parent (which then passes the PID to
// veil-bridge for /proc/<pid>/ns/net path resolution).
func CurrentPID() int { return os.Getpid() }

// getenv wraps os.Getenv so the package-level IsChild can be
// shimmed in userns_other.go without dragging in build-tagged
// imports. (Pure os.Getenv is cross-platform but Go's vet doesn't
// know that for a const-using build-tag-split package.)
func getenv(k string) string { return os.Getenv(k) }

// Read the raw integer level if the parent set the legacy form
// "user+net+time" before LevelFromEnv was added.
var _ = strconv.Itoa
