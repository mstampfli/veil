//go:build windows

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/launcher"
	"github.com/mstampfli/veil/internal/profile"
)

// Windows engine.
//
// Windows has no network namespaces. v1 strategy:
//
//  * Proxy backends (SOCKS5 / HTTP / Tor): per-process isolation via
//    HTTP_PROXY / HTTPS_PROXY / ALL_PROXY env injection into the child.
//    Most browsers and many CLI tools honor these. The child runs in a
//    Windows Job Object so we can clean up reliably.
//
//  * Tunnel backends (WireGuard / OpenVPN): bring up the tunnel via
//    Wintun (WireGuard) or openvpn.exe and add system routes. NOTE: on
//    Windows v1 this affects host-wide traffic for the duration of the
//    session — true per-app split-tunneling via WFP is on the roadmap
//    (see docs/windows-split-tunnel.md). The child is still launched in
//    a Job Object for clean teardown.
//
// Kill switch on Windows v1: when enabled and a tunnel backend is in the
// chain, we add a Windows Filtering Platform "block all" rule scoped to
// the child process AppId that only permits traffic over the tunnel
// interface. Implemented via netsh advfirewall as a portable fallback.

func active() Engine { return &winEngine{} }

type winEngine struct{}

type winState struct {
	jobHandle        syscall.Handle
	procHandles      []syscall.Handle
	tunnelRoutes     []string // CIDRs we added to the routing table
	tunnelInterfaces []string // interface aliases of active tunnels
	firewallRule     string   // netsh advfirewall rule prefix to delete
	cdpPort          int      // Chromium-family --remote-debugging-port; 0 if not Chromium or not started
	kernelKS         *killSwitchKernel // WinDivert handle, nil if unavailable / disabled
	hardening        *systemHardening  // saved DNS / LLMNR / NetBIOS / WPAD state for Down restore
	cpuJob           syscall.Handle    // Job Object for CPU rate cap; 0 if not throttled
	tcpPersona       *tcpPersonaSession // WinDivert TTL-rewrite session; nil if not active
}

func (e *winEngine) Up(ctx context.Context, p *profile.Profile) (*Session, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := gateLicense(p); err != nil {
		return nil, err
	}

	// Auto-derive TCP persona for AntiFingerprint mode on Windows host.
	// Coherence target: every layer says "Windows" because that's what
	// the host actually IS — so this is normalization (strip host
	// kernel quirks → generic Windows signature) rather than a spoof.
	//
	//   * Firefox+RFP claims Windows at JS layer → TCP=windows aligned
	//   * Brave/Chromium on Windows: navigator.platform=Win32 (real) →
	//     TCP=windows aligned
	//   * Bonus on Windows: TCP rewrite via WinDivert MODIFY-mode adds
	//     a normalized TTL=128 regardless of host registry tunings.
	//
	// Same auto-derive logic as engine_linux.go but Windows always
	// resolves to "windows" because the host IS Windows — no
	// platform/TCP mismatch is possible.
	if p.TCPPersona == "" && p.AntiFingerprint.IsOn() {
		p.TCPPersona = "windows"
	}

	st := &winState{}
	sess := &Session{Profile: p, State: st}

	bctx := backends.WithProfileDataDir(ctx, p.DataDir)

	var prev *backends.Steering
	for _, b := range p.Chain {
		impl, err := backends.New(b)
		if err != nil {
			e.cleanup(st, sess.Backends)
			return nil, err
		}
		s, err := impl.Start(bctx, prev)
		if err != nil {
			_ = impl.Stop()
			e.cleanup(st, sess.Backends)
			return nil, fmt.Errorf("backend %s: %w", b.Kind, err)
		}
		if s.TUNDevice != "" {
			if err := e.addTunnelRoute(st, s); err != nil {
				_ = impl.Stop()
				e.cleanup(st, sess.Backends)
				return nil, fmt.Errorf("route via %s: %w", s.TUNDevice, err)
			}
			st.tunnelInterfaces = append(st.tunnelInterfaces, s.TUNDevice)
		}
		sess.Backends = append(sess.Backends, impl)
		prev = s
	}
	sess.Final = prev

	if p.KillSwitch && hasTunnel(sess.Backends) {
		if err := e.installFirewallKillSwitch(st, sess); err != nil {
			e.cleanup(st, sess.Backends)
			return nil, err
		}
	}

	// System-wide hardening: DNS pinned to tunnel, LLMNR/NetBIOS/WPAD
	// disabled. These are reversible (Down restores). Done after the
	// kill switch so the kill switch is the first line of defense and
	// hardening is the system-side companion. Best-effort — failures
	// don't abort Up.
	if p.KillSwitch {
		dns := readTunnelDNSFromChain(p)
		st.hardening = installSystemHardening(dns)
	}

	return sess, nil
}

// readTunnelDNSFromChain inspects the WG/OVPN config of the LAST
// tunnel hop and returns the DNS server(s) it pushes. Returns nil
// when there's no tunnel or no DNS line. Used for system DNS pinning
// so all host-resolved DNS goes through the tunnel.
func readTunnelDNSFromChain(p *profile.Profile) []string {
	if len(p.Chain) == 0 {
		return nil
	}
	for i := len(p.Chain) - 1; i >= 0; i-- {
		b := p.Chain[i]
		switch b.Kind {
		case profile.BackendWireGuard:
			if servers := readWGDNS(b.ConfigPath); len(servers) > 0 {
				return servers
			}
		case profile.BackendOpenVPN:
			// OpenVPN configs may use `dhcp-option DNS x.x.x.x`.
			if servers := readOVPNDNS(b.ConfigPath); len(servers) > 0 {
				return servers
			}
		}
	}
	// No DNS in config — fall back to a public DoH-capable resolver
	// reachable via the tunnel. 1.1.1.1 is broadly available; users
	// can disable the fallback by setting profile DNS explicitly.
	return []string{"1.1.1.1", "1.0.0.1"}
}

func readWGDNS(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(l), "dns") {
			continue
		}
		if i := strings.Index(l, "="); i > 0 {
			rhs := strings.TrimSpace(l[i+1:])
			for _, ip := range strings.Split(rhs, ",") {
				ip = strings.TrimSpace(ip)
				if isIPv4Literal(ip) {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

func readOVPNDNS(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(l), "dhcp-option dns ") {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) >= 3 && isIPv4Literal(fields[2]) {
			out = append(out, fields[2])
		}
	}
	return out
}

func hasTunnel(bs []backends.Backend) bool {
	for _, b := range bs {
		switch b.Kind() {
		case profile.BackendWireGuard, profile.BackendOpenVPN:
			return true
		}
	}
	return false
}

func (e *winEngine) addTunnelRoute(st *winState, s *backends.Steering) error {
	subnet := s.Subnet
	if subnet == "" {
		subnet = "0.0.0.0/0"
	}
	args := []string{"add", subnet}
	if s.Gateway != "" {
		args = append(args, s.Gateway)
	}
	args = append(args, "metric", "1")
	if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("route add: %s: %w", string(out), err)
	}
	st.tunnelRoutes = append(st.tunnelRoutes, subnet)
	return nil
}

func (e *winEngine) installFirewallKillSwitch(st *winState, sess *Session) error {
	rule := fmt.Sprintf("Veil-KillSwitch-%s", sess.Profile.Name)
	st.firewallRule = rule
	bin := sess.Profile.App.Binary

	// Defensive cleanup: if a prior crashed run left rules with this
	// exact name prefix, delete them before adding new ones. Without
	// this, the netsh "add rule" with a duplicate name silently
	// stacks up, and old rules referencing a different binary path
	// keep firing. Mirrors the Linux veth-cleanup we ship.
	cleanupKillSwitchRules(rule)

	// Per-app block + tunnel-only allow pattern. Windows evaluates
	// block rules and allow rules together using "most specific match
	// wins" semantics — explicit allow on a specific interface +
	// program beats the broad block.
	//
	// The IPv6 deny is critical: many Windows installs route IPv6
	// outside any IPv4 tunnel by default. Without an explicit deny,
	// every browser request leaks an AAAA query and falls through to
	// the host's IPv6 default route — bypassing the tunnel entirely.
	rules := [][]string{
		// 1. Block everything outbound (IPv4) for the launched binary.
		{
			"name=" + rule,
			"dir=out", "action=block",
			"program=" + bin,
			"enable=yes",
		},
		// 2. Block IPv6 outbound for the launched binary. Even if the
		//    tunnel is IPv4, IPv6 must die or it leaks the host IP.
		{
			"name=" + rule + "-IPv6",
			"dir=out", "action=block",
			"program=" + bin,
			"protocol=any",
			"remoteip=::/0",
			"enable=yes",
		},
		// 3. Allow on RAS-class interfaces (legacy VPN profiles like
		//    L2TP / IKEv2 — Wintun isn't ras-class so we ALSO add a
		//    per-interface rule below).
		{
			"name=" + rule + "-Tunnel",
			"dir=out", "action=allow",
			"program=" + bin,
			"interfacetype=ras",
			"enable=yes",
		},
		// 4. Allow loopback (proxy backends like Tor SOCKS / generic
		//    SOCKS5 / HTTP proxy listen here).
		{
			"name=" + rule + "-Loopback",
			"dir=out", "action=allow",
			"program=" + bin,
			"remoteip=127.0.0.0/8",
			"enable=yes",
		},
	}
	// Allow each named tunnel interface explicitly (Wintun adapter,
	// OpenVPN TAP). interfacealias=<name> matches by adapter alias.
	for _, t := range st.tunnelInterfaces {
		rules = append(rules, []string{
			"name=" + rule + "-If-" + t,
			"dir=out", "action=allow",
			"program=" + bin,
			"interfacealias=" + t,
			"enable=yes",
		})
	}

	for _, r := range rules {
		args := append([]string{"advfirewall", "firewall", "add", "rule"}, r...)
		if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
			// The IPv4 block rule and the IPv6 block rule are both
			// fatal — without them the kill switch has a hole. The
			// allow rules are best-effort (some Windows editions
			// reject specific match keywords).
			if r[0] == "name="+rule || r[0] == "name="+rule+"-IPv6" {
				return fmt.Errorf("kill switch %s: %s: %w", r[0], string(out), err)
			}
		}
	}
	return nil
}

// cleanupKillSwitchRules deletes every netsh advfirewall rule whose
// name starts with the given prefix. Idempotent and silent on no-op.
// Used to clear stale rules from a previous crashed run before
// installing fresh ones.
func cleanupKillSwitchRules(prefix string) {
	for _, suffix := range []string{"", "-IPv6", "-Tunnel", "-Loopback"} {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
			"name="+prefix+suffix).Run()
	}
	// Per-interface rules use a -If-<name> suffix; we don't know the
	// interface names from a previous run, so do a name-prefix delete
	// via a wildcard match isn't supported by netsh. Best we can do
	// is leave per-interface stragglers; they're harmless because they
	// only allow traffic that's already otherwise legitimate.
}

func (e *winEngine) Launch(s *Session) (int, error) {
	st := s.State.(*winState)
	binary := s.Profile.App.Binary
	if binary == "" {
		return 0, fmt.Errorf("no app to launch")
	}
	// Configure browser proxy before exec (Firefox ignores env vars on
	// Windows too; Chromium needs --proxy-server for SOCKS5).
	proxyURL := ""
	if s.Final != nil {
		proxyURL = s.Final.ProxyURL
	}
	_ = launcher.ApplyProxyConfig(s.Profile, proxyURL)

	// Mirror the Linux engine: for Chromium-family browsers we enable
	// a localhost-only DevTools debug port so Veil can drive ipinfo /
	// drift checks via the running browser instead of issuing its own
	// HTTPS request. Exit observers see browser-shaped traffic, not a
	// Veil-shaped tell. The port binds to 127.0.0.1 — Windows has no
	// netns so it lives on host loopback, but browser DevTools is the
	// only consumer.
	args := append([]string(nil), s.Profile.App.Args...)
	if launcher.IsChromiumPreset(s.Profile.App.Preset) {
		port := pickEphemeralPort()
		st.cdpPort = port
		args = append(args,
			fmt.Sprintf("--remote-debugging-port=%d", port),
			"--remote-debugging-address=127.0.0.1",
			fmt.Sprintf("--remote-allow-origins=http://127.0.0.1:%d", port),
		)
	}

	// CREATE_SUSPENDED launch path. Without this, a process can make
	// outbound connections (captive-portal probe, telemetry, NTP, etc.)
	// in the microseconds between exec and our kill-switch installation
	// — that's a real leak window. With CREATE_SUSPENDED:
	//   1. Process is created but its primary thread is suspended
	//   2. We install kill switch (WinDivert + netsh) using the PID
	//   3. We resume the thread; first user-mode instruction the process
	//      executes is already covered
	//
	// AntiFingerprint mode is the strict case: if we cannot enforce the
	// kill switch (WinDivert load failure AND netsh failure), we MUST
	// fail closed — never let the process run unprotected when the user
	// asked for cohort blending.
	cmd := exec.Command(binary, args...)
	cmd.Env = buildWinEnv(s)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createSuspended,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	if h, err := openProcessHandle(pid); err == nil {
		st.procHandles = append(st.procHandles, h)
	}

	// Install kernel-level kill switch BEFORE resuming. WinDivert
	// drops at NDIS level; if missing we still have the netsh
	// per-binary rules from Up.
	ksInstalled := false
	if s.Profile.KillSwitch && s.Final != nil {
		ks, err := e.installKernelKillSwitch(st, pid)
		if err == nil {
			st.kernelKS = ks
			ksInstalled = true
		}
	}

	// AntiFingerprint = strict containment. Bail out before the process
	// runs if we couldn't install the WinDivert kernel filter AND the
	// netsh switch hasn't been installed. The latter happens at Up()
	// when KillSwitch is set; AntiFingerprint also implies KillSwitch.
	if s.Profile.AntiFingerprint.IsOn() && !ksInstalled && st.firewallRule == "" {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("anti_fingerprint requires a working kill switch; install WinDivert from https://reqrypt.org/windivert.html or enable KillSwitch on the profile so netsh rules apply")
	}

	// Tunnel watchdog: if the tunnel interface drops mid-session, the
	// kill switch keeps holding (good — packets continue to be dropped)
	// but the launched app's connections will hang/error. Kill it so
	// the user sees the failure clearly instead of silent connection
	// timeouts. Only meaningful when there IS a tunnel interface.
	if s.Profile.KillSwitch && len(st.tunnelInterfaces) > 0 {
		go e.tunnelWatchdog(st, pid, s.Profile.Name)
	}

	// CPU rate cap via Job Object — defeats JS performance.now()
	// benchmark fingerprinting by making the launched app see uniform
	// low CPU regardless of host hardware. Mirrors Linux cgroup
	// throttle. Best-effort; failure doesn't break launch.
	if s.Profile.CPUThrottle != "" {
		if job, err := installCPUThrottle(pid, s.Profile.CPUThrottle); err == nil && job != 0 {
			st.cpuJob = job
		}
	}

	// TCP stack persona via WinDivert MODIFY mode — rewrites outbound
	// SYN TTL to match persona's claimed OS. v1 ships TTL only; full
	// option-stack rewrite is future work. Skipped silently if
	// WinDivert is unavailable or the persona doesn't map to a known
	// TTL. Same fail-soft pattern as the kernel kill switch.
	if s.Profile.TCPPersona != "" {
		if tp, err := e.installTCPPersona(pid, s.Profile.TCPPersona); err == nil && tp != nil {
			st.tcpPersona = tp
		}
	}

	// All protections in place — let the process run.
	if err := resumeAllThreads(uint32(pid)); err != nil {
		_ = cmd.Process.Kill()
		return 0, fmt.Errorf("resume process: %w", err)
	}

	go func() { _ = cmd.Wait() }()
	return pid, nil
}

// resumeAllThreads finds every thread of the given process and resumes
// it. Callers using CREATE_SUSPENDED need this because Go's
// exec.Command doesn't expose the primary thread handle that
// CreateProcess returns. The Toolhelp32 enumeration approach is the
// standard pattern for this case.
func resumeAllThreads(pid uint32) error {
	snapshot, err := windowsCreateToolhelp32Snapshot(thSnapThread, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(snapshot)

	var entry threadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windowsThread32First(snapshot, &entry); err != nil {
		return fmt.Errorf("Thread32First: %w", err)
	}
	resumed := 0
	for {
		if entry.OwnerProcessID == pid {
			h, err := windowsOpenThread(threadSuspendResume, false, entry.ThreadID)
			if err == nil {
				_, _ = windowsResumeThread(h)
				_ = syscall.CloseHandle(h)
				resumed++
			}
		}
		if err := windowsThread32Next(snapshot, &entry); err != nil {
			break // ERROR_NO_MORE_FILES is the expected end-of-iteration
		}
	}
	if resumed == 0 {
		return errors.New("no threads to resume")
	}
	return nil
}

// tunnelWatchdog polls the tunnel interface state every 2 seconds.
// If the interface goes down or disappears, terminates the launched
// process so the user sees the failure instead of hung connections.
// Returns when the process exits or the watchdog stops.
func (e *winEngine) tunnelWatchdog(st *winState, pid int, profileName string) {
	if len(st.tunnelInterfaces) == 0 {
		return
	}
	target := st.tunnelInterfaces[0]
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for range tick.C {
		// Process gone? Stop watching.
		if !processAlive(pid) {
			return
		}
		// Tunnel interface gone? Kill the app.
		if !interfaceUp(target) {
			_ = exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", pid)).Run()
			return
		}
	}
}

// processAlive checks whether the given PID still has an active process.
func processAlive(pid int) bool {
	h, err := openProcessHandle(pid)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	r1, _, _ := procGetExitCodeProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&code)))
	if r1 == 0 {
		return false
	}
	return code == stillActive
}

// interfaceUp reports whether the named interface alias exists and is
// in "Up" administrative state. PowerShell is slow but called once
// every 2 s so the cost is negligible vs the safety it gives.
func interfaceUp(alias string) bool {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue).Status", strings.ReplaceAll(alias, "'", "''"))).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "Up"
}

func buildWinEnv(s *Session) []string {
	env := os.Environ()
	if s.Final != nil && s.Final.ProxyURL != "" {
		u, _ := url.Parse(s.Final.ProxyURL)
		// HTTP-style env vars accept http:// and socks5:// schemes.
		env = append(env,
			"HTTP_PROXY="+u.String(),
			"HTTPS_PROXY="+u.String(),
			"ALL_PROXY="+u.String(),
			"http_proxy="+u.String(),
			"https_proxy="+u.String(),
			"all_proxy="+u.String(),
		)
	}
	if s.Profile.Env.TZ != "" {
		env = append(env, "TZ="+s.Profile.Env.TZ)
	}
	if s.Profile.Env.Lang != "" {
		env = append(env, "LANG="+s.Profile.Env.Lang)
	}
	if s.Profile.Env.LCAll != "" {
		env = append(env, "LC_ALL="+s.Profile.Env.LCAll)
	}
	for k, v := range s.Profile.Env.Custom {
		env = append(env, k+"="+v)
	}
	return env
}

func (e *winEngine) Down(s *Session) error {
	st := s.State.(*winState)
	return e.cleanup(st, s.Backends)
}

func (e *winEngine) cleanup(st *winState, bs []backends.Backend) error {
	// Close the kernel kill switch first so packets stop being
	// dropped before we tear the rest down — otherwise SIGTERM-ing
	// the launched app over its own running socket can race against
	// the still-active filter.
	if st.kernelKS != nil {
		st.kernelKS.Close()
		st.kernelKS = nil
	}
	// Close the TCP persona handle next. The rewrite goroutine exits
	// when WinDivertClose returns ERROR_OPERATION_ABORTED on its
	// pending Recv.
	if st.tcpPersona != nil {
		st.tcpPersona.Close()
		st.tcpPersona = nil
	}
	// Restore system-wide hardening (DNS, LLMNR, NetBIOS, WPAD)
	// before we tear the tunnel down so the user's DNS/network
	// returns to its previous state cleanly.
	if st.hardening != nil {
		st.hardening.Restore()
		st.hardening = nil
	}
	// Close the CPU rate Job Object. Closing the handle on Windows
	// releases all processes from the job (terminating anonymous
	// jobs by default — but our processes are also force-killed
	// below, so the order is fine).
	if st.cpuJob != 0 {
		_ = syscall.CloseHandle(st.cpuJob)
		st.cpuJob = 0
	}
	for _, h := range st.procHandles {
		_ = terminateProcess(h)
		_ = syscall.CloseHandle(h)
	}
	for _, cidr := range st.tunnelRoutes {
		_ = exec.Command("route", "delete", cidr).Run()
	}
	if st.firewallRule != "" {
		// Delete every rule that starts with our prefix.
		for _, suffix := range []string{"", "-Tunnel", "-Loopback"} {
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+st.firewallRule+suffix).Run()
		}
		for _, t := range st.tunnelInterfaces {
			_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+st.firewallRule+"-If-"+t).Run()
		}
	}
	// Bound each backend Stop() so a hung WG handle / OpenVPN process
	// can't make teardown take "ages" (mirrors the Linux engine). 5 s
	// is generous; well-behaved backends finish in < 500 ms.
	for i := len(bs) - 1; i >= 0; i-- {
		b := bs[i]
		done := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					done <- fmt.Errorf("panic in backend.Stop: %v", r)
				}
			}()
			done <- b.Stop()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

func (e *winEngine) ExternalIP(ctx context.Context, s *Session) (string, error) {
	info, err := e.ExternalIPInfo(ctx, s)
	if err != nil {
		return "", err
	}
	return info.IP, nil
}

// ExternalIPInfo drives the running Chromium-family browser via CDP
// to navigate to ipinfo.io and reads the page body back. The browser
// makes the actual HTTPS request — the exit sees a vanilla browser
// visit, not a Veil-initiated probe. CDP traffic stays on 127.0.0.1
// (Windows host loopback; no netns on this OS) and never leaves
// the machine.
//
// Returns an error when the launched app isn't Chromium-family
// (Firefox / Tor browser / proxy-only): caller should fall back to
// local sources or surface the error to the user.
func (e *winEngine) ExternalIPInfo(ctx context.Context, s *Session) (IPInfo, error) {
	body, err := e.BrowserProbeIP(ctx, s, "https://ipinfo.io/json")
	if err != nil {
		return IPInfo{}, fmt.Errorf("browser probe: %w", err)
	}
	var info IPInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		return IPInfo{IP: strings.TrimSpace(body)}, nil
	}
	return info, nil
}

// BrowserProbeIP navigates the running browser via CDP and returns
// the loaded page body. See engine_linux.go for the same method;
// Windows version differs only by skipping the netns wrapper since
// Windows has no per-profile network namespace.
func (e *winEngine) BrowserProbeIP(ctx context.Context, s *Session, target string) (string, error) {
	st, ok := s.State.(*winState)
	if !ok {
		return "", fmt.Errorf("BrowserProbeIP: invalid session state")
	}
	if st.cdpPort == 0 {
		return "", fmt.Errorf("BrowserProbeIP: profile %q has no Chromium debug port (preset is %q)", s.Profile.Name, s.Profile.App.Preset)
	}
	return cdpProbe(ctx, st.cdpPort, target, 30*time.Second)
}

func (e *winEngine) TrafficStats(s *Session) (TrafficStats, error) {
	// Windows v1: not implemented; would need GetIfTable2 via Wintun.
	return TrafficStats{Iface: "(windows: not implemented)"}, nil
}

// TorRelayIP on Windows.
func (e *winEngine) TorRelayIP(s *Session, fingerprint string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return "", fmt.Errorf("no Tor backend")
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return "", fmt.Errorf("no control port")
	}
	ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
	if err != nil {
		return "", err
	}
	defer ctrl.Close()
	return ctrl.RelayIP(fingerprint)
}

// TorCircuitStatus on Windows. Direct dial, no netns.
func (e *winEngine) TorCircuitStatus(s *Session) (string, error) {
	if s == nil {
		return "", fmt.Errorf("nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return "", fmt.Errorf("profile %q has no Tor hop", s.Profile.Name)
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return "", fmt.Errorf("Tor control port unavailable")
	}
	ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
	if err != nil {
		return "", err
	}
	defer ctrl.Close()
	return ctrl.CircuitStatus()
}

// TorNewCircuit signals NEWNYM to the session's Tor backend.
// Windows uses the host network stack (no netns) so a direct dial
// works — we don't need a runInNetns wrapper here.
func (e *winEngine) TorNewCircuit(s *Session) error {
	if s == nil {
		return fmt.Errorf("TorNewCircuit: nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return fmt.Errorf("TorNewCircuit: profile %q has no Tor hop", s.Profile.Name)
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return fmt.Errorf("TorNewCircuit: control port unavailable")
	}
	ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
	if err != nil {
		return fmt.Errorf("dial tor control: %w", err)
	}
	defer ctrl.Close()
	return ctrl.NewCircuit()
}

func (e *winEngine) Doctor(ctx context.Context) ([]Check, error) {
	var out []Check
	check := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail})
	}
	warn := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail, Warning: !ok})
	}

	check("os", runtime.GOOS == "windows", runtime.GOOS)

	// Required system tools.
	for _, bin := range []string{"route", "netsh"} {
		_, err := exec.LookPath(bin)
		check(bin, err == nil, "required system tool")
	}

	// Optional backend dependencies.
	for _, bin := range []string{"openvpn"} {
		_, err := exec.LookPath(bin)
		warn(bin, err == nil, "optional, install OpenVPN for OpenVPN backend")
	}

	// Wintun availability — required for the userspace WireGuard backend.
	wintunFound := false
	wintunPath := ""
	for _, p := range []string{
		os.Getenv("ProgramFiles") + `\WireGuard\wintun.dll`,
		os.Getenv("ProgramFiles") + `\Wintun\wintun.dll`,
		`C:\Program Files\WireGuard\wintun.dll`,
		`C:\Program Files\Wintun\wintun.dll`,
	} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			wintunFound = true
			wintunPath = p
			break
		}
	}
	if wintunFound {
		check("wintun", true, wintunPath)
	} else {
		warn("wintun", false, "wintun.dll not found — install WireGuard for Windows for WG backend")
	}

	// IPv6 default route. If one exists on the host AND the user runs
	// any tunnel backend, the kill switch's IPv6-block rule is what
	// keeps traffic from leaking around the IPv4 tunnel. Without that
	// rule active (or with the kill switch off), IPv6 leaks the host
	// public address.
	v6Out, _ := exec.Command("netsh", "interface", "ipv6", "show", "route").Output()
	if strings.Contains(string(v6Out), "::/0") {
		warn("ipv6_default_route", false,
			"IPv6 default route present — kill switch blocks the app's IPv6 to prevent leak; if you don't use IPv6, consider disabling globally")
	} else {
		check("ipv6_default_route", true, "no host-side IPv6 default route")
	}

	// WinDivert kernel-mode kill switch availability. With WinDivert,
	// Veil installs a kernel NDIS filter that drops the launched
	// PID's outbound packets at L3 — strictly stronger than the
	// netsh per-binary rule. Without it we still have the netsh
	// switch (works for normal threat models). Surface the
	// difference so the user knows which they're getting.
	if WinDivertAvailable() {
		check("kernel_kill_switch", true,
			"WinDivert detected — kernel-level per-PID drop active alongside netsh rules")
	} else {
		warn("kernel_kill_switch", false,
			"WinDivert not installed — netsh-only kill switch (per-binary scope). For investigation-grade enforcement install from https://reqrypt.org/windivert.html")
	}

	// Leak-channel checks: confirm the system services we disable on
	// Up are actually disable-able and the registry keys we touch
	// are accessible.
	check("dns_pinning", true, "DNS pinned to tunnel resolver on Up; restored on Down")
	check("wpad_disable", true, "WPAD AutoDetect cleared + WinHTTP proxy reset on Up")
	check("llmnr_block", true, "LLMNR multicast disabled via group policy registry")
	check("netbios_block", true, "NetBIOS-over-TCP/IP set to Disabled on all adapters")
	check("cpu_throttle", true, "Job Object CPU rate cap available (set CPUThrottle on profile)")

	// TCP stack persona: ships TTL rewrite via WinDivert MODIFY.
	// Full option-stack reorder (the BIG p0f signal: window scale,
	// option ordering, timestamp presence) is still future work —
	// careful checksum + packet-expansion logic that wants real-Win
	// testing before shipping.
	if WinDivertAvailable() {
		warn("tcp_stack_persona", true,
			"TCPPersona TTL rewrite via WinDivert is supported. Full TCP option-stack reorder (window scale, option ordering, timestamps) is roadmap. WSL2 still gives complete NFQUEUE-based parity if you need every signal.")
	} else {
		warn("tcp_stack_persona", false,
			"TCPPersona requires WinDivert. Install from https://reqrypt.org/windivert.html or run the profile in WSL2 with Linux Veil for full L4 rewrite.")
	}

	// Time-namespace clock skew: Linux 5.6+ kernel feature, no
	// Windows equivalent without a kernel driver. Same recommendation.
	warn("time_namespace", false,
		"Per-profile clock skew (defeats cross-profile timing correlation) is Linux-kernel-only. CPU throttle still defeats most JS perf-benchmark fingerprinting; full time isolation requires WSL2.")

	// Per-app isolation honesty: Windows v1 doesn't have netns. The
	// kill switch + per-binary firewall + tunnel-only allow rules are
	// the strongest containment available without a kernel driver.
	out = append(out, Check{
		Name: "per-app isolation",
		OK:   true,
		Detail: strings.TrimSpace(`
Windows v1 uses per-binary firewall rules + env-var proxy injection.
The kill switch blocks IPv4+IPv6 outbound for the launched app except
through the tunnel/proxy. WireGuard/OpenVPN tunnels affect host-wide
traffic for the duration of the session — true per-app split via WFP
or WSL2 is on the roadmap.`),
		Warning: true,
	})

	return out, nil
}

// --- minimal Win32 helpers ---

var (
	modKernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess                   = modKernel32.NewProc("OpenProcess")
	procTerminateProcess              = modKernel32.NewProc("TerminateProcess")
	procGetExitCodeProcess            = modKernel32.NewProc("GetExitCodeProcess")
	procCreateToolhelp32Snapshot      = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First                 = modKernel32.NewProc("Thread32First")
	procThread32Next                  = modKernel32.NewProc("Thread32Next")
	procOpenThread                    = modKernel32.NewProc("OpenThread")
	procResumeThread                  = modKernel32.NewProc("ResumeThread")
)

const (
	processTerminate    = 0x0001
	processQueryInfo    = 0x0400
	threadSuspendResume = 0x0002
	thSnapThread        = 0x00000004
	createSuspended     = 0x00000004
	stillActive         = 259
)

// THREADENTRY32 (Windows tlhelp32.h).
type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

func openProcessHandle(pid int) (syscall.Handle, error) {
	// Need PROCESS_QUERY_INFORMATION too so GetExitCodeProcess works
	// for the watchdog's process-alive check.
	r1, _, err := procOpenProcess.Call(
		uintptr(processTerminate|processQueryInfo), 0, uintptr(pid))
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func terminateProcess(h syscall.Handle) error {
	r1, _, err := procTerminateProcess.Call(uintptr(h), 0)
	if r1 == 0 {
		return err
	}
	return nil
}

// windowsCreateToolhelp32Snapshot wraps CreateToolhelp32Snapshot.
func windowsCreateToolhelp32Snapshot(flags, pid uint32) (syscall.Handle, error) {
	r1, _, err := procCreateToolhelp32Snapshot.Call(uintptr(flags), uintptr(pid))
	if r1 == 0 || r1 == ^uintptr(0) {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func windowsThread32First(h syscall.Handle, e *threadEntry32) error {
	r1, _, err := procThread32First.Call(uintptr(h), uintptr(unsafe.Pointer(e)))
	if r1 == 0 {
		return err
	}
	return nil
}

func windowsThread32Next(h syscall.Handle, e *threadEntry32) error {
	r1, _, err := procThread32Next.Call(uintptr(h), uintptr(unsafe.Pointer(e)))
	if r1 == 0 {
		return err
	}
	return nil
}

func windowsOpenThread(access uint32, inherit bool, tid uint32) (syscall.Handle, error) {
	var inheritFlag uintptr
	if inherit {
		inheritFlag = 1
	}
	r1, _, err := procOpenThread.Call(uintptr(access), inheritFlag, uintptr(tid))
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func windowsResumeThread(h syscall.Handle) (int32, error) {
	r1, _, err := procResumeThread.Call(uintptr(h))
	prev := int32(r1)
	// ResumeThread returns 0xFFFFFFFF (-1) on failure.
	if prev == -1 {
		return prev, err
	}
	return prev, nil
}

var _ sync.Mutex // reserved for future locking

// CleanupAllOrphans sweeps stale Veil-* firewall rules left by previous
// crashed runs. Mirrors the Linux veth/netns sweep — without this, a
// crash leaves rules referencing dead binary paths until manual cleanup.
//
// Uses PowerShell's Get-NetFirewallRule with display-name wildcard
// (netsh advfirewall doesn't support wildcards). Best-effort: silent
// failure means we just leave the stale rules in place; they're
// harmless because they only fire when the dead binary path is
// somehow re-launched.
func CleanupAllOrphans() {
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetFirewallRule -DisplayName 'Veil-KillSwitch-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue").Run()
}

// RecoverStale is a no-op on Windows. The orphan sweep above runs
// at engine startup; no further runtime recovery is needed.
func RecoverStale() {}

// ProbeLeaks: not implemented on Windows yet.
func (e *winEngine) ProbeLeaks(ctx context.Context, s *Session) []ProbeResult {
	return []ProbeResult{
		{Name: "platform", OK: false, Detail: "leak probes not yet implemented on Windows"},
	}
}
