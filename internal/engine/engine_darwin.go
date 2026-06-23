//go:build darwin

// macOS engine.
//
// macOS has no equivalent to Linux network namespaces. The honest model
// is: while a profile is "up", the host's primary egress is replaced
// with the profile's tunnel (or HTTP_PROXY env vars for proxy-only
// chains). When the profile goes down, the original default route
// returns. This is the same trade-off Mullvad/Proton VPN clients make
// on macOS.
//
// What this engine does:
//
//   * WireGuard backends: utun via wireguard-go (cross-platform), then
//     adds a system-wide default route through the utun.
//   * OpenVPN backends: openvpn binary, same routing model.
//   * Proxy/Tor backends: HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env injection
//     into the launched app + auto-configured browser prefs (Firefox
//     user.js, Chromium --proxy-server) — same as transparent=off mode
//     on Linux.
//   * Kill switch: pf rules anchored to com.veil that drop everything
//     except traffic via the active utun + lo + the launched app's
//     primary egress (best-effort; pf doesn't have per-PID matching
//     without an Apple-signed Network Extension).
//
// Caveats: no per-app isolation. Whole-host while the profile is active.
// Per-app split tunneling on macOS requires Apple's Network Extension
// framework which needs a signed system extension.

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/launcher"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
)

func active() Engine { return &darwinEngine{} }

type darwinEngine struct {
	mu sync.Mutex
}

type darwinState struct {
	tunDevices   []string
	procHandles  []*os.Process
	addedRoutes  [][]string // each: route delete args we'll run on Down
	pfAnchorName string     // pf anchor to flush on Down
	prevDefault  string     // previous default-route gateway, for restore
}

// CleanupAllOrphans is a no-op on macOS — when veil dies, utun devices
// and pf rules clean up automatically.
func CleanupAllOrphans() {}

// RecoverStale is a no-op on macOS (see CleanupAllOrphans).
func RecoverStale() {}

// ProbeLeaks: not implemented on macOS yet.
func (e *darwinEngine) ProbeLeaks(ctx context.Context, s *Session) []ProbeResult {
	return []ProbeResult{
		{Name: "platform", OK: false, Detail: "leak probes not yet implemented on macOS"},
	}
}

func (e *darwinEngine) Up(ctx context.Context, p *profile.Profile) (*Session, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("veil engine on macOS needs root (sudo)")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := gateLicense(p); err != nil {
		return nil, err
	}
	logger.L().Info("engine.Up (darwin)", "profile", p.Name)

	st := &darwinState{pfAnchorName: "com.veil." + p.Name}
	sess := &Session{Profile: p, State: st}

	rollback := func() {
		for i := len(sess.Backends) - 1; i >= 0; i-- {
			_ = sess.Backends[i].Stop()
		}
		e.cleanup(st)
	}

	var prev *backends.Steering
	for _, b := range p.Chain {
		impl, err := backends.New(b)
		if err != nil {
			rollback()
			return nil, err
		}
		s, err := impl.Start(ctx, prev)
		if err != nil {
			_ = impl.Stop()
			rollback()
			return nil, fmt.Errorf("backend %s: %w", b.Kind, err)
		}
		sess.Backends = append(sess.Backends, impl)
		if s.TUNDevice != "" {
			if err := e.routeViaTUN(st, s); err != nil {
				rollback()
				return nil, fmt.Errorf("attach %s: %w", s.TUNDevice, err)
			}
			st.tunDevices = append(st.tunDevices, s.TUNDevice)
		}
		prev = s
	}
	sess.Final = prev

	if p.KillSwitch && len(st.tunDevices) > 0 {
		if err := e.installPFKillSwitch(st); err != nil {
			logger.L().Warn("pf kill switch failed", "err", err)
		}
	}
	return sess, nil
}

// routeViaTUN sets a system default route via the new TUN. Saves the old
// default for restore on Down.
func (e *darwinEngine) routeViaTUN(st *darwinState, s *backends.Steering) error {
	// Save current default gateway.
	out, _ := exec.Command("route", "-n", "get", "default").Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			st.prevDefault = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	// Add per-tunnel addresses to the utun.
	for _, a := range s.Addresses {
		args := []string{"ifconfig", s.TUNDevice, "inet", a, a, "alias"}
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig: %s: %w", string(out), err)
		}
	}
	if err := exec.Command("ifconfig", s.TUNDevice, "up").Run(); err != nil {
		return err
	}
	// Add default route via TUN.
	if out, err := exec.Command("route", "add", "-net", "default", "-interface", s.TUNDevice).CombinedOutput(); err != nil {
		return fmt.Errorf("route add default: %s: %w", string(out), err)
	}
	st.addedRoutes = append(st.addedRoutes, []string{"-net", "default"})
	return nil
}

// installPFKillSwitch loads a pf anchor that drops outbound traffic on
// any interface other than the tunnel + lo. Best-effort.
func (e *darwinEngine) installPFKillSwitch(st *darwinState) error {
	var rules []string
	rules = append(rules, "block out all")
	rules = append(rules, "pass out on lo0 all")
	for _, t := range st.tunDevices {
		rules = append(rules, "pass out on "+t+" all")
	}
	rulesText := strings.Join(rules, "\n") + "\n"
	cmd := exec.Command("pfctl", "-a", st.pfAnchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(rulesText)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl load: %s: %w", string(out), err)
	}
	if err := exec.Command("pfctl", "-e").Run(); err != nil {
		// pf may already be enabled; ignore
		_ = err
	}
	logger.L().Info("pf kill switch loaded", "anchor", st.pfAnchorName, "tuns", st.tunDevices)
	return nil
}

func (e *darwinEngine) Launch(s *Session) (int, error) {
	st := s.State.(*darwinState)
	binary := s.Profile.App.Binary
	if binary == "" {
		return 0, fmt.Errorf("no app to launch")
	}
	// Browser config for proxy backends (user.js / --proxy-server).
	proxyURL := ""
	if s.Final != nil {
		proxyURL = s.Final.ProxyURL
	}
	_ = launcher.ApplyProxyConfig(s.Profile, proxyURL)

	cmd := exec.Command(binary, s.Profile.App.Args...)
	cmd.Env = buildDarwinEnv(s)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	st.procHandles = append(st.procHandles, cmd.Process)
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}

func buildDarwinEnv(s *Session) []string {
	env := os.Environ()
	if s.Final != nil && s.Final.ProxyURL != "" {
		u, _ := url.Parse(s.Final.ProxyURL)
		urlStr := u.String()
		env = append(env,
			"HTTP_PROXY="+urlStr,
			"HTTPS_PROXY="+urlStr,
			"ALL_PROXY="+urlStr,
			"http_proxy="+urlStr,
			"https_proxy="+urlStr,
			"all_proxy="+urlStr,
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

func (e *darwinEngine) Down(s *Session) error {
	st := s.State.(*darwinState)
	logger.L().Info("engine.Down (darwin)", "profile", s.Profile.Name)
	for i := len(s.Backends) - 1; i >= 0; i-- {
		_ = s.Backends[i].Stop()
	}
	for _, p := range st.procHandles {
		_ = p.Signal(syscall.SIGTERM)
	}
	return e.cleanup(st)
}

func (e *darwinEngine) cleanup(st *darwinState) error {
	// Remove routes we added.
	for _, r := range st.addedRoutes {
		args := append([]string{"delete"}, r...)
		_ = exec.Command("route", args...).Run()
	}
	// Restore previous default gateway, if known.
	if st.prevDefault != "" {
		_ = exec.Command("route", "add", "-net", "default", st.prevDefault).Run()
	}
	// Flush pf anchor.
	if st.pfAnchorName != "" {
		_ = exec.Command("pfctl", "-a", st.pfAnchorName, "-F", "all").Run()
	}
	return nil
}

func (e *darwinEngine) ExternalIP(ctx context.Context, s *Session) (string, error) {
	info, err := e.ExternalIPInfo(ctx, s)
	if err != nil {
		return "", err
	}
	return info.IP, nil
}

// BrowserProbeIP not implemented on darwin yet — falls back to the
// HTTP client variant via ExternalIPInfo. Caller of BrowserProbeIP
// directly will get an error.
func (e *darwinEngine) BrowserProbeIP(ctx context.Context, s *Session, target string) (string, error) {
	return "", fmt.Errorf("BrowserProbeIP: not implemented on darwin")
}

// TorNewCircuit not implemented on darwin yet.
func (e *darwinEngine) TorNewCircuit(s *Session) error {
	return fmt.Errorf("TorNewCircuit: not implemented on darwin")
}

// TorCircuitStatus not implemented on darwin yet.
func (e *darwinEngine) TorCircuitStatus(s *Session) (string, error) {
	return "", fmt.Errorf("TorCircuitStatus: not implemented on darwin")
}

// TorRelayIP not implemented on darwin yet.
func (e *darwinEngine) TorRelayIP(s *Session, fingerprint string) (string, error) {
	return "", fmt.Errorf("TorRelayIP: not implemented on darwin")
}

func (e *darwinEngine) ExternalIPInfo(ctx context.Context, s *Session) (IPInfo, error) {
	c, err := HTTPClientForSteering(s.Final)
	if err != nil {
		return IPInfo{}, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://ipinfo.io/json", nil)
	req.Header.Set("User-Agent", "veil/1.0")
	resp, err := c.Do(req)
	if err != nil {
		return IPInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info IPInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return IPInfo{IP: strings.TrimSpace(string(body))}, nil
	}
	return info, nil
}

func (e *darwinEngine) TrafficStats(s *Session) (TrafficStats, error) {
	st := s.State.(*darwinState)
	if len(st.tunDevices) == 0 {
		return TrafficStats{Iface: "(no tunnel)"}, nil
	}
	t := st.tunDevices[len(st.tunDevices)-1]
	out, err := exec.Command("netstat", "-Ibn", "-I", t).Output()
	if err != nil {
		return TrafficStats{Iface: t}, err
	}
	// netstat -Ibn output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[0] == t {
			rxP := parseUint64(fields[4])
			rxB := parseUint64(fields[6])
			txP := parseUint64(fields[7])
			txB := parseUint64(fields[9])
			return TrafficStats{
				Iface:     t,
				RxPackets: rxP, RxBytes: rxB,
				TxPackets: txP, TxBytes: txB,
			}, nil
		}
	}
	return TrafficStats{Iface: t}, nil
}

func parseUint64(s string) uint64 {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}

func (e *darwinEngine) Doctor(ctx context.Context) ([]Check, error) {
	var out []Check
	check := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail})
	}
	warn := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail, Warning: !ok})
	}
	check("os", runtime.GOOS == "darwin", runtime.GOOS)
	for _, bin := range []string{"route", "ifconfig", "pfctl"} {
		_, err := exec.LookPath(bin)
		check(bin, err == nil, "required system tool")
	}
	for _, bin := range []string{"openvpn", "tor"} {
		_, err := exec.LookPath(bin)
		warn(bin, err == nil, "optional")
	}
	if os.Geteuid() == 0 {
		check("running as root", true, "")
	} else {
		warn("running as root", false, "veil needs sudo for tunnel + pf operations")
	}
	out = append(out, Check{
		Name: "per-app isolation",
		OK:   true,
		Detail: strings.TrimSpace(`
macOS v1: whole-system routing while the profile is active. Per-app split
tunneling on macOS requires an Apple-signed Network Extension.`),
		Warning: true,
	})
	return out, nil
}
