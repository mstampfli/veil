//go:build linux

package engine

// usernsEngine is the parent-side engine implementation that runs
// each profile session in its own unprivileged user-namespaced
// child process. The child holds the actual Linux engine state —
// netns, iptables, NFQUEUE, backend goroutines — and the parent
// invokes Engine methods on it via JSON-line RPC over a socketpair.
//
// Privilege model:
//   - parent (veil-gui): runs as the invoking user, no caps
//   - veil-bridge (cap_net_admin+ep): only invoked by parent, only
//     for veth + host-side NAT operations
//   - child (user-ns + net-ns + maybe time-ns): fake root inside
//     the namespaces, runs the existing linuxEngine code unchanged
//
// Selected by Active() when VEIL_USERNS_ENGINE=1 is set in the
// environment AND userns + bridge are both available. Otherwise the
// existing linuxEngine path is used (no behavior change for default
// installs while this is iterated on).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mstampfli/veil/internal/bridge"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
	"github.com/mstampfli/veil/internal/userns"
)

// usernsEngine implements Engine. One instance per process; sessions
// are tracked by profile name so per-method dispatch can find the
// right child socket.
type usernsEngine struct {
	mu       sync.Mutex
	sessions map[string]*usernsSession // keyed by profile.Name

	// reqID is a monotonic counter for RPC message IDs.
	reqID atomic.Uint64
}

// usernsSession is the parent-side handle for one running profile.
// It owns the child process + the IPC socket.
type usernsSession struct {
	profile *profile.Profile

	cmd    *exec.Cmd // the user-ns child
	sock   *os.File  // parent end of socketpair (reads/writes JSON frames)
	reader *bufio.Reader

	// pastaCmd is the pasta uplink process when on the zero-capability
	// path; nil when falling back to the privileged veil-bridge. It IS
	// the netns datapath, so it lives for the whole session and is killed
	// on teardown.
	pastaCmd *exec.Cmd

	// SubnetCIDR / hostCIDR / nsCIDR identify the parent↔child
	// link. Only used so Down can ask veil-bridge to drop the same
	// devices it created.
	subnetCIDR string
	hostCIDR   string
	nsCIDR     string
	wanIface   string

	mu sync.Mutex // serializes RPC calls on this session
}

// newUsernsEngine constructs a parent-side engine that uses the
// user-ns child path. Caller is expected to have already verified
// userns.Detect() != SupportNone and bridge.Doctor() returns OK;
// otherwise spawns will fail at Up time with a clear error.
func newUsernsEngine() *usernsEngine {
	return &usernsEngine{sessions: make(map[string]*usernsSession)}
}

// ----------------------------- Engine interface -----------------------------

func (e *usernsEngine) Up(ctx context.Context, p *profile.Profile) (*Session, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := gateLicense(p); err != nil {
		return nil, err
	}

	// Uplink mode. Prefer pasta (passt): it gives the child netns internet
	// over unprivileged sockets with NO host capability. Fall back to the
	// privileged veil-bridge (veth + host NAT, needs cap_net_admin) only
	// when pasta isn't installed.
	usePasta := pastaAvailable()
	if !usePasta {
		// Bridge fallback: probe the privileged helper up front, and
		// pre-clean any leftover veth from a prior SIGKILL'd session for
		// THIS profile name (RemoveVeth is idempotent + privilege-elevated
		// so it can `ip link delete` even though our parent has no caps;
		// without it a relaunch hits "File exists" on the veth name).
		if _, err := bridge.Doctor(); err != nil {
			return nil, fmt.Errorf("user-ns engine: pasta not found and veil-bridge unusable: %w", err)
		}
		_ = bridge.RemoveVeth(p.Name)
	}

	// 2. Allocate a /30 subnet for the parent↔child veth link.
	//    We use 10.250.<hash[0]>.<hash[1]>/30 derived from the
	//    profile name — deterministic, conflict-free for sane
	//    profile name distributions, easy to reason about.
	subnet := allocUsernsSubnet(p.Name)
	hostIP, nsIP := subnetEndpoints(subnet)
	hostCIDR := fmt.Sprintf("%s/30", hostIP.String())
	nsCIDR := fmt.Sprintf("%s/30", nsIP.String())

	// 3. Spawn the user-ns child with a socketpair for RPC. Pass
	//    the child's end as fd 3 (cmd.ExtraFiles[0]) — that's the
	//    convention.
	pair, err := socketpairCloexec()
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	parentEnd, childEnd := pair[0], pair[1]

	level := userns.Detect()
	cmd, err := userns.Spawn(userns.SpawnConfig{
		Args:          []string{"engine-helper"},
		IncludeTimeNS: level == userns.SupportFull,
		Stderr:        os.Stderr,
	})
	if err != nil {
		parentEnd.Close()
		childEnd.Close()
		return nil, fmt.Errorf("userns.Spawn: %w", err)
	}
	cmd.ExtraFiles = []*os.File{childEnd}
	if err := cmd.Start(); err != nil {
		parentEnd.Close()
		childEnd.Close()
		return nil, fmt.Errorf("start child: %w", err)
	}
	// Parent doesn't need childEnd anymore once Start() forked it
	// over. Close locally.
	childEnd.Close()

	sess := &usernsSession{
		profile:    p,
		cmd:        cmd,
		sock:       parentEnd,
		reader:     bufio.NewReader(parentEnd),
		subnetCIDR: subnet.String(),
		hostCIDR:   hostCIDR,
		nsCIDR:     nsCIDR,
	}

	// 4. Give the child netns an uplink to the host network.
	cfg := configureNetworkParams{NSAddress: nsCIDR, HostGateway: hostIP.String()}
	if usePasta {
		// Zero-capability path: pasta attaches to the child's netns by
		// PID and NATs it to the host over unprivileged sockets — no veth,
		// no host iptables, no cap_net_admin. It must stay alive for the
		// whole session (it is the datapath).
		pcmd, err := startPasta(cmd.Process.Pid, nsIP.String(), hostIP.String(), 1500)
		if err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("pasta uplink: %w", err)
		}
		sess.pastaCmd = pcmd
		cfg.Pasta = true
		cfg.PeerDevice = pastaIface
	} else {
		// Legacy fallback: privileged veil-bridge veth + host NAT.
		wan, err := defaultWANInterface()
		if err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("default wan: %w", err)
		}
		sess.wanIface = wan
		if _, err := bridge.CreateVeth(bridge.CreateVethSpec{
			Profile:  p.Name,
			HostCIDR: hostCIDR,
			NSCIDR:   nsCIDR,
			NSPID:    cmd.Process.Pid,
		}); err != nil {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("bridge create-veth: %w", err)
		}
		if err := bridge.AddNAT(subnet.String(), wan); err != nil {
			_ = bridge.RemoveVeth(p.Name)
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("bridge add-nat: %w", err)
		}
		_, peerDev := bridgeVethNames(p.Name)
		cfg.PeerDevice = peerDev
	}

	// 5. Configure the child's uplink before bringing up the profile.
	//    pasta path: the child waits for veil0 to come up (pasta
	//    configures it asynchronously). bridge path: the child addresses
	//    the veth peer + adds the default route via the host gateway.
	if _, err := sess.callJSON(ctx, mConfigureNetwork, cfg); err != nil {
		e.cleanupFailedUp(sess)
		return nil, fmt.Errorf("configure-network: %w", err)
	}

	// 6. Up the profile inside the child.
	if _, err := sess.callJSON(ctx, mUp, upParams{Profile: p}); err != nil {
		e.cleanupFailedUp(sess)
		return nil, fmt.Errorf("child Up: %w", err)
	}

	e.mu.Lock()
	e.sessions[p.Name] = sess
	e.mu.Unlock()

	logger.L().Info("userns engine: profile up",
		"profile", p.Name, "child_pid", cmd.Process.Pid,
		"subnet", subnet.String(), "level", level.String())

	return &Session{
		Profile: p,
		State:   sess, // opaque; methods look it up by Profile.Name
	}, nil
}

func (e *usernsEngine) Launch(s *Session) (int, error) {
	sess := e.lookup(s)
	if sess == nil {
		return 0, errors.New("usernsEngine.Launch: unknown session")
	}
	out, err := sess.callJSON(context.Background(), mLaunch, nil)
	if err != nil {
		return 0, err
	}
	var pid int
	if err := json.Unmarshal(out, &pid); err != nil {
		return 0, fmt.Errorf("Launch: parse pid: %w", err)
	}
	return pid, nil
}

func (e *usernsEngine) Down(s *Session) error {
	sess := e.lookup(s)
	if sess == nil {
		return errors.New("usernsEngine.Down: unknown session")
	}

	// Best-effort: ask the child to do its own teardown first.
	// 6s budget — backend stops are already parallel + 3s-capped per
	// backend internally (engine_linux Down), so 6s here is enough
	// for the worst real case (3s backend stop + 800ms browser kill
	// grace + a bit of cleanup). Anything longer and the user
	// perceives the stop as hanging.
	stopStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if _, err := sess.callJSON(ctx, mDown, nil); err != nil {
		logger.L().Warn("userns engine: child Down failed",
			"profile", sess.profile.Name, "err", err)
	}
	// Then ask child to exit. If that hangs, kill it.
	_, _ = sess.callJSON(ctx, mShutdown, nil)
	_ = sess.sock.Close()

	done := make(chan error, 1)
	go func() { done <- sess.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
		logger.L().Warn("userns engine: child didn't exit cleanly; killing",
			"profile", sess.profile.Name)
		_ = sess.cmd.Process.Kill()
		<-done
	}

	// Safety-net kill for orphan browser processes belonging to this
	// profile. The pdeathsig chain breaks at the bash wrapper:
	//   helper → ip-netns-exec/bash → brave
	// Pdeathsig=SIGKILL is set on the helper's immediate child (bash),
	// so when the helper dies, bash gets SIGKILL — but SIGKILL does
	// NOT propagate down the process group; brave (the bash subprocess)
	// just reparents to init and keeps running, holding the data_dir
	// SingletonLock and consuming RAM.
	//
	// This kicks in when child Down times out (RPC deadline exceeded —
	// chain teardown ran into a slow iptables / hung backend Stop) and
	// the helper gets force-killed before its in-band SIGTERM-the-pgroup
	// could fire. Walk /proc, match cmdlines that have
	// `--user-data-dir=<this profile's brave data dir>`, kill them.
	if sess.profile.DataDir != "" {
		killed := killOrphanBrowsersForDataDir(sess.profile.DataDir)
		if killed > 0 {
			logger.L().Warn("userns engine: reaped orphan browser procs after Down",
				"profile", sess.profile.Name, "killed", killed)
		}
	}

	logger.L().Info("userns engine: down complete",
		"profile", sess.profile.Name, "took", time.Since(stopStart))

	// Tear down the uplink. pasta path: kill the pasta process (its tap
	// dies with the child netns anyway, but be explicit). Bridge path:
	// drop the host NAT + veth.
	if sess.pastaCmd != nil {
		stopPasta(sess.pastaCmd)
	} else {
		if err := bridge.RemoveNAT(sess.subnetCIDR, sess.wanIface); err != nil {
			logger.L().Warn("userns engine: remove-nat failed", "err", err)
		}
		if err := bridge.RemoveVeth(sess.profile.Name); err != nil {
			logger.L().Warn("userns engine: remove-veth failed", "err", err)
		}
	}

	e.mu.Lock()
	delete(e.sessions, sess.profile.Name)
	e.mu.Unlock()
	return nil
}

func (e *usernsEngine) ExternalIP(ctx context.Context, s *Session) (string, error) {
	sess := e.lookup(s)
	if sess == nil {
		return "", errors.New("usernsEngine.ExternalIP: unknown session")
	}
	out, err := sess.callJSON(ctx, mExternalIP, nil)
	if err != nil {
		return "", err
	}
	var ip string
	if err := json.Unmarshal(out, &ip); err != nil {
		return "", err
	}
	return ip, nil
}

func (e *usernsEngine) ExternalIPInfo(ctx context.Context, s *Session) (IPInfo, error) {
	sess := e.lookup(s)
	if sess == nil {
		return IPInfo{}, errors.New("usernsEngine.ExternalIPInfo: unknown session")
	}
	out, err := sess.callJSON(ctx, mExternalIPInfo, nil)
	if err != nil {
		return IPInfo{}, err
	}
	var info IPInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return IPInfo{}, err
	}
	return info, nil
}

func (e *usernsEngine) BrowserProbeIP(ctx context.Context, s *Session, target string) (string, error) {
	sess := e.lookup(s)
	if sess == nil {
		return "", errors.New("usernsEngine.BrowserProbeIP: unknown session")
	}
	out, err := sess.callJSON(ctx, mBrowserProbeIP, target)
	if err != nil {
		return "", err
	}
	var body string
	if err := json.Unmarshal(out, &body); err != nil {
		return "", err
	}
	return body, nil
}

func (e *usernsEngine) TorNewCircuit(s *Session) error {
	sess := e.lookup(s)
	if sess == nil {
		return errors.New("usernsEngine.TorNewCircuit: unknown session")
	}
	_, err := sess.callJSON(context.Background(), mTorNewCircuit, nil)
	return err
}

func (e *usernsEngine) TorCircuitStatus(s *Session) (string, error) {
	sess := e.lookup(s)
	if sess == nil {
		return "", errors.New("usernsEngine.TorCircuitStatus: unknown session")
	}
	out, err := sess.callJSON(context.Background(), mTorCircuitStatus, nil)
	if err != nil {
		return "", err
	}
	var s2 string
	if err := json.Unmarshal(out, &s2); err != nil {
		return "", err
	}
	return s2, nil
}

func (e *usernsEngine) TorRelayIP(s *Session, fingerprint string) (string, error) {
	sess := e.lookup(s)
	if sess == nil {
		return "", errors.New("usernsEngine.TorRelayIP: unknown session")
	}
	out, err := sess.callJSON(context.Background(), mTorRelayIP, fingerprint)
	if err != nil {
		return "", err
	}
	var ip string
	if err := json.Unmarshal(out, &ip); err != nil {
		return "", err
	}
	return ip, nil
}

func (e *usernsEngine) TrafficStats(s *Session) (TrafficStats, error) {
	sess := e.lookup(s)
	if sess == nil {
		return TrafficStats{}, errors.New("usernsEngine.TrafficStats: unknown session")
	}
	out, err := sess.callJSON(context.Background(), mTrafficStats, nil)
	if err != nil {
		return TrafficStats{}, err
	}
	var ts TrafficStats
	if err := json.Unmarshal(out, &ts); err != nil {
		return TrafficStats{}, err
	}
	return ts, nil
}

func (e *usernsEngine) ProbeLeaks(ctx context.Context, s *Session) []ProbeResult {
	sess := e.lookup(s)
	if sess == nil {
		return []ProbeResult{{Name: "session", OK: false, Detail: "unknown session"}}
	}
	out, err := sess.callJSON(ctx, mProbeLeaks, nil)
	if err != nil {
		return []ProbeResult{{Name: "rpc", OK: false, Detail: err.Error()}}
	}
	var results []ProbeResult
	if err := json.Unmarshal(out, &results); err != nil {
		return []ProbeResult{{Name: "decode", OK: false, Detail: err.Error()}}
	}
	return results
}

// Doctor runs in the parent — it's a host-level check that doesn't
// need namespace context. We delegate to the legacy linuxEngine
// since its checks (sysctl, iptables presence, conntrack module,
// etc.) are exactly the right things to test on the host.
func (e *usernsEngine) Doctor(ctx context.Context) ([]Check, error) {
	host := active() // platform-default engine; on Linux it's *linuxEngine
	checks, err := host.Doctor(ctx)
	if err != nil {
		return checks, err
	}
	// The delegated root-engine Doctor emits "running as root — veil must
	// run with sudo for namespace ops" whenever euid != 0. That is correct
	// for the LEGACY root engine, but we ARE the user-ns engine (active and
	// selected), which is DESIGNED to run non-root. So that warning is
	// false here and directly contradicts the user-ns-path check below
	// (which says non-root works). Drop it and report the real privilege
	// model so `veil doctor` never pushes a non-root user toward sudo.
	var kept []Check
	for _, c := range checks {
		if c.Name == "running as root" {
			continue
		}
		kept = append(kept, c)
	}
	checks = kept
	checks = append(checks, Check{
		Name:   "privilege mode",
		OK:     true,
		Detail: "non-root via user namespaces (no sudo needed)",
	})
	// Uplink mode. pasta is the zero-capability path — it needs nothing
	// privileged. The veil-bridge fallback needs cap_net_admin on the
	// helper binary. Report which one is in effect so the user knows
	// whether any capability is required at all.
	if pastaAvailable() {
		checks = append(checks, Check{
			Name:   "netns uplink",
			OK:     true,
			Detail: "pasta (userspace) — no host capability required",
		})
	} else {
		checks = append(checks, Check{
			Name:   "netns uplink",
			OK:     true,
			Detail: "veil-bridge (cap_net_admin) — install passt for the zero-capability path",
		})
	}
	// Add our own check so users see whether the user-ns path is alive.
	// Only probe the privileged bridge when pasta is absent: on a zero-cap
	// install the bridge is deliberately capless, so `veil-bridge doctor`
	// returns nothing and reporting its parse error here is noise.
	bridgeDetail := "not needed (pasta uplink)"
	if !pastaAvailable() {
		bridgeDetail = bridgeStatus()
	}
	checks = append(checks, Check{
		Name: "userns engine path",
		OK:   userns.Detect() != userns.SupportNone,
		Detail: fmt.Sprintf("userns=%s; bridge=%s",
			userns.Detect().String(), bridgeDetail),
	})
	return checks, nil
}

// ----------------------------- helpers -----------------------------

func (e *usernsEngine) lookup(s *Session) *usernsSession {
	if s == nil || s.Profile == nil {
		return nil
	}
	if sess, ok := s.State.(*usernsSession); ok {
		return sess
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions[s.Profile.Name]
}

func (e *usernsEngine) cleanupFailedUp(sess *usernsSession) {
	if sess.pastaCmd != nil {
		stopPasta(sess.pastaCmd)
	} else {
		_ = bridge.RemoveNAT(sess.subnetCIDR, sess.wanIface)
		_ = bridge.RemoveVeth(sess.profile.Name)
	}
	_ = sess.sock.Close()
	if sess.cmd != nil && sess.cmd.Process != nil {
		_ = sess.cmd.Process.Kill()
		_, _ = sess.cmd.Process.Wait()
	}
}

// callJSON sends one RPC request and waits for its reply. Holds the
// session's mu for the duration so we don't interleave frames.
func (s *usernsSession) callJSON(ctx context.Context, method string, params any) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uint64(time.Now().UnixNano())
	var paramsRaw json.RawMessage
	if params != nil {
		var err error
		paramsRaw, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}

	if err := writeFrame(s.sock, rpcRequest{ID: id, Method: method, Params: paramsRaw}); err != nil {
		// EPIPE here means the child died before our write landed.
		// The child writes one final error frame to the socket
		// before exiting (e.g. setupNetnsDir: "/run/netns missing
		// on host"), but the kernel returns EPIPE to us first, so
		// we never read it. Try one short readFrame to drain that
		// last frame and surface the real cause; otherwise the user
		// sees a generic "broken pipe" with no actionable hint.
		// errors.Is(EPIPE) catches the syscall-wrapped form; the
		// substring fallback catches "broken pipe" inside a fmt.Errorf
		// that didn't preserve the syscall errno (some net.OpError
		// paths drop it).
		msg := err.Error()
		brokenPipe := errors.Is(err, syscall.EPIPE) ||
			strings.Contains(msg, "broken pipe") ||
			strings.Contains(msg, "EPIPE")
		if brokenPipe {
			_ = s.sock.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			defer s.sock.SetReadDeadline(time.Time{})
			var resp rpcResponse
			if rerr := readFrame(s.reader, &resp); rerr == nil && resp.Error != "" {
				return nil, fmt.Errorf("child setup failed: %s", resp.Error)
			}
		}
		return nil, fmt.Errorf("write %s: %w", method, err)
	}

	// Honor ctx deadline by reading in a goroutine.
	type readResult struct {
		resp rpcResponse
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		var resp rpcResponse
		err := readFrame(s.reader, &resp)
		ch <- readResult{resp, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("read %s: %w", method, r.err)
		}
		if r.resp.Error != "" {
			return nil, errors.New(r.resp.Error)
		}
		return r.resp.Result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ----------------------------- subnet allocation -----------------------------

// allocUsernsSubnet picks a deterministic /30 in 10.250.0.0/16 for
// the parent↔child veth link of a given profile name. Same hash as
// veil-bridge's vethNames so the parent can predict device names.
//
// 10.250 is chosen to avoid the existing engine's allocations
// (which are in 10.13.0.0/16) so legacy + user-ns engines can
// theoretically run side-by-side without subnet collisions.
func allocUsernsSubnet(profileName string) *net.IPNet {
	h := fnv.New32()
	_, _ = h.Write([]byte(profileName))
	v := h.Sum32() % (1 << 14) // 16384 unique /30s in 10.250.0.0/16
	a := byte((v >> 6) & 0xff)
	b := byte((v << 2) & 0xfc)
	return &net.IPNet{
		IP:   net.IPv4(10, 250, a, b),
		Mask: net.CIDRMask(30, 32),
	}
}

// subnetEndpoints returns the .1 (host) and .2 (ns) addresses in a /30.
func subnetEndpoints(n *net.IPNet) (host, ns net.IP) {
	ip4 := n.IP.To4()
	host = net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+1)
	ns = net.IPv4(ip4[0], ip4[1], ip4[2], ip4[3]+2)
	return
}

// bridgeVethNames mirrors the helper's hash so the parent can give
// the child the right device name before exec'ing veil-bridge —
// avoids a roundtrip just to learn the name.
func bridgeVethNames(profile string) (host, peer string) {
	h := fnv.New32()
	_, _ = h.Write([]byte(profile))
	hash := h.Sum32() % 0xffff
	return fmt.Sprintf("veil-%x0", hash),
		fmt.Sprintf("veil-%x1", hash)
}

func bridgeStatus() string {
	if _, err := bridge.Doctor(); err != nil {
		return "unavailable: " + err.Error()
	}
	return "ok"
}

// killOrphanBrowsersForDataDir walks /proc and SIGKILLs every process
// whose cmdline carries `--user-data-dir=<dataDir>` or
// `--user-data-dir=<dataDir>/<anything>`. Used as a safety net after
// the userns child is force-killed (Pdeathsig only takes the bash
// wrapper, not the brave subprocess underneath it). Returns the
// number of PIDs signalled.
//
// We don't try graceful SIGTERM here — by the time we reach this code
// path the child Down has already either succeeded (in which case
// nothing is left to kill, this is a no-op) or failed with a hung
// teardown (in which case waiting another 800 ms for SIGTERM to take
// effect just stretches the user-visible "stop" hang further). Hard
// kill, then move on.
func killOrphanBrowsersForDataDir(dataDir string) int {
	dataDir = strings.TrimRight(dataDir, "/")
	if dataDir == "" {
		return 0
	}
	matchExact := "--user-data-dir=" + dataDir
	matchPrefix := matchExact + "/"

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	killed := 0
	for _, p := range procs {
		if !p.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		cmdlineBytes, err := os.ReadFile("/proc/" + p.Name() + "/cmdline")
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline is NUL-separated argv.
		args := strings.Split(string(cmdlineBytes), "\x00")
		hit := false
		for _, a := range args {
			if a == matchExact || strings.HasPrefix(a, matchPrefix) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		pid, _ := strconv.Atoi(p.Name())
		if pid <= 1 {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err == nil {
			killed++
		}
	}
	if killed > 0 {
		// Brief settle so the kernel reaps before any subsequent code
		// in Down touches the data dir or netns ref-count.
		time.Sleep(200 * time.Millisecond)
	}
	return killed
}

// socketpairCloexec returns a pair of connected SOCK_STREAM sockets
// with FD_CLOEXEC set. Used as the parent↔child IPC channel.
func socketpairCloexec() ([2]*os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return [2]*os.File{}, err
	}
	return [2]*os.File{
		os.NewFile(uintptr(fds[0]), "veil-rpc-parent"),
		os.NewFile(uintptr(fds[1]), "veil-rpc-child"),
	}, nil
}
