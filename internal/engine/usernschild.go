// Package engine — child entrypoint for the user-ns isolation model.
//
// When veil-gui (or veil) is started with VEIL_USERNS_CHILD=1 it has
// been re-execed by its own parent into a CLONE_NEWUSER + CLONE_NEWNET
// + (where supported) CLONE_NEWTIME stack. The child becomes the
// privileged inside-the-namespace engine; the parent stays
// unprivileged on the host and proxies the bits the namespace can't
// reach (host-side veth + NAT, which veil-bridge handles).
//
// The child runs an RPC loop on fd 3 (the parent passed it via
// cmd.ExtraFiles). Requests are JSON-line frames; replies the same.
// Inside the child we hold one in-process linuxEngine + at most one
// Session (one profile per child).

package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/userns"
	"github.com/vishvananda/netlink"
)

// runtimeStack is a thin wrapper so we don't have to import "runtime"
// twice (the var _ at file bottom already pulls it in). Returns the
// number of bytes written into buf.
func runtimeStack(buf []byte) int { return runtime.Stack(buf, false) }

// MaybeRunUsernsChild checks whether the current process is the
// re-exec'd child described above. If so, it runs the engine helper
// loop and never returns. Otherwise it returns immediately and the
// normal GUI/CLI flow continues.
//
// Call this FIRST in main(), before the Wails runtime starts — the
// Wails initialization would otherwise try to bring up the X/Wayland
// connection which we don't want in a child process.
func MaybeRunUsernsChild() {
	if !userns.IsChild() {
		return
	}
	runChild()
	// Belt-and-suspenders: never let the child fall through into the
	// parent's main() flow even if runChild returned early on an
	// unexpected error. The child has no business running Wails,
	// the CLI, or any of the other top-level paths.
	os.Exit(0)
}

func runChild() {
	logger.Init()
	logger.L().Info("userns child: starting",
		"pid", os.Getpid(), "level", userns.LevelFromEnv().String())

	// Make /run/netns + /etc/netns writable inside our private
	// mount-ns. Both are needed by `ip netns add` / `ip netns exec`
	// / writeResolvConf and would otherwise fail with EPERM because
	// host-uid-0 owns the parent dirs and is unmapped in our
	// user-ns.
	//
	// HARD FAIL: if the bind mounts can't be set up, the child has
	// no usable netns layout and the parent's Up RPC would fail
	// with a confusing "ip netns add" error. Surface the real
	// reason here as the FIRST RPC reply so the user sees a clear
	// "fix /run/netns" message rather than the downstream symptom.
	if err := setupNetnsDir(); err != nil {
		// Send the error back to the parent over the RPC socket
		// before exiting. We aren't in dispatch yet so we craft a
		// minimal frame manually — the parent's Up call will be
		// the first to see it.
		if sock := os.NewFile(3, "veil-rpc"); sock != nil {
			_ = writeFrame(sock, rpcResponse{
				ID:    0,
				Error: fmt.Sprintf("userns child: netns dir setup failed: %v", err),
			})
			sock.Close()
		}
		fmt.Fprintln(os.Stderr, "veil: userns child setup failed:", err)
		os.Exit(2)
	}

	// Parent passed the RPC socket as fd 3 via cmd.ExtraFiles. We
	// detect "fd 3 isn't actually a socket" by stat-ing it; running
	// the binary with VEIL_USERNS_CHILD=1 outside the proper spawn
	// context shouldn't try to do any RPC.
	if _, err := os.Stat("/proc/self/fd/3"); err != nil {
		emitError("rpc fd 3 not present; child must be spawned by usernsEngine")
		os.Exit(2)
	}
	sock := os.NewFile(3, "veil-rpc")
	defer sock.Close()

	reader := bufio.NewReader(sock)
	host := active().(Engine) // platform engine; Linux returns *linuxEngine
	state := childState{host: host}

	for {
		var req rpcRequest
		if err := readFrame(reader, &req); err != nil {
			logger.L().Info("userns child: parent closed RPC; exiting", "err", err)
			return
		}
		resp := state.dispatchSafely(&req)
		if err := writeFrame(sock, resp); err != nil {
			logger.L().Warn("userns child: write reply failed", "err", err)
			return
		}
		if req.Method == mShutdown {
			return
		}
	}
}

type childState struct {
	host    Engine
	session *Session // at most one — one profile per child
}

// dispatchSafely wraps dispatch with a panic recovery so the child
// reports a runtime error to the parent instead of silently dying
// (which presents to the parent as `read $METHOD: EOF` and is hell
// to diagnose). Stack trace gets logged to stderr too.
func (st *childState) dispatchSafely(req *rpcRequest) (resp rpcResponse) {
	defer func() {
		if r := recover(); r != nil {
			stack := make([]byte, 8192)
			n := runtimeStack(stack)
			logger.L().Warn("userns child: panic in dispatch",
				"method", req.Method,
				"panic", fmt.Sprintf("%v", r),
				"stack", string(stack[:n]))
			resp = rpcError(req.ID,
				fmt.Errorf("child panic in %s: %v", req.Method, r))
		}
	}()
	return st.dispatch(req)
}

func (st *childState) dispatch(req *rpcRequest) rpcResponse {
	switch req.Method {
	case mConfigureNetwork:
		return st.handleConfigureNetwork(req)
	case mUp:
		return st.handleUp(req)
	case mLaunch:
		return st.handleLaunch(req)
	case mDown:
		return st.handleDown(req)
	case mExternalIP:
		return st.handleExternalIP(req)
	case mExternalIPInfo:
		return st.handleExternalIPInfo(req)
	case mTrafficStats:
		return st.handleTrafficStats(req)
	case mProbeLeaks:
		return st.handleProbeLeaks(req)
	case mBrowserProbeIP:
		return st.handleBrowserProbeIP(req)
	case mTorNewCircuit:
		return st.handleTorNewCircuit(req)
	case mTorControlInfo:
		return st.handleTorControlInfo(req)
	case mTorCircuitStatus:
		return st.handleTorCircuitStatus(req)
	case mTorRelayIP:
		return st.handleTorRelayIP(req)
	case mShutdown:
		// Best-effort teardown; main loop exits after responding.
		if st.session != nil {
			_ = st.host.Down(st.session)
			st.session = nil
		}
		return rpcOK(req.ID, nil)
	default:
		return rpcError(req.ID, fmt.Errorf("unknown method %q", req.Method))
	}
}

func (st *childState) handleConfigureNetwork(req *rpcRequest) rpcResponse {
	var p configureNetworkParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return rpcError(req.ID, fmt.Errorf("ConfigureNetwork: %w", err))
	}
	if err := configureChildNetwork(p); err != nil {
		return rpcError(req.ID, err)
	}
	// Pasta uplink: record the address at which the host's loopback is
	// reachable from the profile netns (pasta's gateway), so the in-child
	// linuxEngine can hand it to backends that rewrite "localhost" (socks5
	// / http) when Up runs next. Bridge path leaves it empty.
	if p.Pasta {
		if le, ok := st.host.(*linuxEngine); ok {
			le.pastaHostLoopback = p.HostGateway
		}
	}
	return rpcOK(req.ID, nil)
}

func (st *childState) handleUp(req *rpcRequest) rpcResponse {
	var p upParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return rpcError(req.ID, fmt.Errorf("Up: %w", err))
	}
	if p.Profile == nil {
		return rpcError(req.ID, fmt.Errorf("Up: nil profile"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	cancel() // dummy; real timeout enforced by parent
	_ = ctx
	sess, err := st.host.Up(context.Background(), p.Profile)
	if err != nil {
		return rpcError(req.ID, err)
	}
	st.session = sess
	return rpcOK(req.ID, nil)
}

func (st *childState) handleLaunch(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("Launch: no active session"))
	}
	pid, err := st.host.Launch(st.session)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, pid)
}

func (st *childState) handleDown(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcOK(req.ID, nil) // already gone, treat as success
	}
	err := st.host.Down(st.session)
	st.session = nil
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, nil)
}

func (st *childState) handleExternalIP(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("ExternalIP: no active session"))
	}
	ip, err := st.host.ExternalIP(context.Background(), st.session)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, ip)
}

func (st *childState) handleExternalIPInfo(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("ExternalIPInfo: no active session"))
	}
	info, err := st.host.ExternalIPInfo(context.Background(), st.session)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, info)
}

func (st *childState) handleTrafficStats(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("TrafficStats: no active session"))
	}
	ts, err := st.host.TrafficStats(st.session)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, ts)
}

// torBackendFromChildSession looks up the live Tor backend running
// inside the userns child's session. Used by handleTor* RPCs to act
// on the actual tor process without needing the parent to pass back
// a remote handle.
func (st *childState) torBackendFromChildSession() *tor.Backend {
	if st.session == nil {
		return nil
	}
	for _, b := range st.session.Backends {
		if t, ok := b.(*tor.Backend); ok {
			return t
		}
	}
	return nil
}

func (st *childState) handleTorNewCircuit(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("TorNewCircuit: no active session"))
	}
	// Delegate to the host engine's TorNewCircuit. It wraps the
	// tor.Dial in runInNetns so the dial reaches the
	// veil-PROFILE netns where Tor's control port is bound. The
	// userns child's MAIN netns (from CLONE_NEWNET at spawn) is
	// NOT the same as the named netns Tor lives in — a direct
	// tor.Dial from this goroutine would hit the wrong loopback
	// and return connection-refused.
	if err := st.host.TorNewCircuit(st.session); err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, nil)
}

func (st *childState) handleTorRelayIP(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("TorRelayIP: no active session"))
	}
	var fingerprint string
	if err := json.Unmarshal(req.Params, &fingerprint); err != nil {
		return rpcError(req.ID, err)
	}
	ip, err := st.host.TorRelayIP(st.session, fingerprint)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, ip)
}

func (st *childState) handleTorCircuitStatus(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("TorCircuitStatus: no active session"))
	}
	out, err := st.host.TorCircuitStatus(st.session)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, out)
}

func (st *childState) handleTorControlInfo(req *rpcRequest) rpcResponse {
	tb := st.torBackendFromChildSession()
	if tb == nil {
		return rpcError(req.ID, fmt.Errorf("TorControlInfo: no tor backend"))
	}
	port, cookie := tb.ControlInfo()
	return rpcOK(req.ID, map[string]any{"port": port, "cookie": cookie})
}

func (st *childState) handleBrowserProbeIP(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("BrowserProbeIP: no active session"))
	}
	var target string
	if err := json.Unmarshal(req.Params, &target); err != nil {
		return rpcError(req.ID, fmt.Errorf("BrowserProbeIP: parse target: %w", err))
	}
	body, err := st.host.BrowserProbeIP(context.Background(), st.session, target)
	if err != nil {
		return rpcError(req.ID, err)
	}
	return rpcOK(req.ID, body)
}

func (st *childState) handleProbeLeaks(req *rpcRequest) rpcResponse {
	if st.session == nil {
		return rpcError(req.ID, fmt.Errorf("ProbeLeaks: no active session"))
	}
	results := st.host.ProbeLeaks(context.Background(), st.session)
	return rpcOK(req.ID, results)
}

// setupNetnsDir is implemented per-platform — Linux uses bind-mounts
// inside the user-ns child, other platforms get a no-op stub.

// configureChildNetwork addresses the peer veth (already moved into
// our net-ns by veil-bridge) and adds a default route to the host
// gateway. Inside the user-ns child we have CAP_NET_ADMIN so this
// works without further elevation.
func configureChildNetwork(p configureNetworkParams) error {
	// loopback up in all modes — the in-netns chain resolver + proxies
	// bind 127.0.0.1.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}

	// Pasta (zero-cap) path: pasta configures the uplink interface
	// (p.PeerDevice == "veil0") with its address + default route
	// asynchronously after it attaches by PID. We don't address it
	// ourselves — just wait for it to be up with a default route before
	// the engine brings up the chain (which reads the default-route iface
	// as its WAN).
	if p.Pasta {
		return waitUplinkReady(15 * time.Second)
	}

	link, err := netlink.LinkByName(p.PeerDevice)
	if err != nil {
		return fmt.Errorf("find peer %s: %w", p.PeerDevice, err)
	}
	addr, err := netlink.ParseAddr(p.NSAddress)
	if err != nil {
		return fmt.Errorf("parse %s: %w", p.NSAddress, err)
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("add addr %s: %w", p.NSAddress, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up %s: %w", p.PeerDevice, err)
	}
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}
	gw := net.ParseIP(p.HostGateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway %q", p.HostGateway)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
		Dst:       nil, // default route
	}); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}

// waitUplinkReady polls until a default route appears in the current netns
// — the signal that pasta has finished configuring the uplink. pasta
// attaches by PID and configures asynchronously, naming the interface
// itself, so we key off the route (any uplink), not a fixed interface
// name. On timeout it reports the netns links seen, to distinguish "pasta
// never attached" (only lo) from "attached but no route yet".
func waitUplinkReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	// A default route may be reported with Dst==nil OR Dst==0.0.0.0/0
	// depending on kernel/netlink; accept either.
	isDefault := func(r netlink.Route) bool {
		if r.Dst == nil {
			return true
		}
		ones, _ := r.Dst.Mask.Size()
		return ones == 0 && r.Dst.IP.IsUnspecified()
	}
	for {
		if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err == nil {
			for _, r := range routes {
				if isDefault(r) {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			var links, rts []string
			if ls, err := netlink.LinkList(); err == nil {
				for _, l := range ls {
					links = append(links, l.Attrs().Name)
				}
			}
			if routes, err := netlink.RouteList(nil, netlink.FAMILY_V4); err == nil {
				for _, r := range routes {
					rts = append(rts, fmt.Sprintf("{dst=%v gw=%v idx=%d}", r.Dst, r.Gw, r.LinkIndex))
				}
			}
			return fmt.Errorf("pasta uplink not ready within %s; links=%v routes=%v", timeout, links, rts)
		}
		time.Sleep(80 * time.Millisecond)
	}
}

// emitError writes an error response with id=0 (no request) for use
// during startup failures before any RPC has arrived.
func emitError(msg string) {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": msg})
}

// silence "imported and not used" if a future cleanup drops one
// of these helpers.
var _ = runtime.GOOS
