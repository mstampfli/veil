//go:build linux

package engine

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/mstampfli/veil/internal/backends"
)

// PeerIP returns the kernel-reported peer IP of the chain's last
// tunnel device — the IP we are CURRENTLY tunneled to. No probe, no
// network call: this comes straight from the kernel's view of the
// tunnel state.
//
// What this is and isn't:
//   - For WireGuard: returns the configured Endpoint that wireguard-go
//     is currently using. If the .conf points at a roundrobin DNS, this
//     is the resolved IP at handshake time.
//   - For OpenVPN: returns the remote we're connected to.
//   - For SOCKS5/HTTP: returns the proxy host (already known from config).
//   - For Tor: caller should use the Tor control protocol path instead.
//
// The peer IP equals the actual exit IP for ~99% of commercial single-
// server VPNs (Mullvad, Proton, IVPN). For multi-hop or NAT'd egress,
// peer IP != exit IP — caller checks Profile.ChainIsMultihop() and
// either accepts off-mode or runs the explicit verify-once probe.
func PeerIP(s *Session) (net.IP, error) {
	st, ok := s.State.(*linuxState)
	if !ok {
		return nil, errors.New("session has no linux state")
	}

	// Prefer the backend's in-memory endpoint. Veil ships userspace
	// wireguard-go, which does NOT register a kernel WG device — so
	// `wg show` (kernel UAPI) returns "interface not found" and
	// /proc/net/wireguard/<iface>/peer doesn't exist. The
	// EndpointReporter interface exposes the live endpoint that
	// wireguard-go is actually talking to (post-DoH-resolution); read
	// it from there. Walk backends in reverse so the last hop wins —
	// matches the original "last tun device" semantic.
	for i := len(s.Backends) - 1; i >= 0; i-- {
		rep, ok := s.Backends[i].(backends.EndpointReporter)
		if !ok {
			continue
		}
		for _, ep := range rep.Endpoints() {
			host, _, splitErr := net.SplitHostPort(ep)
			if splitErr != nil {
				host = ep
			}
			if ip := net.ParseIP(host); ip != nil {
				return ip, nil
			}
		}
	}

	// Fallback for kernel-mode WireGuard installs (no userspace
	// wireguard-go in play): shell out to `wg show` inside the netns.
	if len(st.tunDevices) == 0 {
		return nil, errors.New("no tunnel device — chain may be proxy-only")
	}
	dev := st.tunDevices[len(st.tunDevices)-1]
	return readWGPeerIP(st.netnsName, dev)
}

// readWGPeerIP runs `wg show <iface> endpoints` inside the namespace
// and parses the peer's endpoint IP. WG's wg utility output:
//
//   <peer-pubkey>\t<endpoint-ip>:<port>\n
//
// We take the first peer's endpoint (single-server VPN configs only
// have one peer; multi-peer setups are an advanced case the caller
// would have to handle).
func readWGPeerIP(nsName, iface string) (net.IP, error) {
	out, err := exec.Command("ip", "netns", "exec", nsName,
		"wg", "show", iface, "endpoints").Output()
	if err != nil {
		// Fall back to /proc/net/wireguard if the wg utility isn't
		// available in $PATH (some minimal containers).
		return readWGPeerFromProc(nsName, iface)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] == "(none)" {
			continue
		}
		host, _, splitErr := net.SplitHostPort(fields[1])
		if splitErr != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		return ip, nil
	}
	return nil, errors.New("no peer endpoint reported by wg show")
}

// readWGPeerFromProc reads the kernel-side WG state via the legacy
// procfs path used by some wg-go variants.
func readWGPeerFromProc(nsName, iface string) (net.IP, error) {
	out, err := exec.Command("ip", "netns", "exec", nsName,
		"cat", "/proc/net/wireguard/"+iface+"/peer").Output()
	if err != nil {
		return nil, fmt.Errorf("read wg peer for %s: %w", iface, err)
	}
	// Look for "endpoint X.X.X.X:port" anywhere in the dump.
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, "endpoint ") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(l, "endpoint"))
		host, _, splitErr := net.SplitHostPort(val)
		if splitErr != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip, nil
		}
	}
	return nil, errors.New("no endpoint in /proc/net/wireguard")
}
