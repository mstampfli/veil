//go:build linux

package engine

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ProbeResult is one row from a leak probe.
type ProbeResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// ProbeLeaks runs a series of namespace-internal leak tests against
// the given session. Returns one ProbeResult per check. A profile that
// passes all checks has no observable leak through this surface.
//
// Tests:
//   - DNS connectivity (configured resolver responds)
//   - IPv6 isolation (cannot reach the public IPv6 internet from netns)
//   - No surprise listening sockets (`ss -tln` inside ns is empty)
//
// Note: this isn't a substitute for browser-side tests like
// browserleaks.com or ipleak.net — those probe at the JS/WebRTC layer
// which only the launched browser exposes. ProbeLeaks covers the
// network-namespace side.
func (e *linuxEngine) ProbeLeaks(ctx context.Context, s *Session) []ProbeResult {
	st := s.State.(*linuxState)
	var out []ProbeResult

	// 1. DNS connectivity.
	if err := e.verifyDNS(st); err != nil {
		out = append(out, ProbeResult{
			Name:   "dns_connectivity",
			OK:     false,
			Detail: err.Error(),
		})
	} else {
		out = append(out, ProbeResult{
			Name:   "dns_connectivity",
			OK:     true,
			Detail: "configured resolver responds",
		})
	}

	// 2. IPv6 isolation. Try to reach a known IPv6 host. Should fail
	// (timeout or No route) if the chain is IPv4-only — the typical
	// safe case. If it succeeds, IPv6 is leaking around the chain.
	v6Ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Reach a known public IPv6 host DIRECTLY by its address literal.
	// Cloudflare's resolver cert carries 2606:4700:4700::1111 as an IP
	// SAN, so a reachable v6 path validates and curl exits 0 (= LEAK);
	// an unreachable path errors (= isolated, expected).
	//
	// The previous form passed `--connect-to ::1:443:[2606:4700:4700::1111]:443`
	// with URL host `::1`, which curl REJECTED at parse time ("Port number
	// was not a decimal number", exit 3) and never connected — so this
	// probe always errored and always reported "isolated", structurally
	// unable to detect a real IPv6 leak.
	cmd := exec.CommandContext(v6Ctx,
		"ip", "netns", "exec", st.netnsName,
		"curl", "-6", "-s", "--max-time", "3",
		"-o", "/dev/null",
		"https://[2606:4700:4700::1111]/")
	v6Out, v6Err := cmd.CombinedOutput()
	if v6Err == nil {
		out = append(out, ProbeResult{
			Name: "ipv6_isolation",
			OK:   false,
			Detail: fmt.Sprintf("LEAK: IPv6 reachable: %s",
				truncate(string(v6Out), 200)),
		})
	} else {
		out = append(out, ProbeResult{
			Name:   "ipv6_isolation",
			OK:     true,
			Detail: "IPv6 unreachable (expected)",
		})
	}

	// 3. No unexpected NON-LOOPBACK listening sockets. Loopback listeners
	// are expected and harmless: tor's SocksPort/ControlPort/DNSPort, a
	// chained SOCKS relay, and the in-netns DoH proxy all bind 127.0.0.1
	// and are reachable only from inside the namespace. Only a listener
	// bound to a routable address (0.0.0.0, ::, the veth or tun IP) is a
	// real "surprise" worth flagging. Flagging loopback made `veil profile
	// probe` FAIL for every tor/proxy profile (false positive).
	cmd = exec.Command("ip", "netns", "exec", st.netnsName, "ss", "-tlnH")
	ssOut, _ := cmd.CombinedOutput()
	flagged := nonLoopbackListeners(string(ssOut))
	if len(flagged) == 0 {
		out = append(out, ProbeResult{
			Name: "no_listeners",
			OK:   true, Detail: "no non-loopback listening sockets in namespace",
		})
	} else {
		out = append(out, ProbeResult{
			Name: "no_listeners",
			OK:   false,
			Detail: fmt.Sprintf("non-loopback listening sockets present: %s",
				truncate(strings.Join(flagged, "; "), 300)),
		})
	}

	return out
}

// nonLoopbackListeners returns the `ss -tlnH` rows whose local bind
// address is NOT loopback (127.0.0.0/8 or ::1). Loopback listeners are
// only reachable inside the namespace, so they are not a leak; a listener
// on a routable address is.
func nonLoopbackListeners(ssOutput string) []string {
	var flagged []string
	for _, line := range strings.Split(ssOutput, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local := f[3] // "Local Address:Port"
		host := local
		if i := strings.LastIndex(local, ":"); i >= 0 {
			host = local[:i]
		}
		host = strings.Trim(host, "[]")
		if host == "::1" || strings.HasPrefix(host, "127.") {
			continue
		}
		flagged = append(flagged, strings.TrimSpace(line))
	}
	return flagged
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
