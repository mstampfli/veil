//go:build linux

package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ExternalIP returns just the IP address from ExternalIPInfo.
func (e *linuxEngine) ExternalIP(ctx context.Context, s *Session) (string, error) {
	info, err := e.ExternalIPInfo(ctx, s)
	if err != nil {
		return "", err
	}
	return info.IP, nil
}

// ExternalIPInfo fetches IP + city + country + org. It first tries to
// drive a running Chromium/Firefox browser through CDP/Marionette so
// exit observers see a vanilla browser visit indistinguishable from
// the user opening a new tab to ipinfo (CDP traffic stays on
// 127.0.0.1; Veil never opens a socket outside the netns).
//
// When no browser is available — curl / proxy-only / headless
// profiles, or the browser has exited — it falls back to an in-netns
// HTTP probe (see probeIPViaNetns). That makes `veil selftest`, the
// `ip` command, and auto-fingerprint country detection work for EVERY
// chain, not just browser presets.
func (e *linuxEngine) ExternalIPInfo(ctx context.Context, s *Session) (IPInfo, error) {
	body, err := e.BrowserProbeIP(ctx, s, "https://ipinfo.io/json")
	if err != nil {
		// No usable browser: verify the chain directly from inside the
		// netns instead of failing. This is the universal path.
		info, ferr := e.probeIPViaNetns(ctx, s)
		if ferr != nil {
			return IPInfo{}, fmt.Errorf("browser probe: %w; netns probe: %v", err, ferr)
		}
		return info, nil
	}
	var info IPInfo
	if err := jsonUnmarshalIPInfo([]byte(body), &info); err != nil {
		// Page may have rendered something other than JSON if ipinfo
		// rate-limited or served HTML. Best-effort: return what we got.
		txt := strings.TrimSpace(body)
		return IPInfo{IP: txt}, nil
	}
	return info, nil
}

// probeIPViaNetns verifies the exit IP from inside the netns, with a
// short bounded retry. It traverses the full chain (tor / vpn / socks /
// mitm) exactly like the launched app, so it is the universal
// verification path for selftest and proxy-only profiles.
//
// Why retry: a freshly-built tunnel — especially WireGuard, whose
// handshake is lazy — can need a beat after Up() before it passes
// traffic. The first probe then fails fast (ENETUNREACH while the
// handshake completes) even though routing is already correct (verified:
// the netns default route is present, but the tunnel isn't forwarding
// yet). A real browser rides through that window by retrying/reloading;
// veil's own verification must be equally resilient or it reports a
// transient bring-up as a hard FAIL (the intermittent DNS_leak_test
// failures). Each attempt is the full multi-endpoint probe; we back off
// briefly between attempts and still fail closed after a few tries.
func (e *linuxEngine) probeIPViaNetns(ctx context.Context, s *Session) (IPInfo, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return IPInfo{}, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		info, err := e.probeIPViaNetnsOnce(ctx, s)
		if err == nil {
			return info, nil
		}
		lastErr = err
	}
	return IPInfo{}, lastErr
}

// probeIPViaNetnsOnce runs ONE pass of the in-netns probe: a DNS-free
// 1.1.1.1 trace first (needs only TCP egress), then DNS-dependent geo /
// bare-IP-echo endpoints.
//
// DNS resolves through the netns's own resolv.conf (the chain's resolver
// — Tor's DNSPort, the VPN-pushed server, etc.) because `ip netns exec`
// bind-mounts /etc/netns/<name>/resolv.conf over /etc/resolv.conf for
// the spawned process.
func (e *linuxEngine) probeIPViaNetnsOnce(ctx context.Context, s *Session) (IPInfo, error) {
	st, ok := s.State.(*linuxState)
	if !ok {
		return IPInfo{}, fmt.Errorf("probeIPViaNetns: invalid session state")
	}
	var lastErr error
	// 1) DNS-free path first: Cloudflare's trace endpoint reached by IP
	//    literal. It needs no in-netns resolver — only TCP egress
	//    through the chain — so it verifies the exit IP even when chain
	//    DNS is misconfigured, and avoids the round-trip's dependence on
	//    a working resolver.
	if body, err := e.netnsHTTPGet(ctx, st, "https://1.1.1.1/cdn-cgi/trace"); err == nil {
		if ip := parseTraceIP(body); net.ParseIP(ip) != nil {
			return IPInfo{IP: ip}, nil
		}
	} else {
		lastErr = err
	}
	// 2) ipinfo.io/json for geo (City/Country/Org) — needs working DNS.
	if geoBody, err := e.netnsHTTPGet(ctx, st, "https://ipinfo.io/json"); err == nil {
		var info IPInfo
		if jerr := jsonUnmarshalIPInfo([]byte(geoBody), &info); jerr == nil && net.ParseIP(info.IP) != nil {
			return info, nil
		}
	} else {
		lastErr = err
	}
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		body, err := e.netnsHTTPGet(ctx, st, url)
		if err != nil {
			lastErr = err
			continue
		}
		if ip := strings.TrimSpace(body); net.ParseIP(ip) != nil {
			return IPInfo{IP: ip}, nil
		}
	}
	if lastErr != nil {
		return IPInfo{}, lastErr
	}
	return IPInfo{}, fmt.Errorf("in-netns probe returned no usable IP")
}

// parseTraceIP extracts the "ip=" field from Cloudflare's
// /cdn-cgi/trace key=value body (one pair per line).
func parseTraceIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// netnsHTTPGet runs a single HTTP GET inside the session netns and
// returns the response body. curl is preferred (it is the freetor
// preset's own binary and ubiquitous); wget is the fallback for
// minimal images. The 25s cap accommodates a cold Tor circuit; the
// caller's ctx can shorten it.
func (e *linuxEngine) netnsHTTPGet(ctx context.Context, st *linuxState, url string) (string, error) {
	if path, err := exec.LookPath("curl"); err == nil {
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", st.netnsName,
			path, "-s", "--max-time", "25", "-A", "Mozilla/5.0", url).Output()
		if err != nil {
			return "", fmt.Errorf("curl in netns: %w", err)
		}
		return string(out), nil
	}
	if path, err := exec.LookPath("wget"); err == nil {
		out, err := exec.CommandContext(ctx, "ip", "netns", "exec", st.netnsName,
			path, "-q", "-T", "25", "-O", "-", url).Output()
		if err != nil {
			return "", fmt.Errorf("wget in netns: %w", err)
		}
		return string(out), nil
	}
	return "", fmt.Errorf("no curl or wget available for in-netns IP probe")
}

// writableBuffer is a minimal io.Writer-based buffer.
type writableBuffer struct{ b []byte }

func (w *writableBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *writableBuffer) String() string              { return string(w.b) }

// jsonUnmarshalIPInfo decodes ipinfo.io's response into IPInfo.
func jsonUnmarshalIPInfo(data []byte, out *IPInfo) error {
	return json.Unmarshal(data, out)
}

// TrafficStats reads byte counters for the session's primary outbound
// interface. Returns counters from the TUN if a tunnel is active,
// otherwise the veth peer (proxy chain).
func (e *linuxEngine) TrafficStats(s *Session) (TrafficStats, error) {
	st := s.State.(*linuxState)
	iface := st.peer
	if len(st.tunDevices) > 0 {
		iface = st.tunDevices[len(st.tunDevices)-1]
	}
	return readNetnsStats(st.netnsName, iface)
}

func readNetnsStats(ns, iface string) (TrafficStats, error) {
	read := func(field string) uint64 {
		out, err := exec.Command("ip", "netns", "exec", ns, "cat",
			"/sys/class/net/"+iface+"/statistics/"+field).Output()
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		return v
	}
	return TrafficStats{
		Iface:     iface,
		TxBytes:   read("tx_bytes"),
		RxBytes:   read("rx_bytes"),
		TxPackets: read("tx_packets"),
		RxPackets: read("rx_packets"),
	}, nil
}
