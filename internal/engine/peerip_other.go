//go:build !linux

package engine

// Cross-platform PeerIP for non-Linux hosts (Windows, macOS, *BSD).
//
// Linux's path reads the kernel's WG/OVPN peer endpoint via `wg show`
// inside the per-profile netns — that's the runtime, kernel-confirmed
// peer IP. The other OSes don't have netns or a unified peer-query
// API, so we use the next-best leak-free alternative: parse the on-
// disk WG/OVPN config the user pointed us at. For commercial single-
// server VPN configs (Mullvad, Proton, IVPN, etc.) the configured
// endpoint IS the peer/exit IP; this matches what `wg show` would
// report on Linux 99% of the time.
//
// Honest limitations:
//   - If the config uses a hostname (not IP literal), we can't resolve
//     it without a DNS query — we return ErrPeerHostname rather than
//     leak a query. Caller falls back to "exit unknown".
//   - For multi-hop or pool configs, we don't report a peer here;
//     caller should check Profile.ChainIsMultihop() and route to the
//     verify-once flow if needed.

import (
	"errors"
	"fmt"
	"net"
)

// ErrPeerHostname is returned when the WG/OVPN config uses a hostname
// rather than an IP literal. Caller can decide to do an explicit DNS
// resolution (with the leak that implies) or treat the exit as unknown.
var ErrPeerHostname = errors.New("peer endpoint is a hostname, not an IP literal")

// PeerIP returns the configured peer endpoint for the session's first
// tunnel hop. Pure offline: parses the WG/OVPN config that was used
// to bring the tunnel up. For chains that don't have a parseable
// fixed endpoint (Tor, multi-hop with dynamic exit) returns an error.
func PeerIP(s *Session) (net.IP, error) {
	if s == nil || s.Profile == nil {
		return nil, errors.New("nil session")
	}
	if s.Profile.ChainIsMultihop() {
		return nil, errors.New("multi-hop chain: peer IP is entry hop, not exit")
	}
	ep, err := s.Profile.ReadFirstHopEndpoint()
	if err != nil {
		return nil, err
	}
	if ep.IsIP {
		return ep.HostIP, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrPeerHostname, ep.Host)
}
