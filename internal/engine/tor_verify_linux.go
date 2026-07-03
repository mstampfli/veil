//go:build linux

package engine

import (
	"fmt"
	"net"
	"strings"

	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/geoip"
	"github.com/mstampfli/veil/internal/profile"
)

// verifyTorExit verifies the current Tor circuit's exit relay matches
// the profile's expected country. ZERO external queries — uses the
// local Tor control protocol + Tor's cached consensus + local
// GeoLite2.
//
// Lookup chain:
//   1. GETINFO circuit-status            → parse exit-relay fingerprint
//   2. GETINFO ns/id/<fingerprint>       → relay's IP from local consensus
//   3. geoip.Lookup(IP)                  → country code, offline
//   4. Compare to wantCountry; fail if mismatch.
//
// On first successful verification, capture observed values into the
// profile (VerifiedIP / VerifiedCountry / VerifiedAt). Subsequent
// launches verify against captured values.
// TorExitInfoLocal queries the running Tor's control protocol for the
// current circuit's exit relay, then resolves its IP from the cached
// consensus, then GeoLite2 for country. ZERO external traffic — pure
// localhost control-proto + bundled DB lookups. Returns ok=false if
// Tor isn't in the chain, control port isn't accessible, or no
// circuit is built yet.
//
// This makes Firefox + Tor profiles work leak-free for IP/geo
// display without depending on CDP (which Firefox doesn't speak).
func TorExitInfoLocal(s *Session) (IPInfo, bool) {
	st, ok := s.State.(*linuxState)
	if !ok {
		return IPInfo{}, false
	}
	ctrlAddr, cookie := torControlInfo(s, st)
	if ctrlAddr == "" {
		return IPInfo{}, false
	}
	ctl, err := tor.Dial(ctrlAddr, cookie)
	if err != nil {
		return IPInfo{}, false
	}
	defer ctl.Close()
	cs, err := ctl.CircuitStatus()
	if err != nil {
		return IPInfo{}, false
	}
	exitFP := parseExitFingerprint(cs)
	if exitFP == "" {
		return IPInfo{}, false
	}
	exitIPStr, err := ctl.RelayIP(exitFP)
	if err != nil || exitIPStr == "" {
		return IPInfo{}, false
	}
	exitIP := net.ParseIP(exitIPStr)
	if exitIP == nil {
		return IPInfo{}, false
	}
	info := IPInfo{IP: exitIPStr}
	if cc, ok := geoip.Lookup(exitIP); ok {
		info.Country = cc
	}
	if asn, org, ok := geoip.LookupASN(exitIP); ok {
		switch {
		case asn != "" && org != "":
			info.Org = asn + " " + org
		case asn != "":
			info.Org = asn
		case org != "":
			info.Org = org
		}
	}
	return info, true
}

// torControlInfo extracts the local Tor's control endpoint + cookie
// path from the active session. Returns "" if no Tor backend is
// active or control-port info wasn't recorded.
//
// HISTORY: this function used to type-assert backends against an
// interface named ControlEndpoint() — which no backend ever
// implemented. The assertion silently failed for every Tor backend,
// torControlInfo always returned "", and verifyTorExit / the local
// health probe both silently skipped. Result: the country pin
// claimed to be "verified" but verification was a no-op for months.
// Now uses the concrete *tor.Backend.ControlInfo() that actually
// exists.
func torControlInfo(s *Session, st *linuxState) (addr, cookie string) {
	for i := len(s.Backends) - 1; i >= 0; i-- {
		if tb, ok := s.Backends[i].(*tor.Backend); ok {
			port, cookiePath := tb.ControlInfo()
			if port == 0 {
				continue
			}
			return fmt.Sprintf("127.0.0.1:%d", port), cookiePath
		}
	}
	return "", ""
}

// parseExitFingerprint pulls the last $FP from the path field of the
// most recent BUILT circuit in `circuit-status` output. Tor format:
//
//   ID STATUS path [...flags...]
//   2  BUILT  $FP1=Nick1,$FP2~Nick2,$FP3~Nick3 BUILD_FLAGS=...
//
// Fingerprint and nickname are separated by EITHER "=" (relay has
// the Named flag in the consensus) OR "~" (the more common case for
// modern relays — Named flag was effectively retired). The previous
// version only handled "=", which left "~Nick" stuck on the
// fingerprint and made the subsequent GETINFO ns/id/<fp> fail with
// "relay not in local consensus".
//
// Returns "" if no BUILT circuit found.
func parseExitFingerprint(cs string) string {
	var lastFP string
	for _, line := range strings.Split(cs, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "BUILT" {
			continue
		}
		path := fields[2]
		hops := strings.Split(path, ",")
		if len(hops) == 0 {
			continue
		}
		lastHop := hops[len(hops)-1]
		if !strings.HasPrefix(lastHop, "$") {
			continue
		}
		fp := lastHop[1:]
		if i := strings.IndexAny(fp, "=~"); i > 0 {
			fp = fp[:i]
		}
		if fp != "" {
			lastFP = fp
		}
	}
	return lastFP
}

// silence unused-import linter when build tags strip features.
var _ = profile.BackendTor
