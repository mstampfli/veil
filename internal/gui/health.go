package gui

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mstampfli/veil/internal/audit"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/geoip"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// chainHasTor reports whether any backend in the session is a Tor hop.
func chainHasTor(s *engine.Session) bool {
	if s == nil || s.Profile == nil {
		return false
	}
	for _, b := range s.Profile.Chain {
		if b.Kind == profile.BackendTor {
			return true
		}
	}
	return false
}

// healthState is the per-session health snapshot.
type healthState struct {
	State    string    // "starting" / "healthy" / "degraded" / "failed"
	LastIP   string    // last IP we observed; if it changes, that's a degradation signal
	LastOK   time.Time // last successful probe
	LastErr  string
	cancel   context.CancelFunc
	stopOnce sync.Once
}

// healthMu guards App.health
var (
	healthMu      sync.Mutex
	probeInterval = 60 * time.Second // local probe is cheap; tighter loop
)

// localHealthProbe inspects the kernel-side tunnel state for non-Tor
// single-hop chains. Returns (info, ok).
//
//	ok=true  → tunnel is up, peer IP visible. info has IP and (when
//	           GeoLite2 is bundled) country/asn/org. No external probe.
//	ok=false → caller should fall back to engine.ExternalIPInfo (Tor,
//	           multi-hop, or no tunnel device exists).
//
// This is the "no-leak default" for the health probe: the kernel
// already knows what we're tunneled to; we don't need ipinfo to learn
// it for the common case.
func localHealthProbe(sess *engine.Session) (engine.IPInfo, bool) {
	if sess == nil || sess.Profile == nil {
		return engine.IPInfo{}, false
	}
	// Tor in the chain: use the Tor control protocol to learn the
	// current exit relay's IP from the cached consensus, then
	// GeoLite2 for country. Pure localhost + local DB — no external
	// traffic, works regardless of which browser is running. Lets
	// Firefox+Tor profiles show IP/geo without CDP.
	if chainHasTor(sess) {
		if info, ok := engine.TorExitInfoLocal(sess); ok && info.IP != "" {
			return info, true
		}
		// Tor in chain but control proto didn't return — caller falls
		// through to CDP (works for Chromium-family) or surfaces the
		// "no Tor exit info available" error.
		return engine.IPInfo{}, false
	}
	// Multi-hop without Tor: kernel only sees entry hop, not exit.
	// Caller falls through to CDP / verify-once.
	if sess.Profile.ChainIsMultihop() {
		return engine.IPInfo{}, false
	}
	// Single-hop: get the peer endpoint. Try kernel state first
	// (engine.PeerIP runs wg show inside the netns) — but that fails
	// for our wg-go userspace setup because wg-go's UAPI socket lives
	// in the HOST namespace, not the per-profile netns. Fall back to
	// parsing the WG/OVPN config file: no kernel query, no network
	// traffic, just reads the on-disk Endpoint line. For commercial
	// single-server VPN configs (Mullvad, Proton, IVPN) this is the
	// actual peer/exit IP.
	var ip net.IP
	if peer, err := engine.PeerIP(sess); err == nil && peer != nil {
		ip = peer
	} else if ep, err := sess.Profile.ReadFirstHopEndpoint(); err == nil && ep.IsIP {
		ip = ep.HostIP
	}
	if ip == nil {
		return engine.IPInfo{}, false
	}
	info := engine.IPInfo{IP: ip.String()}
	if cc, ok := geoip.Lookup(ip); ok {
		info.Country = cc
	}
	if asn, org, ok := geoip.LookupASN(ip); ok {
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

// startHealthProbe spawns a background goroutine that re-fetches the
// session's external IP every probeInterval and updates the State.
//
// Status semantics:
//   - "starting" — first probe in flight
//   - "healthy"  — last probe succeeded; IP matches the previous one
//   - "degraded" — last probe failed once OR IP changed
//   - "failed"   — three consecutive probe failures
func (a *App) startHealthProbe(name string, sess *engine.Session) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if a.health == nil {
		a.health = map[string]*healthState{}
	}
	// Cancel any prior probe for this name.
	if old, ok := a.health[name]; ok && old.cancel != nil {
		old.cancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	hs := &healthState{State: "starting", cancel: cancel}
	a.health[name] = hs
	go a.healthProbeLoop(ctx, name, sess, hs)
}

func (a *App) healthProbeLoop(ctx context.Context, name string, sess *engine.Session, hs *healthState) {
	defer hs.stopOnce.Do(func() {})
	// Tor circuits legitimately rotate, so IP changes there are
	// expected, not a degradation signal. Probe failure is still a
	// degradation signal regardless of chain.
	allowIPChange := chainHasTor(sess)
	failures := 0
	probe := func() {
		// Local-first: kernel-side peer IP for single-hop non-Tor
		// chains. Eliminates the spurious "degraded" flicker that
		// happened when ipinfo.io rate-limited or had a network blip,
		// and stops the recurring 5-minute leak to ipinfo for the
		// common case. Falls back to ExternalIPInfo only for chains
		// where local can't see the actual exit (Tor, multi-hop).
		var info engine.IPInfo
		var err error
		if li, ok := localHealthProbe(sess); ok {
			info = li
		} else {
			// Tor over WG / rare-country exits can take 30-60s for a
			// single ipinfo fetch; use a generous outer deadline so
			// slow-but-functional chains aren't flagged as failed.
			to := 30 * time.Second
			if chainHasTor(sess) {
				to = 90 * time.Second
			}
			pctx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			info, err = engine.Active().ExternalIPInfo(pctx, sess)
		}

		healthMu.Lock()
		defer healthMu.Unlock()
		cur, ok := a.health[name]
		if !ok {
			return
		}
		if err != nil {
			failures++
			cur.LastErr = err.Error()
			// One probe failure: degraded (could be transient).
			// Three consecutive failures: failed (the chain genuinely
			// isn't carrying traffic — leaving the GUI showing stale
			// last-known-good data is misleading the user, who then
			// thinks their chain works when it doesn't).
			if failures >= 3 {
				cur.State = "failed"
				// Clear cached IP/geo so the GUI stops displaying
				// stale numbers from a chain that's no longer
				// carrying traffic. Without this, user sees green
				// "Sweden 45.66…" even though they have no internet.
				cur.LastIP = ""
				logger.L().Error("health probe failed repeatedly — chain is not carrying traffic",
					"profile", name, "err", err, "consec_fail", failures)
			} else {
				cur.State = "degraded"
				logger.L().Warn("health probe failed (chain may still be fine)",
					"profile", name, "err", err, "consec_fail", failures)
			}
			return
		}
		failures = 0
		cur.LastErr = ""
		cur.LastOK = time.Now()
		if !allowIPChange && cur.LastIP != "" && cur.LastIP != info.IP {
			cur.State = "degraded"
			logger.L().Warn("health probe: ip changed (tunnel may have reconnected)",
				"profile", name, "old", cur.LastIP, "new", info.IP)
		} else {
			cur.State = "healthy"
		}
		cur.LastIP = info.IP

		// Locked-endpoint drift check: re-validate constraints. For
		// chains where local probe captured the exit (single-hop VPN),
		// the info struct has country+org from GeoLite2 and we can
		// drift-check without leaking. For Tor/multihop the info came
		// from ipinfo and the same drift check applies.
		if sess.Profile.LockedEndpoint {
			driftReason := checkLockedEndpointDrift(sess.Profile, info)
			if driftReason != "" {
				cur.State = "drift"
				cur.LastErr = driftReason
				audit.Log(audit.Event{
					Type: audit.EventDriftDetected, Severity: audit.SeverityError,
					Profile: name, Persona: sess.Profile.Persona,
					Detail: map[string]any{
						"reason": driftReason, "ip": info.IP,
						"country": info.Country, "city": info.City, "org": info.Org,
						"action": "session torn down",
					},
				})
				logger.L().Error("locked endpoint drift — KILLING session",
					"profile", name, "reason", driftReason,
					"observed_ip", info.IP, "observed_country", info.Country)
				// HARD KILL: drift means traffic is currently flowing
				// through a wrong-country exit. Some leakage already
				// happened (every probe interval is a window), but
				// tearing the session down NOW caps it. The chain's
				// kill switch + iptables rules block further egress;
				// the browser process gets SIGTERM via eng.Down.
				//
				// Done in a goroutine so we release healthMu before
				// eng.Down (which can take seconds and grabs other
				// locks). The deferred stopOnce in this loop fires
				// when ctx is cancelled by stopHealthProbe.
				go a.killProfileForDrift(name, driftReason)
				return // exit the probe loop; session is gone
			}
		}
	}

	probe()
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probe()
		}
	}
}

// checkLockedEndpointDrift returns a non-empty reason string if the
// observed IPInfo doesn't match the profile's locked-endpoint
// constraints. Empty string = no drift.
//
// Each Lock* dim is checked independently — the user opted in to that
// specific check. Dims they didn't opt into are skipped even if the
// matching Require* field happens to have a value.
func checkLockedEndpointDrift(p *profile.Profile, info engine.IPInfo) string {
	if !p.AnyLockEnabled() {
		return ""
	}
	if p.LockCountry {
		want := strings.ToUpper(p.RequireExitCountry)
		got := strings.ToUpper(info.Country)
		if want != "" && got != "" && want != got {
			return fmt.Sprintf("country %s != required %s", got, want)
		}
	}
	if c := p.RequireExitCity; c != "" && !strings.EqualFold(c, info.City) {
		return fmt.Sprintf("city %s != required %s", info.City, c)
	}
	if p.LockASN {
		if asn := p.RequireExitASN; asn != "" {
			gotASN := ""
			if i := strings.Index(info.Org, " "); i > 0 {
				gotASN = info.Org[:i]
			}
			if !strings.EqualFold(asn, gotASN) {
				return fmt.Sprintf("asn %s != required %s", gotASN, asn)
			}
		}
	}
	if p.LockIP {
		if ip := p.RequireExitIP; ip != "" && ip != info.IP {
			return fmt.Sprintf("ip %s != required %s", info.IP, ip)
		}
	}
	return ""
}

// killProfileForDrift tears down a running session because the post-
// launch ipinfo probe detected the actual exit doesn't match the
// pinned country (or other locked_endpoint constraint). Called from
// the health probe goroutine after it has already logged + audited
// the drift; this function does the destructive work (eng.Down,
// remove from sessions map, stop reroll timer, stop health probe).
//
// Some traffic has already flowed by the time this fires — at least
// one probe interval's worth, plus whatever the user/browser did
// since the previous probe. The kill bounds the leak window to
// (probe interval) rather than letting it run indefinitely.
func (a *App) killProfileForDrift(name, reason string) {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	if ok {
		delete(a.sessions, name)
	}
	a.mu.Unlock()
	a.stopRerollTimer(name)
	a.stopHealthProbe(name)
	if !ok {
		return
	}
	if err := engine.Active().Down(sess); err != nil {
		logger.L().Warn("kill-on-drift: engine.Down failed", "profile", name, "err", err)
	} else {
		logger.L().Info("kill-on-drift: session torn down", "profile", name, "reason", reason)
	}
	// Push a UI event so the GUI shows the kill reason prominently
	// instead of the user wondering why their browser disappeared.
	wruntime.EventsEmit(a.ctx, "profile-killed", map[string]any{
		"name":   name,
		"reason": reason,
	})
}

func (a *App) stopHealthProbe(name string) {
	healthMu.Lock()
	defer healthMu.Unlock()
	if hs, ok := a.health[name]; ok && hs.cancel != nil {
		hs.cancel()
		delete(a.health, name)
	}
}

// HealthState returns the current health string for a profile.
func (a *App) HealthState(name string) string {
	healthMu.Lock()
	defer healthMu.Unlock()
	if hs, ok := a.health[name]; ok {
		return hs.State
	}
	return ""
}
