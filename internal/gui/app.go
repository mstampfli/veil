// Package gui hosts the Wails-bound application object.
//
// Methods on *App that take and return JSON-marshalable types are exposed
// to the frontend automatically by Wails.
package gui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"net"
	"net/url"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/chain"
	cliversion "github.com/mstampfli/veil/internal/cli"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/launcher"
	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/persona"
	"github.com/mstampfli/veil/internal/profile"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is bound to the Wails frontend.
type App struct {
	ctx context.Context

	mu       sync.Mutex
	store    *profile.Store
	sessions map[string]*engine.Session // keyed by profile name
	health   map[string]*healthState

	geoMu    sync.Mutex
	geoCache map[string]geoCacheEntry // keyed by profile name (last exit IP info)
	ipCache  map[string]geoCacheEntry // keyed by IP (for hop geo lookups)

	rerollMu     sync.Mutex
	rerollCancel map[string]context.CancelFunc
}

type geoCacheEntry struct {
	info engine.IPInfo
	at   time.Time
}

// NewApp constructs the bound app.
func NewApp() *App {
	return &App{
		sessions: map[string]*engine.Session{},
		health:   map[string]*healthState{},
	}
}

// Startup is called by Wails after JS is ready.
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	s, err := profile.DefaultStore()
	if err == nil {
		a.store = s
	}
}

// ReportBug opens the project's bug tracker in the user's browser with a
// prefilled issue (version + OS). Consistent with the no-telemetry guarantee:
// nothing is sent automatically — it just opens GitHub for the user to submit.
// Bound to the frontend "Report a bug" action.
func (a *App) ReportBug() {
	body := fmt.Sprintf(
		"## What happened?\n\n<!-- describe the bug -->\n\n"+
			"## Steps to reproduce\n\n1. \n2. \n\n"+
			"## Environment\n\n- veil version: %s\n- OS/arch: %s/%s\n",
		cliversion.Version, runtime.GOOS, runtime.GOARCH)
	u := cliversion.IssuesNewURL + "?labels=bug&title=" + url.QueryEscape("[bug] ") +
		"&body=" + url.QueryEscape(body)
	wruntime.BrowserOpenURL(a.ctx, u)
}

// guiErr is a deferred error-logger for Wails-bound methods. Wails
// surfaces returned errors as JS toasts but doesn't log them server-
// side, so a failure mid-Launch (etc.) leaves no forensic trace.
// Add `defer guiErr("MethodName", &err)` to bound methods with a
// named `err` return; non-nil errors get logged before they're
// returned to JS. Cheap, no behavior change for the caller.
func guiErr(method string, errp *error) {
	if errp == nil || *errp == nil {
		return
	}
	logger.L().Warn("gui method failed", "method", method, "err", (*errp).Error())
}

// RequestShutdown is the JS-callable shutdown trigger. The GUI's
// "Quit" button calls this; it tears down all sessions and exits.
// Equivalent to writing to the user-accessible socket from the CLI.
// Avoids the "X-button doesn't work because root-vs-user X mismatch"
// fallback path.
func (a *App) RequestShutdown() {
	a.Shutdown(context.Background())
	// Best-effort: remove the socket so a stale entry doesn't
	// confuse the next launch.
	_ = removeShutdownSocketIfPresent()
	os.Exit(0)
}

// Shutdown tears down all running sessions. Idempotent — safe to
// call from both the Wails OnShutdown hook and an external signal
// handler.
func (a *App) Shutdown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sessions) == 0 {
		return
	}
	eng := engine.Active()
	for name, s := range a.sessions {
		if err := eng.Down(s); err != nil {
			logger.L().Warn("shutdown: down failed", "profile", name, "err", err)
		}
		delete(a.sessions, name)
	}
	a.sessions = map[string]*engine.Session{}
}

// --- DTOs exposed to frontend ---

type ProfileDTO struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Chain       string   `json:"chain"`
	ChainKinds  []string `json:"chain_kinds"`
	App         string   `json:"app"`
	Preset      string   `json:"preset"`
	KillSwitch  bool     `json:"kill_switch"`
	Running     bool     `json:"running"`
	PID         int      `json:"pid"`
	Health      string   `json:"health,omitempty"`
	LastIP      string   `json:"last_ip,omitempty"`
}

type LicenseDTO struct {
	Tier   string `json:"tier"`
	Email  string `json:"email"`
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type LaunchResult struct {
	PID int    `json:"pid"`
	IP  string `json:"ip,omitempty"`
}

// --- bound methods ---

// ListProfiles returns all profiles with running status.
func (a *App) ListProfiles() ([]ProfileDTO, error) {
	if a.store == nil {
		return nil, fmt.Errorf("profile store not ready")
	}
	profs, err := a.store.LoadAll()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ProfileDTO, 0, len(profs))
	for _, p := range profs {
		dto := ProfileDTO{
			Name:        p.Name,
			Description: p.Description,
			Chain:       chain.Summary(p.Chain),
			ChainKinds:  kindsOf(p),
			App:         p.App.Binary,
			Preset:      p.App.Preset,
			KillSwitch:  p.KillSwitch,
		}
		if sess, ok := a.sessions[p.Name]; ok && sess != nil {
			dto.Running = true
			if hs, ok2 := a.health[p.Name]; ok2 {
				dto.Health = hs.State
				dto.LastIP = hs.LastIP
			}
		}
		out = append(out, dto)
	}
	return out, nil
}

func kindsOf(p *profile.Profile) []string {
	out := make([]string, len(p.Chain))
	for i, b := range p.Chain {
		out[i] = string(b.Kind)
	}
	return out
}

// GetProfile returns a single profile (full YAML-equivalent).
func (a *App) GetProfile(name string) (*profile.Profile, error) {
	if a.store == nil {
		return nil, fmt.Errorf("profile store not ready")
	}
	return a.store.Load(name)
}

// SaveProfile creates or updates a profile.
func (a *App) SaveProfile(p profile.Profile) (err error) {
	defer guiErr("SaveProfile", &err)
	if a.store == nil {
		return fmt.Errorf("profile store not ready")
	}
	if err := chain.Validate(p.Chain); err != nil {
		return err
	}
	// Preserve fields the form doesn't carry — they're authoritative
	// state owned by the engine, not by the editor. If the form re-
	// posted them as zero we'd silently revoke consent / lose the
	// CA-removal-pending flag, which is exactly the bug the user
	// hit ("CA prompt re-fires after every edit").
	if existing, lerr := a.store.Load(p.Name); lerr == nil {
		if p.StrictMITMAcceptedAt.IsZero() {
			p.StrictMITMAcceptedAt = existing.StrictMITMAcceptedAt
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = existing.CreatedAt
		}
	}
	return a.store.Save(&p)
}

// DeleteProfile removes a profile.
func (a *App) DeleteProfile(name string) (err error) {
	defer guiErr("DeleteProfile", &err)
	if a.store == nil {
		return fmt.Errorf("profile store not ready")
	}
	a.mu.Lock()
	if s, ok := a.sessions[name]; ok {
		_ = engine.Active().Down(s)
		delete(a.sessions, name)
	}
	a.mu.Unlock()
	return a.store.Delete(name)
}

// LaunchProfile brings the profile up and starts the configured app.
func (a *App) LaunchProfile(name string) (res LaunchResult, err error) {
	defer guiErr("LaunchProfile", &err)
	if a.store == nil {
		return LaunchResult{}, fmt.Errorf("profile store not ready")
	}
	p, err := a.store.Load(name)
	if err != nil {
		return LaunchResult{}, err
	}
	// Lock country checkbox + empty require_exit_country = derive
	// from persona's country. The checkbox is the explicit opt-in;
	// without it ticked we don't touch country at all.
	if p.LockCountry && p.RequireExitCountry == "" {
		if pc := personaExitCountry(p); pc != "" {
			p.RequireExitCountry = pc
			logger.L().Info("derived RequireExitCountry from persona",
				"profile", p.Name, "country", pc)
		}
	}
	// Apply policy → backend wiring (e.g. RequireExitCountry → Tor's
	// torrc ExitNodes) BEFORE Resolve picks pool entries, so any
	// shape-derived defaults see the propagated values.
	p.PropagateExitConstraints()
	// Strict-tier installs a per-profile TLS interception CA. Refuse
	// to bring the chain up until the user has explicitly accepted
	// the install — the JS frontend matches on
	// ErrStrictTierConsentRequired to decide between a toast vs the
	// consent modal.
	if p.NeedsStrictTierConsent() {
		return LaunchResult{}, ErrStrictTierConsentRequired
	}
	// Auto-insert tls_mitm at end of chain when anti_fingerprint is
	// strict. Closes the TLS-OS-coherence gap: without this,
	// Firefox+RFP claims Windows in JS but emits Firefox-on-Linux NSS
	// quirks at L4 — fingerprintable. With this, every strict-tier
	// browser's TLS handshake is uTLS-shaped uniformly.
	p.PropagateAntiFingerprintMITM()
	if err := launcher.Resolve(p); err != nil {
		return LaunchResult{}, err
	}

	a.mu.Lock()
	if _, ok := a.sessions[name]; ok {
		a.mu.Unlock()
		return LaunchResult{}, fmt.Errorf("profile %q already running", name)
	}
	a.mu.Unlock()

	eng := engine.Active()
	// Tor over a slow VPN can take 30-60s to bootstrap; allow plenty of
	// slack so launches don't fail spuriously.
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Minute)
	defer cancel()
	sess, err := eng.Up(ctx, p)
	if err != nil {
		return LaunchResult{}, err
	}
	pid, err := eng.Launch(sess)
	if err != nil {
		_ = eng.Down(sess)
		return LaunchResult{}, err
	}
	a.mu.Lock()
	a.sessions[name] = sess
	a.mu.Unlock()
	a.startHealthProbe(name, sess)
	a.startRerollTimer(name, p)
	return LaunchResult{PID: pid}, nil
}

// StopProfile tears down a running profile.
func (a *App) StopProfile(name string) (err error) {
	defer guiErr("StopProfile", &err)
	a.mu.Lock()
	sess, ok := a.sessions[name]
	if ok {
		delete(a.sessions, name)
	}
	a.mu.Unlock()
	a.stopHealthProbe(name)
	a.stopRerollTimer(name)
	if !ok {
		return fmt.Errorf("profile %q not running", name)
	}
	return engine.Active().Down(sess)
}

// RerollProfile prefers a soft reroll (no connection drop) when the
// chain contains Tor; falls back to a hard restart otherwise. The auto-
// reroll timer also uses this so connections survive whenever they can.
func (a *App) RerollProfile(name string) (err error) {
	defer guiErr("RerollProfile", &err)
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("profile %q not running", name)
	}
	if chainHasTor(sess) {
		if err := a.SoftReroll(name); err != nil {
			logger.L().Warn("soft reroll failed, falling back to hard", "profile", name, "err", err)
			return a.HardReroll(name)
		}
		return nil
	}
	return a.HardReroll(name)
}

// SoftReroll asks Tor to build new circuits for subsequent connections
// (SIGNAL NEWNYM). Existing TCP streams stay on their old circuits and
// finish naturally. Only meaningful when the chain has a Tor hop.
func (a *App) SoftReroll(name string) (err error) {
	defer guiErr("SoftReroll", &err)
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("profile %q not running", name)
	}
	if !chainHasTorBackend(sess) {
		return fmt.Errorf("profile %q has no Tor hop in chain (chain=%v) — soft reroll only works with Tor in the chain (use HardReroll to fully restart)", name, chainKinds(sess))
	}
	if err := a.TorNewCircuit(name); err != nil {
		return err
	}
	logger.L().Info("soft reroll: NEWNYM signaled", "profile", name)
	return nil
}

// HardReroll graceful-restarts a running profile so chain randomization
// + endpoint-pool selection roll fresh. All connections drop.
func (a *App) HardReroll(name string) (err error) {
	defer guiErr("HardReroll", &err)
	a.mu.Lock()
	_, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("profile %q not running", name)
	}
	if err = a.StopProfile(name); err != nil {
		return err
	}
	_, err = a.LaunchProfile(name)
	return err
}

// startRerollTimer arms a periodic re-roll if the profile asks for one.
func (a *App) startRerollTimer(name string, p *profile.Profile) {
	if p.RerollEvery == "" {
		return
	}
	d, err := time.ParseDuration(p.RerollEvery)
	if err != nil || d < 30*time.Second {
		logger.L().Warn("invalid reroll_every (must be ≥30s)", "profile", name, "value", p.RerollEvery)
		return
	}
	a.rerollMu.Lock()
	defer a.rerollMu.Unlock()
	if a.rerollCancel == nil {
		a.rerollCancel = map[string]context.CancelFunc{}
	}
	if cancel, ok := a.rerollCancel[name]; ok {
		cancel()
	}
	ctx, cancel := context.WithCancel(a.ctx)
	a.rerollCancel[name] = cancel
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				logger.L().Info("reroll: tick", "profile", name)
				if err := a.RerollProfile(name); err != nil {
					logger.L().Warn("reroll failed", "profile", name, "err", err)
				}
			}
		}
	}()
}

func (a *App) stopRerollTimer(name string) {
	a.rerollMu.Lock()
	defer a.rerollMu.Unlock()
	if cancel, ok := a.rerollCancel[name]; ok {
		cancel()
		delete(a.rerollCancel, name)
	}
}

// ProfileExternalIP returns the public IP for a running session.
func (a *App) ProfileExternalIP(name string) (string, error) {
	info, err := a.ProfileExternalIPInfo(name)
	if err != nil {
		return "", err
	}
	return info.IP, nil
}

// ProfileExternalIPInfo returns IP + geo + org for a running session.
//
// Geo lookups are cached per-IP for 10 minutes so repeated calls (from
// the dashboard, health probe, etc.) don't blow through ipinfo.io's
// rate limits when the IP hasn't changed.
func (a *App) ProfileExternalIPInfo(name string) (info engine.IPInfo, err error) {
	defer guiErr("ProfileExternalIPInfo", &err)
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return engine.IPInfo{}, fmt.Errorf("profile %q not running", name)
	}
	ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
	defer cancel()

	// Check cache first.
	a.geoMu.Lock()
	if a.geoCache == nil {
		a.geoCache = map[string]geoCacheEntry{}
	}
	a.geoMu.Unlock()

	// LOCAL-FIRST: kernel peer IP + GeoLite2 covers the common case
	// (single-hop VPN profiles) leak-free with no browser dependency.
	// Works for Firefox profiles too — no Chromium debug port needed.
	// Falls through to engine.ExternalIPInfo (CDP-driven) only when
	// local can't see the exit (Tor without consensus, multi-hop, no
	// tunnel device). That CDP path drives the running browser to
	// fetch ipinfo via its own real fingerprint.
	if li, ok := localHealthProbe(sess); ok && li.IP != "" {
		a.geoMu.Lock()
		a.geoCache[name] = geoCacheEntry{info: li, at: time.Now()}
		a.geoMu.Unlock()
		return li, nil
	}

	info, err = engine.Active().ExternalIPInfo(ctx, sess)
	if err != nil {
		// On transient failure (rate-limit, network blip), fall back
		// to a recent cached entry so the dashboard doesn't blank.
		// Only return cache entries < 60s old — older than that and
		// the user deserves to see the actual error rather than a
		// stale IP that may belong to a different exit by now.
		a.geoMu.Lock()
		if e, ok := a.geoCache[name]; ok && time.Since(e.at) < 60*time.Second {
			a.geoMu.Unlock()
			return e.info, nil
		}
		a.geoMu.Unlock()
		return engine.IPInfo{}, err
	}
	a.geoMu.Lock()
	a.geoCache[name] = geoCacheEntry{info: info, at: time.Now()}
	a.geoMu.Unlock()
	return info, nil
}

// Doctor runs preflight checks.
func (a *App) Doctor() ([]engine.Check, error) {
	return engine.Active().Doctor(a.ctx)
}

// TorCircuitsDTO is the GUI-facing view of a profile's Tor circuits.
type TorCircuitsDTO struct {
	Circuits []TorCircuitDTO `json:"circuits"`
}
type TorCircuitDTO struct {
	ID      string             `json:"id"`
	Status  string             `json:"status"`
	Purpose string             `json:"purpose"`
	Hops    []TorCircuitHopDTO `json:"hops"`
}
type TorCircuitHopDTO struct {
	Fingerprint string `json:"fingerprint"`
	Nickname    string `json:"nickname"`
}

// TorCircuits returns parsed Tor circuit info for a running profile.
//
// Uses engine.TorCircuitStatus (which goes through the userns RPC
// when applicable) instead of iterating sess.Backends — under the
// userns engine path the parent's Backends slice is empty since
// the actual *tor.Backend lives inside the userns child.
func (a *App) TorCircuits(name string) (TorCircuitsDTO, error) {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return TorCircuitsDTO{}, fmt.Errorf("profile %q not running", name)
	}
	if !chainHasTorBackend(sess) {
		return TorCircuitsDTO{}, fmt.Errorf("profile %q has no Tor hop in chain (chain=%v)", name, chainKinds(sess))
	}
	reply, err := engine.Active().TorCircuitStatus(sess)
	if err != nil {
		return TorCircuitsDTO{}, err
	}
	parsed := tor.ParseCircuits(reply)
	out := TorCircuitsDTO{Circuits: make([]TorCircuitDTO, 0, len(parsed))}
	for _, c := range parsed {
		dto := TorCircuitDTO{ID: c.ID, Status: c.Status, Purpose: c.Purpose}
		for _, h := range c.Hops {
			dto.Hops = append(dto.Hops, TorCircuitHopDTO{Fingerprint: h.Fingerprint, Nickname: h.Nickname})
		}
		out.Circuits = append(out.Circuits, dto)
	}
	return out, nil
}

// TorHopsDTO carries enriched circuit info: each hop with IP + geo so
// the dashboard can plot markers + a polyline trace.
type TorHopsDTO struct {
	Hops []TorHopGeoDTO `json:"hops"`
}
type TorHopGeoDTO struct {
	Fingerprint string `json:"fingerprint"`
	Nickname    string `json:"nickname"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	City        string `json:"city"`
	Loc         string `json:"loc"` // "lat,lon"
	Org         string `json:"org"`
}

// TorHopsTrace returns the hops of the first BUILT general circuit, with
// each hop's IP geo-resolved (cached). Used by the dashboard to plot the
// path on the world map.
func (a *App) TorHopsTrace(name string) (TorHopsDTO, error) {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return TorHopsDTO{}, fmt.Errorf("profile %q not running", name)
	}
	if !chainHasTorBackend(sess) {
		return TorHopsDTO{}, fmt.Errorf("profile %q has no Tor hop in chain (chain=%v)", name, chainKinds(sess))
	}
	reply, err := engine.Active().TorCircuitStatus(sess)
	if err != nil {
		return TorHopsDTO{}, err
	}
	circuits := tor.ParseCircuits(reply)
	// Prefer GENERAL+BUILT, fall back to any BUILT.
	var pick tor.Circuit
	found := false
	for _, c := range circuits {
		if c.Status == "BUILT" && c.Purpose == "GENERAL" {
			pick = c
			found = true
			break
		}
	}
	if !found {
		for _, c := range circuits {
			if c.Status == "BUILT" {
				pick = c
				found = true
				break
			}
		}
	}
	if !found {
		return TorHopsDTO{}, nil // no built circuits yet
	}

	out := TorHopsDTO{Hops: make([]TorHopGeoDTO, 0, len(pick.Hops))}
	for _, h := range pick.Hops {
		dto := TorHopGeoDTO{Fingerprint: h.Fingerprint, Nickname: h.Nickname}
		if ip, err := engine.Active().TorRelayIP(sess, h.Fingerprint); err == nil && ip != "" {
			dto.IP = ip
			geo, err := a.geoLookupIP(sess, ip)
			if err == nil {
				dto.Country = geo.Country
				dto.City = geo.City
				dto.Loc = geo.Loc
				dto.Org = geo.Org
			}
		}
		out.Hops = append(out.Hops, dto)
	}
	return out, nil
}

// geoLookupIP resolves an IP to geo via ipinfo.io, called through the
// session's network. Cached per-IP for 24h to spare ipinfo's free tier.
func (a *App) geoLookupIP(sess *engine.Session, ip string) (engine.IPInfo, error) {
	a.geoMu.Lock()
	if a.ipCache == nil {
		a.ipCache = map[string]geoCacheEntry{}
	}
	if e, ok := a.ipCache[ip]; ok && time.Since(e.at) < 24*time.Hour {
		a.geoMu.Unlock()
		return e.info, nil
	}
	a.geoMu.Unlock()

	// Issue a one-off ipinfo lookup *through the session's network* —
	// re-uses the session's egress (so VPN/Tor in scope, not the host's
	// default route).
	info, err := lookupIPThroughSession(sess, ip)
	if err != nil {
		return engine.IPInfo{}, err
	}
	a.geoMu.Lock()
	a.ipCache[ip] = geoCacheEntry{info: info, at: time.Now()}
	a.geoMu.Unlock()
	return info, nil
}

// ChainTraceDTO is the full path through Veil's chain plus any Tor relays
// plus the final exit, with each hop geo-located so the dashboard map can
// connect them with a polyline.
type ChainTraceDTO struct {
	Hops []TorHopGeoDTO `json:"hops"`
	Exit TorHopGeoDTO   `json:"exit"`
}

// ChainTrace returns geo info for every hop in a running profile's chain
// (VPN endpoint(s), proxy server(s), Tor relays) plus the final exit.
// All lookups are cached per-IP and routed through the session's network.
func (a *App) ChainTrace(name string) (ChainTraceDTO, error) {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return ChainTraceDTO{}, fmt.Errorf("profile %q not running", name)
	}
	out := ChainTraceDTO{}

	// Walk Veil's chain backends and collect endpoints.
	for i, b := range sess.Backends {
		ep, ok := b.(backends.EndpointReporter)
		if !ok {
			continue
		}
		for _, addr := range ep.Endpoints() {
			host := stripPort(addr)
			ip := host
			// If host is a hostname not an IP, resolve through the
			// session's network.
			if net.ParseIP(host) == nil {
				resolved, err := resolveHostThroughSession(sess, host)
				if err == nil && resolved != "" {
					ip = resolved
				}
			}
			label := fmt.Sprintf("%s #%d", b.Kind(), i+1)
			geo, err := a.geoLookupIP(sess, ip)
			h := TorHopGeoDTO{Nickname: label, IP: ip}
			if err == nil {
				h.Country = geo.Country
				h.City = geo.City
				h.Loc = geo.Loc
				h.Org = geo.Org
			}
			out.Hops = append(out.Hops, h)
		}

		// If this hop is Tor, also enumerate its internal relays.
		if tb, ok := b.(*tor.Backend); ok {
			port, cookie := tb.ControlInfo()
			if port > 0 {
				ctrl, err := dialTorControlForGUI(sess, port, cookie)
				if err == nil {
					reply, _ := ctrl.CircuitStatus()
					ctrl.Close()
					circuits := tor.ParseCircuits(reply)
					var pick tor.Circuit
					for _, c := range circuits {
						if c.Status == "BUILT" && c.Purpose == "GENERAL" {
							pick = c
							break
						}
					}
					if pick.ID == "" {
						for _, c := range circuits {
							if c.Status == "BUILT" {
								pick = c
								break
							}
						}
					}
					for _, h := range pick.Hops {
						ctrl2, err := dialTorControlForGUI(sess, port, cookie)
						if err != nil {
							continue
						}
						ip, _ := ctrl2.RelayIP(h.Fingerprint)
						ctrl2.Close()
						hop := TorHopGeoDTO{Fingerprint: h.Fingerprint, Nickname: h.Nickname, IP: ip}
						if ip != "" {
							geo, err := a.geoLookupIP(sess, ip)
							if err == nil {
								hop.Country = geo.Country
								hop.City = geo.City
								hop.Loc = geo.Loc
								hop.Org = geo.Org
							}
						}
						out.Hops = append(out.Hops, hop)
					}
				}
			}
		}
	}

	// Final exit: resolve via the standard ipinfo path (cached).
	if info, err := engine.Active().ExternalIPInfo(a.ctx, sess); err == nil {
		out.Exit = TorHopGeoDTO{
			Nickname: "exit",
			IP:       info.IP,
			Country:  info.Country,
			City:     info.City,
			Loc:      info.Loc,
			Org:      info.Org,
		}
	}
	return out, nil
}

func stripPort(addr string) string {
	if i := lastIndexByte(addr, ':'); i >= 0 {
		// Don't strip IPv6 (no brackets handling here for brevity)
		return addr[:i]
	}
	return addr
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TorNewCircuit forces Tor to use new circuits for subsequent connections.
//
// Routed through engine.TorNewCircuit so the userns-engine path works
// correctly (Backends slice in the parent's Session is empty under
// userns isolation — the actual *tor.Backend lives inside the userns
// child process. Engine RPC handles the indirection.)
func (a *App) TorNewCircuit(name string) error {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("profile %q not running", name)
	}
	if !chainHasTorBackend(sess) {
		return fmt.Errorf("profile %q has no Tor hop in chain (chain=%v)", name, chainKinds(sess))
	}
	return engine.Active().TorNewCircuit(sess)
}

// chainKinds is a small diagnostic helper — returns the chain hop
// kinds as a slice for inclusion in error messages so the user can
// see what veil thinks the chain looks like vs. what they expect.
func chainKinds(sess *engine.Session) []string {
	if sess == nil || sess.Profile == nil {
		return nil
	}
	out := make([]string, 0, len(sess.Profile.Chain))
	for _, h := range sess.Profile.Chain {
		out = append(out, string(h.Kind))
	}
	return out
}

// ProfileStats returns traffic byte/packet counters for a running profile.
func (a *App) ProfileStats(name string) (engine.TrafficStats, error) {
	a.mu.Lock()
	sess, ok := a.sessions[name]
	a.mu.Unlock()
	if !ok {
		return engine.TrafficStats{}, fmt.Errorf("profile %q not running", name)
	}
	return engine.Active().TrafficStats(sess)
}

// LogTail returns the most recent log content (~64 KB).
func (a *App) LogTail() (string, error) {
	return logger.Tail(64 * 1024)
}

// LogPath returns the on-disk path of the active log file.
func (a *App) LogPath() string {
	return logger.LogPath()
}

// Version returns the build-stamped Veil version string. Bound to JS so
// the About page can display it.
func (a *App) Version() string {
	return cliversion.Version
}

// License returns the current license status.
func (a *App) License() LicenseDTO {
	s := license.LoadFromDefault()
	return LicenseDTO{Tier: s.Tier.String(), Email: s.Email, Valid: s.Valid, Reason: s.Reason}
}

// InstallLicense writes a JWT token to the user's license path. The
// frontend pastes the token contents into a textarea and submits.
func (a *App) InstallLicense(token string) (lic LicenseDTO, err error) {
	defer guiErr("InstallLicense", &err)
	cfg, err := os.UserConfigDir()
	if err != nil {
		return LicenseDTO{}, err
	}
	dir := filepath.Join(cfg, "veil")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return LicenseDTO{}, err
	}
	path := filepath.Join(dir, "license.jwt")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)), 0o600); err != nil {
		return LicenseDTO{}, err
	}
	return a.License(), nil
}

// Presets returns available app presets.
func (a *App) Presets() []string { return launcher.Presets() }

// Personas returns all stored personas.
func (a *App) Personas() ([]*persona.Persona, error) {
	s, err := persona.DefaultStore()
	if err != nil {
		return nil, err
	}
	return s.LoadAll()
}

// DriftRow is one row of the persona-vs-observed comparison shown by
// `veil profile drift` and the GUI Drift view.
type DriftRow struct {
	Field    string `json:"field"`
	Claimed  string `json:"claimed"`
	Observed string `json:"observed"`
	Match    string `json:"match"` // "ok" | "DRIFT" | "(no claim)"
}

// ProfileDrift returns a comparison of the profile's claimed identity
// values against the live exit info. Mirror of the CLI `veil profile
// drift <name>` command for use in the GUI.
func (a *App) ProfileDrift(name string) (rows []DriftRow, err error) {
	defer guiErr("ProfileDrift", &err)
	a.mu.Lock()
	sess := a.sessions[name]
	a.mu.Unlock()
	if sess == nil {
		return nil, fmt.Errorf("profile %q is not running", name)
	}
	prof := sess.Profile
	personaName := prof.Persona
	if prof.ForgePersona && personaName == "" {
		personaName = prof.Name
	}
	var pers *persona.Persona
	if personaName != "" {
		if ps, err := persona.DefaultStore(); err == nil {
			pers, _ = ps.Load(personaName)
			if pers == nil && prof.ForgePersona {
				pers, _ = ps.ForgeAndStore(personaName)
			}
		}
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	// Same local-first path as ProfileExternalIPInfo: try the kernel
	// peer IP + GeoLite2 first (works for single-hop VPN, no browser
	// dependency), fall back to ExternalIPInfo (CDP-driven probe via
	// the running browser) only when local can't see the exit.
	var info engine.IPInfo
	if li, ok := localHealthProbe(sess); ok && li.IP != "" {
		info = li
	} else {
		info, err = engine.Active().ExternalIPInfo(ctx, sess)
		if err != nil {
			return nil, err
		}
	}
	row := func(label, want, got string) DriftRow {
		match := "(no claim)"
		switch {
		case want == "":
			match = "(no claim)"
		case strings.EqualFold(want, got):
			match = "ok"
		default:
			match = "DRIFT"
		}
		return DriftRow{Field: label, Claimed: want, Observed: got, Match: match}
	}
	out := []DriftRow{}
	wantCountry := strings.ToUpper(prof.RequireExitCountry)
	if wantCountry == "" && pers != nil {
		wantCountry = strings.ToUpper(pers.Country)
	}
	out = append(out, row("country", wantCountry, strings.ToUpper(info.Country)))
	out = append(out, row("city", prof.RequireExitCity, info.City))
	gotASN := ""
	if i := strings.Index(info.Org, " "); i > 0 {
		gotASN = info.Org[:i]
	}
	out = append(out, row("asn", prof.RequireExitASN, gotASN))
	out = append(out, row("ip", prof.RequireExitIP, info.IP))
	tzWant := ""
	if pers != nil {
		tzWant = pers.Timezone
	}
	out = append(out, row("timezone", tzWant, info.Timezone))
	return out, nil
}

// ForgePersona produces a deterministic forged persona from the given
// name without saving. Frontend uses this for the "Preview" button on
// the New Profile form so users can see what they'll get before
// committing. Same name always yields the same persona.
// personaExitCountry resolves the country the profile's persona will
// claim. Named persona → load from store. forge_persona → reproduce
// the engine's forge call with the same name+constraints+seed so what
// we lock to matches what the engine actually picks at launch.
func personaExitCountry(p *profile.Profile) string {
	if p.Persona != "" {
		store, err := persona.DefaultStore()
		if err == nil {
			if pers, err := store.Load(p.Persona); err == nil && pers != nil {
				return strings.ToUpper(strings.TrimSpace(pers.Country))
			}
		}
		return ""
	}
	if p.ForgePersona {
		pers := persona.ForgeWith(p.Name, persona.ForgeOptions{
			FormFactor: p.ForgeFormFactor,
			OS:         p.ForgeOS,
			Browser:    p.ForgeBrowser,
			Country:    p.ForgeCountry,
			Seed:       p.ForgeSeed,
		})
		if pers != nil {
			return strings.ToUpper(strings.TrimSpace(pers.Country))
		}
	}
	return ""
}

func (a *App) ForgePersona(name string) (*persona.Persona, error) {
	if err := license.RequirePro("persona forge"); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("name required")
	}
	p := persona.Forge(name)
	if p == nil {
		return nil, fmt.Errorf("forge returned nil")
	}
	return p, nil
}

// ForgePersonaWith is ForgePersona + per-call constraints (form
// factor, OS, browser, country) and a re-roll seed. The frontend
// uses this for the "configure forge" UI so users can pick:
//   - desktop vs mobile
//   - specific OS within form factor
//   - specific browser within OS
//   - country (for locale/timezone matching)
//   - re-roll seed (rotate without renaming the profile)
//
// Returns a structured error when the option combination is
// incoherent (e.g. desktop+android, ios+firefox) so the frontend
// can surface an actionable hint immediately.
func (a *App) ForgePersonaWith(name string, opts persona.ForgeOptions) (*persona.Persona, error) {
	if err := license.RequirePro("persona forge"); err != nil {
		return nil, err
	}
	return persona.ForgeWithError(name, opts)
}

// ForgeCatalog returns the universe of GUI-pickable forge options
// (form factors, OSes, browsers, countries) along with the
// dependency map (which browsers per OS, which OSes per form
// factor). Frontend uses this to populate cascading dropdowns
// without hardcoding the lists in JS.
func (a *App) ForgeCatalog() persona.ForgeCatalog {
	return persona.Catalog()
}

// SavePersona writes a persona.
func (a *App) SavePersona(p persona.Persona) error {
	if err := license.RequirePro("persona system"); err != nil {
		return err
	}
	s, err := persona.DefaultStore()
	if err != nil {
		return err
	}
	return s.Save(&p)
}

// DeletePersona removes a persona.
func (a *App) DeletePersona(name string) error {
	s, err := persona.DefaultStore()
	if err != nil {
		return err
	}
	return s.Delete(name)
}

// BulkImportWG bulk-imports WireGuard .conf files from a directory or
// single file. Returns the created profile names.
func (a *App) BulkImportWG(path, preset string, killSwitch bool) ([]string, error) {
	if a.store == nil {
		return nil, fmt.Errorf("profile store not ready")
	}
	if preset == "" {
		preset = "firefox"
	}
	return a.store.BulkImportWG(path, preset, "", killSwitch)
}

// BulkImportOVPN does the same for OpenVPN .ovpn files.
func (a *App) BulkImportOVPN(path, preset string, killSwitch bool) ([]string, error) {
	if a.store == nil {
		return nil, fmt.Errorf("profile store not ready")
	}
	if preset == "" {
		preset = "firefox"
	}
	return a.store.BulkImportOVPN(path, preset, "", killSwitch)
}

// BrowseFile opens the OS file picker and returns the absolute path
// the user selected, or "" if they cancelled.
//
// kind selects the dialog filter:
//   "wg"     -> WireGuard configs (.conf)
//   "ovpn"   -> OpenVPN configs (.ovpn)
//   "binary" -> any executable (no extension filter)
//   ""       -> any file
func (a *App) BrowseFile(kind, defaultDir string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("dialog unavailable: GUI not initialised")
	}
	opts := wruntime.OpenDialogOptions{
		Title:            "Select file",
		DefaultDirectory: defaultDir,
	}
	switch kind {
	case "wg":
		opts.Title = "Select WireGuard config"
		opts.Filters = []wruntime.FileFilter{{DisplayName: "WireGuard (*.conf)", Pattern: "*.conf"}}
	case "ovpn":
		opts.Title = "Select OpenVPN config"
		opts.Filters = []wruntime.FileFilter{{DisplayName: "OpenVPN (*.ovpn)", Pattern: "*.ovpn"}}
	case "binary":
		opts.Title = "Select executable"
	}
	path, err := wruntime.OpenFileDialog(a.ctx, opts)
	if err != nil {
		return "", err
	}
	return path, nil
}

// BrowseDirectory opens the OS directory picker. Returns "" if cancelled.
func (a *App) BrowseDirectory(defaultDir string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("dialog unavailable: GUI not initialised")
	}
	return wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{
		Title:            "Select directory",
		DefaultDirectory: defaultDir,
	})
}

// AvailableBackends returns the backend kinds this build supports.
func (a *App) AvailableBackends() []string {
	return []string{
		string(profile.BackendDirect),
		string(profile.BackendSOCKS5),
		string(profile.BackendHTTP),
		string(profile.BackendWireGuard),
		string(profile.BackendOpenVPN),
		string(profile.BackendTor),
	}
}
