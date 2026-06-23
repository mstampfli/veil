// Package profile defines Veil profiles and their persistence.
package profile

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mstampfli/veil/internal/validate"
)

// AntiFingerprintMode controls which fingerprint-spoofing layers are
// active when a profile launches. Two tiers are exposed so users can
// choose their trust budget:
//
//	"basic"  — JS persona extension + TCP persona + time namespace.
//	           No TLS interception, no CA install. Looks like a normal
//	           Firefox/Brave user with extra hardening; cohort blends
//	           with millions of regular browser users. The browser's
//	           native TLS handshake reaches destinations as-is.
//
//	"strict" — Everything in basic, plus tls_mitm with a per-profile
//	           CA. The browser TLS handshake is terminated locally and
//	           re-emitted with a uTLS-shaped fingerprint matching the
//	           persona. Closes the TLS layer leak entirely. Requires
//	           the user to accept a per-profile root CA installed only
//	           into the browser data dir Veil owns (no system-wide
//	           trust changes).
//
// Off (zero value) disables anti-fingerprint behavior entirely.
//
// Backwards compatibility: YAML/JSON decoding accepts the legacy
// boolean form. `anti_fingerprint: true` decodes to "basic" — the
// safer default — and `false` decodes to off. Existing profile files
// keep working unchanged.
type AntiFingerprintMode string

const (
	AFOff    AntiFingerprintMode = ""
	AFBasic  AntiFingerprintMode = "basic"
	AFStrict AntiFingerprintMode = "strict"
)

// IsOn reports whether anti-fingerprint behavior is active at any tier.
func (m AntiFingerprintMode) IsOn() bool { return m == AFBasic || m == AFStrict }

// IsStrict reports whether the strict tier is selected (tls_mitm + per-profile CA).
func (m AntiFingerprintMode) IsStrict() bool { return m == AFStrict }

// IsBasic reports whether the basic tier is selected.
func (m AntiFingerprintMode) IsBasic() bool { return m == AFBasic }

// UnmarshalYAML accepts boolean or string form. See AntiFingerprintMode docs.
func (m *AntiFingerprintMode) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		*m = AFOff
		return nil
	}
	switch value.Tag {
	case "!!bool":
		var b bool
		if err := value.Decode(&b); err != nil {
			return err
		}
		if b {
			*m = AFBasic
		} else {
			*m = AFOff
		}
		return nil
	default:
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		return m.fromString(s)
	}
}

// UnmarshalJSON mirrors YAML decoding for JSON profile files.
func (m *AntiFingerprintMode) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		*m = AFOff
		return nil
	}
	if s == "true" {
		*m = AFBasic
		return nil
	}
	if s == "false" {
		*m = AFOff
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return m.fromString(s)
}

func (m *AntiFingerprintMode) fromString(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none", "no", "false", "0":
		*m = AFOff
	case "true", "1", "on", "yes", "basic", "lite", "blend":
		*m = AFBasic
	case "strict", "full", "coherent", "ultra":
		*m = AFStrict
	default:
		return fmt.Errorf("anti_fingerprint: invalid value %q (want basic|strict|true|false)", s)
	}
	return nil
}

// BackendKind enumerates supported tunnel backends.
type BackendKind string

const (
	BackendDirect    BackendKind = "direct"
	BackendSOCKS5    BackendKind = "socks5"
	BackendHTTP      BackendKind = "http"
	BackendWireGuard BackendKind = "wireguard"
	BackendOpenVPN   BackendKind = "openvpn"
	BackendTor       BackendKind = "tor"
	// BackendTLSMITM is a local TLS-intercepting proxy that re-handshakes
	// outgoing connections with a chosen browser fingerprint via uTLS.
	BackendTLSMITM BackendKind = "tls_mitm"
)

// Backend is a single hop in a profile's chain.
type Backend struct {
	Kind BackendKind `yaml:"kind"        json:"kind"`

	// SOCKS5 / HTTP
	Host     string `yaml:"host,omitempty"     json:"host,omitempty"`
	Port     int    `yaml:"port,omitempty"     json:"port,omitempty"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// HostPool: list of "host:port" entries to random-pick per launch.
	// Same idea as ConfigPaths but for proxy backends — give Veil a
	// pool of SOCKS5/HTTP servers and let it rotate.
	HostPool []string `yaml:"host_pool,omitempty" json:"host_pool,omitempty"`
	// UnencryptedAck is the explicit opt-in for SOCKS5/HTTP hops that
	// would otherwise send credentials in cleartext over a public
	// network. SOCKS5 auth (and HTTP Basic) is plaintext by spec.
	// Veil refuses to launch a chain that:
	//   - has a SOCKS5 or HTTP hop with username/password set,
	//   - whose host is NOT loopback / netns-loopback,
	//   - AND has no preceding encrypting hop (wireguard / openvpn /
	//     tor / ssh / tls_mitm-with-tunnel) to carry the auth
	//     handshake.
	// Setting this true asserts the user knows the credentials will
	// travel in cleartext and accepts it (typical case: commercial
	// provider that whitelists the source IP, so the password isn't
	// actually a secret on the wire). Loud opt-in by design — silent
	// plaintext-cred leakage is the kind of thing Veil is supposed to
	// prevent, not enable.
	UnencryptedAck bool `yaml:"unencrypted_ack,omitempty" json:"unencrypted_ack,omitempty"`

	// WireGuard / OpenVPN — path to a single config OR inline contents.
	ConfigPath string `yaml:"config_path,omitempty" json:"config_path,omitempty"`
	ConfigData string `yaml:"config_data,omitempty" json:"config_data,omitempty"`
	// ConfigPaths: pool of candidate configs. When non-empty the
	// backend picks one uniformly at random per launch (so the apparent
	// exit IP rotates instead of pinning to one server). Set a single
	// entry — or use ConfigPath — for a fixed endpoint.
	ConfigPaths []string `yaml:"config_paths,omitempty" json:"config_paths,omitempty"`

	// Mandatory marks a hop as required when RandomizeChain is on.
	// Optional hops may be skipped on a given launch.
	Mandatory bool `yaml:"mandatory,omitempty" json:"mandatory,omitempty"`
	Optional  bool `yaml:"optional,omitempty"  json:"optional,omitempty"`

	// Tor
	ManagedTor bool   `yaml:"managed_tor,omitempty" json:"managed_tor,omitempty"`
	SocksAddr  string `yaml:"socks_addr,omitempty"  json:"socks_addr,omitempty"`
	// TorExitCountry: ISO-3166 alpha-2 (e.g. "ch", "de", "us"). When
	// set, torrc gets `ExitNodes {cc} StrictNodes 1` so circuits exit
	// only via that country. Apparent location stays predictable,
	// without adding a third-party server.
	TorExitCountry string `yaml:"tor_exit_country,omitempty" json:"tor_exit_country,omitempty"`

	// TLSFingerprint (tls_mitm only): browser TLS fingerprint to mimic
	// for outgoing connections — "chrome" / "firefox" / "safari" /
	// "ios" / "edge" / "tor" / "random". Default: "chrome".
	TLSFingerprint string `yaml:"tls_fingerprint,omitempty" json:"tls_fingerprint,omitempty"`
	// Transparent (Tor only): when nil-or-true, all TCP and DNS in the
	// namespace is REDIRECTed through Tor's TransPort/DNSPort and UDP
	// is dropped — apps can't bypass Tor even if they ignore proxy
	// settings. Set false to disable (e.g. for apps that need UDP).
	Transparent *bool `yaml:"transparent,omitempty" json:"transparent,omitempty"`
	// UseBridges (Tor only): turns on UseBridges and pushes the Bridges
	// list into torrc. Required when the local network blocks direct
	// Tor (censorship circumvention).
	UseBridges bool `yaml:"use_bridges,omitempty" json:"use_bridges,omitempty"`
	// Bridges: each entry is a full Bridge line as Tor expects, e.g.
	//   "obfs4 1.2.3.4:443 FINGERPRINT cert=... iat-mode=0"
	//   "snowflake 192.0.2.3:80 FP fingerprint=..."
	Bridges []string `yaml:"bridges,omitempty" json:"bridges,omitempty"`
	// PluggableTransport: path or name of the pluggable transport
	// binary to use, e.g. "obfs4proxy" or "/usr/bin/snowflake-client".
	// Empty falls back to system defaults.
	PluggableTransport string `yaml:"pluggable_transport,omitempty" json:"pluggable_transport,omitempty"`
}

// App describes what to launch in the namespace.
type App struct {
	Binary string   `yaml:"binary"          json:"binary"`
	Args   []string `yaml:"args,omitempty"  json:"args,omitempty"`
	// Preset overrides Binary/Args with a built-in (e.g. "firefox", "chromium").
	Preset string `yaml:"preset,omitempty" json:"preset,omitempty"`
}

// EnvOverrides are environment overrides for the launched app.
//
// AutoFromExit, when true, asks the engine to derive TZ and Lang from the
// session's exit country (looked up via the same IP geo path as veil ip).
// User-set TZ/Lang values still win.
type EnvOverrides struct {
	TZ           string            `yaml:"tz,omitempty"            json:"tz,omitempty"`
	Lang         string            `yaml:"lang,omitempty"          json:"lang,omitempty"`
	LCAll        string            `yaml:"lc_all,omitempty"        json:"lc_all,omitempty"`
	AutoFromExit bool              `yaml:"auto_from_exit,omitempty" json:"auto_from_exit,omitempty"`
	Custom       map[string]string `yaml:"custom,omitempty"        json:"custom,omitempty"`
}

// Profile is a complete Veil profile.
type Profile struct {
	Name        string       `yaml:"name"                  json:"name"`
	Description string       `yaml:"description,omitempty" json:"description,omitempty"`
	Chain       []Backend    `yaml:"chain"                 json:"chain"`
	App         App          `yaml:"app"                   json:"app"`
	DataDir     string       `yaml:"data_dir,omitempty"    json:"data_dir,omitempty"`
	DNS         []string     `yaml:"dns,omitempty"         json:"dns,omitempty"`
	Env         EnvOverrides `yaml:"env,omitempty"         json:"env,omitempty"`
	KillSwitch  bool         `yaml:"kill_switch"           json:"kill_switch"`
	// AntiFingerprint controls browser-side fingerprint spoofing.
	// See AntiFingerprintMode for the tier semantics. Accepts the
	// legacy boolean form for backwards compatibility — `true` maps
	// to "basic".
	AntiFingerprint AntiFingerprintMode `yaml:"anti_fingerprint,omitempty" json:"anti_fingerprint,omitempty"`
	// Persona is the name of a persona definition (in
	// ~/.config/veil/personas/<name>.yaml) to apply at launch — UA,
	// Accept-Language, TZ, locale, screen, platform. Persona overrides
	// AntiFingerprint's uniform values when both are set.
	Persona string `yaml:"persona,omitempty" json:"persona,omitempty"`
	// ForgePersona, when true, deterministically generates a unique
	// realistic persona for this profile (named after the profile if
	// Persona is empty, otherwise after Persona). Same profile name →
	// same forged persona forever; different profiles → different
	// real-looking identities. This is the anti-detect mode: each
	// profile looks like a different real person, no cross-profile
	// correlation by fingerprint.
	ForgePersona bool `yaml:"forge_persona,omitempty" json:"forge_persona,omitempty"`
	// ForgeOptions narrows the forge result. Stored on the profile so
	// launch-time forging produces the same shape the user previewed
	// in the GUI. Empty fields fall through to deterministic auto-pick.
	// Validated as a coherent combination at profile-load time
	// (desktop+android etc. is rejected). See persona.ForgeOptions.
	ForgeFormFactor string `yaml:"forge_form_factor,omitempty" json:"forge_form_factor,omitempty"`
	ForgeOS         string `yaml:"forge_os,omitempty" json:"forge_os,omitempty"`
	ForgeBrowser    string `yaml:"forge_browser,omitempty" json:"forge_browser,omitempty"`
	ForgeCountry    string `yaml:"forge_country,omitempty" json:"forge_country,omitempty"`
	ForgeSeed       string `yaml:"forge_seed,omitempty" json:"forge_seed,omitempty"`
	// LockedEndpoint, when true, enforces that the network exit IP
	// geolocates to the persona's claimed Country. If the actual exit
	// is in a different country, the launch FAILS rather than
	// silently letting the persona-vs-IP mismatch leak (a strong
	// correlation signal across sessions). Use this for investigation
	// opsec where persona consistency is more important than
	// reachability — better to fail to launch than to launch with a
	// broken identity.
	LockedEndpoint bool `yaml:"locked_endpoint,omitempty" json:"locked_endpoint,omitempty"`
	// RequireExitCountry overrides persona.Country for the locked-
	// endpoint check (e.g. you want a German persona but actually
	// exit through the Netherlands because that's where your
	// trusted Mullvad server lives). ISO 3166-1 alpha-2.
	RequireExitCountry string `yaml:"require_exit_country,omitempty" json:"require_exit_country,omitempty"`
	// RequireExitCity, RequireExitASN, RequireExitIP — finer-grained
	// pinning. Each is an additional check on top of the country
	// match. Use as many as you have stable values for:
	//
	//   require_exit_city: "Berlin"           — city-level
	//   require_exit_asn:  "AS9009"           — ASN match (Mullvad's ASN)
	//   require_exit_ip:   "193.32.249.50"    — exact IP (most stable)
	//
	// IP pinning is the gold standard for opsec — same IP every
	// session means no /24, ASN, city, or country drift can leak.
	// Achievable with: dedicated VPS per identity, residential proxy
	// with sticky-session, or VPN provider's "static IP" addon.
	RequireExitCity string `yaml:"require_exit_city,omitempty" json:"require_exit_city,omitempty"`
	RequireExitASN  string `yaml:"require_exit_asn,omitempty" json:"require_exit_asn,omitempty"`
	RequireExitIP   string `yaml:"require_exit_ip,omitempty" json:"require_exit_ip,omitempty"`
	// ScheduleWindow restricts when this profile can launch, expressed
	// in the persona's timezone. Format "HH:MM-HH:MM" (e.g. "08:00-22:00").
	// A Berlin user opening a session at 03:00 Berlin time is a
	// behavioral inconsistency. Empty = no schedule guard.
	ScheduleWindow string `yaml:"schedule_window,omitempty" json:"schedule_window,omitempty"`
	// RandomizeChain shuffles the chain (within validation rules) on
	// each launch, picking a random subset of optional hops. Mandatory
	// hops always run.
	RandomizeChain bool `yaml:"randomize_chain,omitempty" json:"randomize_chain,omitempty"`
	// RerollEvery is a Go time.Duration string (e.g. "30m", "1h"). When
	// non-empty Veil tears down + relaunches the profile at this
	// interval — fresh chain randomization, fresh endpoint pick. Empty
	// = no auto-reroll. The user can always trigger a reroll manually.
	RerollEvery string `yaml:"reroll_every,omitempty" json:"reroll_every,omitempty"`
	// TCPPersona normalizes the namespace's TCP/IP stack fingerprint
	// to match a target OS — closes p0f / nmap-style passive OS
	// detection. One of: "windows", "macos", "linux", "ios",
	// "android". Empty = leave default (Linux).
	TCPPersona string `yaml:"tcp_persona,omitempty" json:"tcp_persona,omitempty"`
	// CPUThrottle limits the launched app's CPU usage so JavaScript
	// performance benchmarks report a uniform slow speed regardless of
	// real hardware. Format: percent of one core (e.g. "30%") or
	// "<quota>/<period>" microseconds (e.g. "30000/100000"). Empty =
	// no throttle.
	CPUThrottle string `yaml:"cpu_throttle,omitempty" json:"cpu_throttle,omitempty"`
	// BehavioralJitter intercepts keyboard events at the kernel layer
	// (Linux uinput) and replays them with random per-event timing
	// offsets so keystroke-dynamics fingerprinting can't profile the
	// physical typist. Linux only for now (Windows/macOS planned).
	// While active, ALL keyboard input on the host is jittered, not
	// just input to the launched app.
	BehavioralJitter bool `yaml:"behavioral_jitter,omitempty" json:"behavioral_jitter,omitempty"`
	// MouseJitter does the same for mouse movement: ±1 px noise on a
	// fraction of REL_X/REL_Y events plus 0–3 ms timing jitter per event.
	// Defeats mouse-curvature and inter-event-delay fingerprinting.
	// Linux only for now. While active, ALL host mouse input is jittered,
	// not just input to the launched app.
	MouseJitter bool `yaml:"mouse_jitter,omitempty" json:"mouse_jitter,omitempty"`

	// Verified records the ground-truth state captured on the most
	// recent successful launch — what the actual exit IP / country was.
	// Locked-endpoint enforcement compares against these fields, not
	// the pre-flight guess from the WG config endpoint.
	//
	// VerifiedIP / VerifiedCountry are written by the engine on the
	// first successful launch where:
	//   - the chain came up,
	//   - actual exit was queried, and
	//   - if forge_persona was set, exit country matched persona country.
	// On every subsequent launch the engine re-verifies actual exit
	// matches these — drift = fail-closed.
	//
	// VerifiedAt is the timestamp of the last successful verification.
	// Empty / zero = profile has never verified — strict mode treats
	// this as "needs first-launch sanity check".
	VerifiedIP      string    `yaml:"verified_ip,omitempty" json:"verified_ip,omitempty"`
	VerifiedCountry string    `yaml:"verified_country,omitempty" json:"verified_country,omitempty"`
	VerifiedAt      time.Time `yaml:"verified_at,omitempty" json:"verified_at,omitempty"`

	// GeoUnknownPolicy controls behavior when GeoIP can't resolve a
	// country (database miss, brand-new IP allocation, hostname-only
	// endpoint that we refuse to DNS-resolve, etc.):
	//
	//   "" or "warn"  — log warning, country check skipped, proceed
	//   "fail"        — refuse to launch (right for investigation opsec)
	//   "fallback"    — query ipinfo.io as last resort (back to leak surface)
	GeoUnknownPolicy string `yaml:"geo_unknown_policy,omitempty" json:"geo_unknown_policy,omitempty"`

	// LockCountry / LockASN / LockIP are independent opt-ins for what
	// the locked-endpoint check enforces. Composable — any subset can
	// be on, all on = strictest. Empty target fields auto-derive (or
	// auto-capture) only for the dimension that's locked:
	//
	//   LockCountry: enforce country match. RequireExitCountry empty?
	//                derive from persona.Country at launch.
	//   LockASN:     enforce ASN match. RequireExitASN empty? capture
	//                first observed ASN on first launch.
	//   LockIP:      enforce exact IP match. RequireExitIP empty?
	//                capture first observed IP on first launch.
	//                Rejected for Tor profiles (exits rotate per
	//                circuit; pinning the first one is meaningless).
	//
	// LockMode is the legacy single-select. Kept for backward compat:
	// when LockMode is set on an old profile, Validate translates it
	// into the bool flags and clears LockMode. New profiles should
	// use the bools directly.
	LockCountry bool   `yaml:"lock_country,omitempty" json:"lock_country,omitempty"`
	LockASN     bool   `yaml:"lock_asn,omitempty"     json:"lock_asn,omitempty"`
	LockIP      bool   `yaml:"lock_ip,omitempty"      json:"lock_ip,omitempty"`
	LockMode    string `yaml:"lock_mode,omitempty"    json:"lock_mode,omitempty"`

	// DNSMatchExit forces the browser's DNS to travel via DoH through
	// the chain, terminating at an anycast resolver (Mullvad by default).
	// The DoH endpoint is BGP-announced from many PoPs; from the chain's
	// exit POV the route hits the PoP nearest to that exit, so the
	// resolver IP visible to upstream auth NS records geographically
	// matches the exit IP. Whoer-style "DNS doesn't match exit" tests
	// then pass without weakening the leak guarantee — the DoH packets
	// still travel inside the tunnel and the transparent DNS REDIRECT
	// stays in place as a safety net for any process that bypasses the
	// browser's DoH config.
	//
	// Requires the chain to contain at least one tunnel hop (wireguard,
	// openvpn, tor, ssh) — without one, DoH packets travel direct to
	// the resolver from the host's real network, leaking the host IP
	// AND geographically matching the host (defeating the purpose).
	// Validation rejects the unsafe configuration.
	DNSMatchExit bool `yaml:"dns_match_exit,omitempty" json:"dns_match_exit,omitempty"`
	// DNSMatchEndpoint is the DoH URL used when DNSMatchExit is on.
	// Empty = "https://194.242.2.2/dns-query" (Mullvad). Custom
	// values must use an IP literal in the host portion to avoid a
	// chicken-and-egg DNS lookup (we have no DNS until DoH is up).
	DNSMatchEndpoint string `yaml:"dns_match_endpoint,omitempty" json:"dns_match_endpoint,omitempty"`

	// DNSProxy spawns an in-netns DoH proxy (cloudflared) at chain
	// bring-up that intercepts every UDP/53 + TCP/53 in the namespace
	// and forwards the query as DoH to the configured upstream.
	// Without this, browser DNS uses DoH (when DNSMatchExit is on)
	// but side queries — OCSP, captive-portal probes, cert
	// revocation, browser background tasks — fall through to Tor's
	// DNSPort + the exit relay's upstream resolver, which leaks to
	// whatever resolver the exit operator configured (often 8.8.8.8
	// or a generic ISP DNS). With DNSProxy on, every DNS query in
	// the netns becomes DoH-encrypted to the same upstream — anti-
	// fraud sees a single consistent resolver IP, no fragmentation.
	//
	// Requires the `cloudflared` binary to be installed; the engine
	// hard-fails launch if it can't find one.
	DNSProxy bool `yaml:"dns_proxy,omitempty" json:"dns_proxy,omitempty"`
	// DNSProxyUpstream is the DoH URL cloudflared forwards to. When
	// empty, falls back to DNSMatchEndpoint (so the same resolver is
	// used for both browser DoH and the netns proxy). Must be an IP
	// literal — no DNS available to bootstrap the resolver's host.
	DNSProxyUpstream string `yaml:"dns_proxy_upstream,omitempty" json:"dns_proxy_upstream,omitempty"`

	// GeoVerificationMode controls how Veil verifies the actual exit:
	//
	//   "" or "local"  — peer IP from kernel + offline GeoLite2 lookup.
	//                    Zero external query, zero leak. Default.
	//   "probe-once"   — opt-in for multi-hop: ONE ipinfo query at first
	//                    launch, captures exit IP, enforced locally
	//                    forever after.
	//   "trust"        — no verification (commercial-anti-detect style).
	GeoVerificationMode string `yaml:"geo_verification_mode,omitempty" json:"geo_verification_mode,omitempty"`

	CreatedAt       time.Time `yaml:"created_at,omitempty"       json:"created_at,omitempty"`
	UpdatedAt       time.Time `yaml:"updated_at,omitempty"       json:"updated_at,omitempty"`

	// StrictMITMAcceptedAt records when the user accepted the
	// per-profile TLS interception CA install for strict-tier
	// anti-fingerprint. Zero = never accepted; the GUI must prompt and
	// store consent before LaunchProfile will bring up a strict-tier
	// chain. Per-profile (not global) so each profile's CA gets its
	// own informed acknowledgement.
	StrictMITMAcceptedAt time.Time `yaml:"strict_mitm_accepted_at,omitempty" json:"strict_mitm_accepted_at,omitempty"`
}

// NeedsStrictTierConsent reports whether LaunchProfile should refuse
// to bring this profile up until the user has acknowledged the
// per-profile CA install. Only relevant for strict tier — basic
// installs no CA.
func (p *Profile) NeedsStrictTierConsent() bool {
	return p.AntiFingerprint.IsStrict() && p.StrictMITMAcceptedAt.IsZero()
}

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

// Validate returns nil if the profile is internally consistent.
//
// Routes through the centralized validate package for fields that
// have well-defined formats (name, country, ASN, IP, schedule window,
// path, exec args). Backend-specific checks stay in Backend.Validate.
func (p *Profile) Validate() error {
	if err := validate.Name(p.Name); err != nil {
		return fmt.Errorf("profile name: %w", err)
	}
	if err := validate.Country(p.RequireExitCountry); err != nil {
		return fmt.Errorf("profile.require_exit_country: %w", err)
	}
	if err := validate.ASN(p.RequireExitASN); err != nil {
		return fmt.Errorf("profile.require_exit_asn: %w", err)
	}
	if err := validate.IP(p.RequireExitIP); err != nil {
		return fmt.Errorf("profile.require_exit_ip: %w", err)
	}
	if err := validate.ScheduleWindow(p.ScheduleWindow); err != nil {
		return fmt.Errorf("profile.schedule_window: %w", err)
	}
	if err := validate.AbsPath(p.DataDir); err != nil {
		return fmt.Errorf("profile.data_dir: %w", err)
	}
	for i, a := range p.App.Args {
		if err := validate.ExecArg(a); err != nil {
			return fmt.Errorf("profile.app.args[%d]: %w", i, err)
		}
	}
	if len(p.Chain) == 0 {
		return errors.New("profile must have at least one backend in chain")
	}
	for i, b := range p.Chain {
		if err := b.Validate(); err != nil {
			return fmt.Errorf("chain[%d]: %w", i, err)
		}
	}
	if p.App.Binary == "" && p.App.Preset == "" {
		return errors.New("profile must specify app.binary or app.preset")
	}
	// AntiFingerprint and Persona used to be mutually exclusive
	// (the comment used to say "RFP zeroes out canvas/screen/TZ at
	// the same time persona pins them"). That was wrong: they share
	// the SAME machinery (tls_mitm, HTTP mediators, persona
	// extension) and only differ in what VALUES feed the extension.
	//
	//   - anti_fingerprint: extension uses generic-blend values
	//   - persona / forge_persona: extension uses the persona's
	//     specific values
	//
	// Both modes need TLS spoofing (uTLS), HTTP-layer rewriting,
	// and JS overrides. Allowing them together means a "persona"
	// profile gets the strict-tier TLS protection too — which it
	// definitely needs (a persona claiming Chrome-on-Windows must
	// emit a Chrome-on-Windows TLS handshake or the persona is
	// instantly contradicted at L4).
	//
	// When both are set, persona wins for value selection (the
	// persona is more specific). The MITM hop is auto-inserted
	// for either trigger via PropagateAntiFingerprintMITM.

	// AntiFingerprint without a kill switch is a self-defeating
	// configuration: cohort blending gives the same browser-side
	// fingerprint as every other RFP user, but the moment the tunnel
	// drops, traffic exits with the host's real IP — which IS uniquely
	// identifying. Forcing kill_switch on aligns the user's intent
	// ("look like everyone else") with the network guarantees that
	// make it true. Honest framing: this is what makes Windows
	// AntiFingerprint enforceable end-to-end.
	if p.AntiFingerprint.IsOn() && !p.KillSwitch {
		return errors.New("anti_fingerprint requires kill_switch=true — cohort blending is meaningless if a tunnel drop leaks the host IP")
	}

	// dns_match_exit requires at least one tunnel hop in the chain.
	// Without one, DoH packets travel from the host's real network
	// straight to the anycast resolver, leaking the host's geo and
	// (worse) making whoer "match" because both DNS and HTTP egress
	// the same real host. That's the exact opposite of the intent.
	if p.DNSMatchExit {
		hasTunnel := false
		for _, b := range p.Chain {
			switch b.Kind {
			case BackendWireGuard, BackendOpenVPN, BackendTor:
				hasTunnel = true
			}
		}
		if !hasTunnel {
			return errors.New("dns_match_exit=true requires a wireguard / openvpn / tor hop in the chain — without a tunnel, DoH packets reveal the host directly")
		}
		if ep := strings.TrimSpace(p.DNSMatchEndpoint); ep != "" {
			u, err := url.Parse(ep)
			if err != nil || u.Scheme != "https" {
				return fmt.Errorf("dns_match_endpoint %q must be an https:// URL", ep)
			}
			if net.ParseIP(u.Hostname()) == nil {
				return fmt.Errorf("dns_match_endpoint host must be an IP literal (got %q) — DoH bootstrap can't depend on DNS", u.Hostname())
			}
		}
	}

	// dns_proxy validation — same IP-literal requirement as
	// dns_match_endpoint, since cloudflared can't bootstrap its
	// upstream via DNS (chicken-and-egg).
	if p.DNSProxy {
		ep := strings.TrimSpace(p.DNSProxyUpstream)
		if ep == "" {
			ep = strings.TrimSpace(p.DNSMatchEndpoint)
		}
		if ep != "" {
			u, err := url.Parse(ep)
			if err != nil || u.Scheme != "https" {
				return fmt.Errorf("dns_proxy_upstream %q must be an https:// URL", ep)
			}
			if net.ParseIP(u.Hostname()) == nil {
				return fmt.Errorf("dns_proxy_upstream host must be an IP literal (got %q) — DoH bootstrap can't depend on DNS", u.Hostname())
			}
		}
	}

	// Plaintext-auth gate. SOCKS5 auth and HTTP Basic both put the
	// username/password directly on the wire. Allowing that over the
	// public internet without an outer encrypted tunnel contradicts
	// the entire point of an opsec tool. Walk the chain and refuse
	// any auth'd SOCKS5/HTTP hop that isn't either:
	//   (a) preceded by an encrypting hop in the same chain, or
	//   (b) targeting loopback (Tor's local SOCKS, on-host daemon),
	//       or
	//   (c) explicitly acked via unencrypted_ack=true.
	if err := p.validatePlaintextAuth(); err != nil {
		return err
	}

	// Translate the legacy LockMode single-select into the new
	// independent bool fields. Done here (not in Load) so the
	// translation is idempotent and visible in Validate logs.
	// Cleared after translation so re-saving the profile drops the
	// legacy field.
	if p.LockMode != "" && !p.LockCountry && !p.LockASN && !p.LockIP {
		switch p.LockMode {
		case "country":
			p.LockCountry = true
		case "asn":
			p.LockCountry = true
			p.LockASN = true
		case "ip":
			p.LockCountry = true
			p.LockASN = true
			p.LockIP = true
		case "off":
			// nothing locked
		}
		p.LockMode = ""
	}
	// LockIP is incompatible with Tor (circuits rotate the exit IP
	// every ~10 min by design — pinning to the first one means every
	// rotation looks like drift). Country and ASN can both be locked
	// for Tor; ASN of Tor exits is reasonably stable per-relay.
	if p.LockIP && p.ChainEndsInTor() {
		return errors.New("lock_ip is incompatible with Tor (exits rotate per circuit) — use lock_country")
	}
	// Multi-hop chains hide the actual exit IP from local kernel
	// inspection (the peer IP is the entry hop). Refusing here prevents
	// the user from saving a profile that would always fail to launch.
	if (p.LockIP || strings.TrimSpace(p.RequireExitIP) != "") &&
		p.ChainIsMultihop() &&
		(p.GeoVerificationMode == "" || p.GeoVerificationMode == "local") {
		return errors.New("multi-hop chains can't verify exit IP locally — set geo_verification_mode=probe-once (one-time ipinfo probe) or trust (skip verification), or use lock_country alone")
	}
	switch p.GeoVerificationMode {
	case "", "local", "probe-once", "trust":
	default:
		return fmt.Errorf("geo_verification_mode %q invalid (must be local|probe-once|trust)", p.GeoVerificationMode)
	}
	return nil
}

// ChainEndsInTor reports whether Tor is the network-exit hop. Walks
// from the back, skipping local-only hops (TLS_MITM is a re-handshaker
// that runs inside the netns; it doesn't egress anywhere of its own),
// and returns true if the first real network hop encountered is Tor.
//
// Without the skip, PropagateAntiFingerprintMITM would mask any Tor
// chain — auto-inserted tls_mitm goes on the end, so a literal
// last-hop check sees TLS_MITM, not Tor, and the engine then mistakes
// the chain for a non-Tor multi-hop and demands probe-once. That's
// the source of the "locked_endpoint on multi-hop chain requires
// geo_verification_mode=probe-once or trust" error users hit when
// they enable strict anti-fingerprint on a WG→Tor profile.
func (p *Profile) ChainEndsInTor() bool {
	for i := len(p.Chain) - 1; i >= 0; i-- {
		switch p.Chain[i].Kind {
		case BackendTLSMITM:
			continue // local re-handshaker, not a network exit
		case BackendDirect:
			continue // pass-through no-op hop, doesn't egress
		case BackendTor:
			return true
		default:
			return false
		}
	}
	return false
}

// ChainIsMultihop reports whether the chain has 2+ tunnel hops
// (WG/OVPN/Tor count as tunnel; SOCKS/HTTP at the end are not
// multi-hop in this sense since the proxy host IS the exit).
func (p *Profile) ChainIsMultihop() bool {
	tunnelHops := 0
	for _, b := range p.Chain {
		switch b.Kind {
		case BackendWireGuard, BackendOpenVPN, BackendTor:
			tunnelHops++
		}
	}
	return tunnelHops >= 2
}

// validatePlaintextAuth refuses chain configurations that would send
// SOCKS5/HTTP credentials in cleartext over a non-loopback link with
// no encrypting hop in front of them. See Backend.UnencryptedAck for
// the rationale and escape hatch.
func (p *Profile) validatePlaintextAuth() error {
	encryptedSoFar := false
	for i, b := range p.Chain {
		// Anything that wraps the bytes from this point onward in an
		// encrypted carrier counts as "encrypted from here on". TLS
		// MITM doesn't qualify — it's a local re-handshaker, the leg
		// from netns → upstream is still in the clear.
		switch b.Kind {
		case BackendWireGuard, BackendOpenVPN, BackendTor:
			encryptedSoFar = true
			continue
		}
		// Plaintext-auth-capable hops: SOCKS5 + HTTP. If they have
		// credentials and we're not yet behind an encrypted carrier,
		// inspect targets.
		if b.Kind != BackendSOCKS5 && b.Kind != BackendHTTP {
			continue
		}
		if b.Username == "" && b.Password == "" {
			continue
		}
		if encryptedSoFar || b.UnencryptedAck {
			continue
		}
		hosts := plaintextHostList(b)
		for _, h := range hosts {
			if isLoopbackHost(h) {
				continue
			}
			return fmt.Errorf(
				"chain[%d] (%s): credentials would travel in cleartext to %q — "+
					"prepend a wireguard/openvpn/tor hop, or set unencrypted_ack=true on this hop "+
					"if the provider whitelists your source IP and the password isn't a wire secret",
				i, b.Kind, h)
		}
	}
	return nil
}

// plaintextHostList returns every distinct host the SOCKS5/HTTP hop
// might dial — the explicit Host field plus every entry in HostPool.
// Each entry is checked independently so a pool with one bad host
// fails the whole profile.
func plaintextHostList(b Backend) []string {
	out := make([]string, 0, 1+len(b.HostPool))
	if b.Host != "" {
		out = append(out, b.Host)
	}
	for _, e := range b.HostPool {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			// Pool entry without a port — treat the whole string as
			// a host. The backend's own Validate will reject it for
			// other reasons; we just don't want to skip it here.
			out = append(out, e)
			continue
		}
		out = append(out, host)
	}
	return out
}

// isLoopbackHost reports whether s is one of the loopback literals
// or parses to a loopback IP. Conservative — we explicitly do NOT
// auto-trust private/RFC1918 ranges because LAN sniffing is a real
// threat model for opsec users.
func isLoopbackHost(s string) bool {
	switch strings.ToLower(s) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(s); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// AnyLockEnabled reports whether the profile has at least one lock
// dimension enabled — used as the master "is enforcement on" toggle.
// LockedEndpoint (the legacy master flag) implies country if no other
// dim is on, so old profiles keep working.
func (p *Profile) AnyLockEnabled() bool {
	return p.LockCountry || p.LockASN || p.LockIP
}

// AllowGeoUnknown reports whether geo_unknown_policy permits proceeding
// when GeoIP can't resolve a country.
func (p *Profile) AllowGeoUnknown() bool {
	return p.GeoUnknownPolicy != "fail"
}

// PropagateAntiFingerprintMITM auto-inserts a tls_mitm hop at the
// end of the chain when ANY of:
//   - anti_fingerprint == strict (cohort-blend mode wants TLS spoof)
//   - persona is set (specific identity wants L4 to match its claims)
//   - forge_persona is set (same, with on-the-fly persona generation)
//
// Skipped for anti_fingerprint == basic so users who don't want the
// per-profile CA can still get JS + TCP layer hardening without the
// trust ceremony.
//
// Rationale: if you claim "I'm Chrome on Windows" via persona but
// emit a Brave-on-Linux TLS handshake, the persona is instantly
// contradicted at L4. Same applies to anti_fingerprint:strict —
// cohort blending requires TLS coherence. Both modes share the
// same machinery; only the values feeding the persona extension
// differ.
//
// Costs accepted when MITM is auto-inserted:
//   - A per-profile Veil CA is installed only into the browser data
//     dir Veil owns. User's normal browsers stay untouched.
//   - Some sites with hard-coded cert pinning (banks, certain Google
//     services) refuse the substituted cert and won't load.
//   - Veil sees decrypted application traffic on this profile since
//     it's terminating TLS — the trade-off for L4 coherence.
//
// Called in-memory at launch time so user-edited YAML is untouched.
// A user-added tls_mitm hop is honored regardless of mode.
func (p *Profile) PropagateAntiFingerprintMITM() {
	for _, b := range p.Chain {
		if b.Kind == BackendTLSMITM {
			return // already present
		}
	}
	needsMITM := p.AntiFingerprint.IsStrict() || p.Persona != "" || p.ForgePersona
	if !needsMITM {
		return
	}
	p.Chain = append(p.Chain, Backend{
		Kind:           BackendTLSMITM,
		TLSFingerprint: pickTLSFingerprint(p),
	})
}

// pickTLSFingerprint chooses the uTLS fingerprint preset for a
// profile's auto-inserted tls_mitm hop. Persona's claimed browser
// (derived from its User-Agent if available) wins over the launched
// app's preset, because the persona's stated identity is what the
// site is supposed to see — even if we're running it in a different
// browser binary.
func pickTLSFingerprint(p *Profile) string {
	// Persona-set profiles: try to derive from persona name (we can't
	// load persona contents here without import cycles; the engine's
	// later resolution may override this via the chain hop's value
	// once the persona file is parsed). Fall back to preset.
	switch strings.ToLower(p.App.Preset) {
	case "firefox", "thunderbird":
		return "firefox"
	case "tor-browser", "mullvad-browser":
		return "tor" // uTLS HelloFirefox_102 — Tor Browser tracks Firefox ESR
	case "chromium", "brave", "veil-browser", "edge":
		return "chrome"
	}
	return "chrome"
}

// PropagateExitConstraints applies profile-level locked-endpoint
// constraints to the per-hop backend config that needs them. Called
// in-memory at launch time so user-edited YAML is left untouched.
//
// Specifically: if RequireExitCountry is set and the last Tor hop has
// no tor_exit_country override, copy the requirement onto it. Without
// this, Tor would pick any random exit and the locked-endpoint gate
// would refuse launch — wasting the bring-up cost. With this, Tor
// pins exits to the required country up front.
func (p *Profile) PropagateExitConstraints() {
	// Tor profiles can never honor an exit-IP pin (circuits rotate per
	// stream by design). An older Veil version captured the first
	// circuit's exit IP into RequireExitIP unconditionally; on Tor that
	// was guaranteed-stale data that turns every subsequent rotation
	// into a "drift" alarm. Scrub it here so users with profiles from
	// before the fix don't have to hand-edit YAML, and persist the
	// cleanup so the stale value doesn't stay on disk between launches.
	if p.ChainEndsInTor() && (p.RequireExitIP != "" || p.VerifiedIP != "") {
		p.RequireExitIP = ""
		p.VerifiedIP = ""
		if store, err := DefaultStore(); err == nil {
			_ = store.Save(p) // best-effort; in-memory scrub still applies
		}
	}

	wantCC := strings.TrimSpace(p.RequireExitCountry)
	if wantCC == "" || len(p.Chain) == 0 {
		return
	}
	last := &p.Chain[len(p.Chain)-1]
	if last.Kind != BackendTor {
		return
	}
	if strings.TrimSpace(last.TorExitCountry) == "" {
		last.TorExitCountry = wantCC
	}
}

// GeoCoherenceWarning returns a non-empty advisory when a profile forges
// a persona for a specific country but neither pins/verifies the exit to
// that country nor adapts the persona to the actual exit. In that case
// the exit IP's geolocation can disagree with the persona's
// timezone/locale — a detectable inconsistency. It is advisory only:
// pinning stays OPT-IN (the user may legitimately not care about the
// exit country, or there may be no exit available in that country), so
// callers warn rather than block. Empty string = coherent by config.
func (p *Profile) GeoCoherenceWarning() string {
	if strings.TrimSpace(p.ForgeCountry) == "" {
		return ""
	}
	if strings.TrimSpace(p.RequireExitCountry) != "" || p.AnyLockEnabled() || p.Env.AutoFromExit {
		return ""
	}
	return fmt.Sprintf("persona forges country %s but the exit is not pinned (require_exit_country/lock_country) and auto_from_exit is off: "+
		"the exit IP's country may not match the persona's timezone/locale (detectable). "+
		"Pin the exit to match, or set auto_from_exit to adapt the persona to whatever exit you get.",
		strings.ToUpper(p.ForgeCountry))
}

// Validate returns nil if the backend has the required fields for its kind.
func (b *Backend) Validate() error {
	switch b.Kind {
	case BackendDirect:
		return nil
	case BackendSOCKS5, BackendHTTP:
		if b.Host == "" || b.Port == 0 {
			return fmt.Errorf("%s backend needs host and port", b.Kind)
		}
	case BackendWireGuard, BackendOpenVPN:
		if b.ConfigPath == "" && b.ConfigData == "" {
			return fmt.Errorf("%s backend needs config_path or config_data", b.Kind)
		}
	case BackendTor:
		// SocksAddr defaulted at runtime.
	case BackendTLSMITM:
		// no required fields
	default:
		return fmt.Errorf("unknown backend kind %q", b.Kind)
	}
	return nil
}
