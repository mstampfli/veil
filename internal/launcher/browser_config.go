package launcher

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	personaextension "github.com/mstampfli/veil/internal/launcher/persona-extension"
	"github.com/mstampfli/veil/internal/launcher/veilbrowser"
	"github.com/mstampfli/veil/internal/persona"
	"github.com/mstampfli/veil/internal/profile"
)

// PersonaConfig is the subset of persona fields the launcher applies.
// Defined here (rather than importing internal/persona) to avoid an
// import cycle: profile depends on launcher, persona depends on profile.
type PersonaConfig struct {
	UserAgent           string
	AcceptLanguage      string
	Platform            string
	ScreenWidth         int
	ScreenHeight        int
	DevicePixelRatio    float64
	HardwareConcurrency int
}

// ApplyProxyConfig configures the launched browser to route through the
// given proxy URL, regardless of whether the user enabled transparent
// mode. The browser doesn't get a chance to "decide" — its config is
// written before it starts.
//
//   * Firefox / Thunderbird → user.js in the data dir with SOCKS5 prefs
//     (Mozilla apps ignore HTTP_PROXY env vars by design).
//   * Chromium / Brave → --proxy-server CLI flag prepended to args.
//   * Other apps → no-op; they already get HTTP_PROXY env vars from the
//     engine and either honor them or rely on transparent mode.
//
// proxyURL may be empty (no proxy in chain) — in that case the config is
// cleared so the browser doesn't carry stale prefs from a prior run.
//
// When p.AntiFingerprint is set, the generated config also enables
// browser-side fingerprint randomization (Mozilla RFP, or Chromium UA +
// canvas/WebGL flags).
func ApplyProxyConfig(p *profile.Profile, proxyURL string) error {
	return ApplyProxyAndPersona(p, proxyURL, nil)
}

// ApplyProxyAndPersona is the richer form: in addition to proxy + the
// AntiFingerprint flag, it also applies a Persona (UA, language, screen,
// platform, hardware concurrency) when one is supplied. Persona
// overrides AntiFingerprint's defaults wherever they conflict.
func ApplyProxyAndPersona(p *profile.Profile, proxyURL string, pers *PersonaConfig) error {
	return ApplyProxyPersonaAndFull(p, proxyURL, pers, nil)
}

// ApplyProxyPersonaAndFull adds a fourth parameter: the full persona
// (with all veil-browser-relevant fields). Used when the launcher has
// the rich persona loaded; if nil, falls back to the older PersonaConfig
// view (backward compat with code paths that haven't been updated).
//
// When the active preset is veil-browser (or any Chromium-family preset
// pointing at a binary that supports --veil-persona), this writes a
// persona.json into the profile data dir and appends the flag.
func ApplyProxyPersonaAndFull(p *profile.Profile, proxyURL string, pers *PersonaConfig, full *persona.Persona) error {
	if p == nil {
		return nil
	}
	switch p.App.Preset {
	case "firefox", "thunderbird":
		if err := writeFirefoxUserJS(p.DataDir, proxyURL, p, pers); err != nil {
			return err
		}
		// Browser-agnostic persona: also drop the WebExtension into
		// the data_dir. Stock Firefox refuses unsigned extensions, but
		// the engine_linux Launch path uses Marionette to install it
		// as a temporary add-on (signature check bypassed for the
		// session). Same persona-overrides.js as Chromium uses.
		if full != nil && p.DataDir != "" {
			_, _ = personaextension.WriteAndPersonaWithFlagsForBrowser(p.DataDir, "firefox", full, nil)
		}
		return nil
	case "chromium", "brave", "veil-browser":
		setChromiumProxyArg(&p.App.Args, proxyURL, p, pers)
		// Write persona.json + append --veil-persona for forks that
		// honor it. Stock browsers will silently ignore the flag.
		if full != nil && p.DataDir != "" {
			if path, err := veilbrowser.Write(p.DataDir, full); err == nil {
				appendUniqueFlag(&p.App.Args, "--veil-persona="+path)
			}
		}
		// Always-on Chromium hardening: DNT header, safebrowsing off,
		// autofill off, locked-down WebRTC IP handling. Whoer-style
		// scanners flag missing DNT regardless of anti_fingerprint
		// setting; this makes that flag clear without needing strict
		// mode. Best-effort; failure to write Preferences doesn't
		// abort launch.
		if p.DataDir != "" {
			_ = chromiumBasePrefs(p.DataDir)
		}
		// AntiFingerprint on Chromium-family: layer Brave Shields =
		// Aggressive (max farbling) plus every other "phone home"
		// Brave knob turned off on top of the base prefs. Done before
		// we write persona.json so the "shields active" flag can
		// reach the extension.
		shieldsActive := false
		if p.App.Preset == "brave" && p.AntiFingerprint.IsOn() && p.DataDir != "" {
			if err := chromiumAntiFingerprintPrefs(p.DataDir); err == nil {
				shieldsActive = true
			}
		}
		// Browser-agnostic persona: install the Veil persona
		// WebExtension into the data_dir + tell Chromium to load it.
		// Content script overrides navigator.* / screen.* / WebGL /
		// AudioContext / timezone / Battery API at document_start,
		// in the page's MAIN world, so page scripts see persona-
		// shaped values. Combined with tls_mitm + uTLS at L4/L7,
		// this gives stock Chromium near-veil-browser-fork behavior.
		//
		// When running on Brave with Shields aggressive, we pass
		// _veil_brave_shields_active=true so the extension SKIPS
		// canvas/audio/font/measureText farbling (Brave's C++ layer
		// already does it more thoroughly + catches OffscreenCanvas
		// and service-worker contexts the JS wraps don't see).
		// Stacking would also break Brave's per-eTLD determinism.
		flags := map[string]any{}
		if shieldsActive {
			flags["_veil_brave_shields_active"] = true
		}
		if full != nil && p.DataDir != "" {
			if extDir, err := personaextension.WriteAndPersonaWithFlagsForBrowser(p.DataDir, "chromium",full, flags); err == nil {
				appendUniqueFlag(&p.App.Args, "--load-extension="+extDir)
				appendUniqueFlag(&p.App.Args, "--disable-extensions-except="+extDir)
			}
		} else if p.AntiFingerprint.IsOn() && p.DataDir != "" {
			// anti_fingerprint without a persona: still load the
			// extension, but with the GENERIC blend persona below.
			// Without this the browser reveals real GPU strings via
			// WebGL UNMASKED_VENDOR/RENDERER even though
			// anti_fingerprint is on — the CLI flags don't cover
			// those getters.
			generic := genericBlendPersona()
			if extDir, err := personaextension.WriteAndPersonaWithFlagsForBrowser(p.DataDir, "chromium",generic, flags); err == nil {
				appendUniqueFlag(&p.App.Args, "--load-extension="+extDir)
				appendUniqueFlag(&p.App.Args, "--disable-extensions-except="+extDir)
			}
		}
	}
	return nil
}

// genericBlendPersona returns the persona-shape JSON the extension
// content script reads when anti_fingerprint is on but no specific
// persona is configured. The values are picked to maximize cohort
// blending — generic Linux Chromium with the most common Mesa Intel
// GPU strings (the largest cluster on Linux desktop browsers).
//
// Real values that would otherwise leak via WebGL UNMASKED_*:
//   - User's actual GPU vendor/renderer string (often distinguishing,
//     e.g. "ANGLE (Intel, Mesa Intel(R) Graphics (RPL-S), OpenGL ES 3.2)"
//     reveals Raptor Lake silicon — a small, identifying cohort).
//
// Generic blend values picked from the most populated bucket on
// Chromium-Linux + Mesa: an Intel UHD 620 / Kaby Lake string. That
// blends with a large slice of the Linux desktop population.
func genericBlendPersona() map[string]any {
	return map[string]any{
		// WebGL — main culprit the user just hit:
		"webgl_vendor":            "Google Inc. (Intel)",
		"webgl_renderer":          "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL ES 3.2)",
		"webgl_unmasked_vendor":   "Google Inc. (Intel)",
		"webgl_unmasked_renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL ES 3.2)",
		// Audio context sample rate — common Linux value (PipeWire/
		// PulseAudio default).
		"audio_sample_rate": 44100,
		// Hardware concurrency / device memory — the most common
		// modern-laptop bucket on the web.
		"hardware_concurrency": 8,
		"device_memory":        8,
		// Screen — already forced via --window-size in CLI flags but
		// set here too so window.screen.* matches.
		"screen_width":   1920,
		"screen_height":  1080,
		"color_depth":    24,
		// Battery — desktop-shape (always charging).
		"max_touch_points": 0,
	}
}

// appendUniqueFlag appends flag to args, replacing any prior occurrence
// of the same switch (matched by the prefix before "=", or whole-string
// for boolean flags).
func appendUniqueFlag(args *[]string, flag string) {
	prefix := flag
	if i := strings.Index(flag, "="); i >= 0 {
		prefix = flag[:i+1]
	}
	out := (*args)[:0]
	for _, a := range *args {
		if strings.HasPrefix(a, prefix) {
			continue
		}
		out = append(out, a)
	}
	*args = append(out, flag)
}

// writeFirefoxUserJS drops a user.js into <dataDir> with SOCKS proxy
// prefs and (optionally) fingerprint-resistance prefs and a persona.
func writeFirefoxUserJS(dataDir, proxyURL string, p *profile.Profile, pers *PersonaConfig) error {
	if dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dataDir, "user.js")

	var body string
	if proxyURL == "" {
		body = firefoxNoProxy
	} else {
		host, port, scheme, err := parseProxy(proxyURL)
		if err != nil {
			return err
		}
		body = firefoxProxyJS(scheme, host, port)
	}

	// intl.accept_languages — derive from Lang for HTTP Accept-Language
	// consistency with the exit country, regardless of AntiFingerprint.
	if p != nil && p.Env.Lang != "" {
		body += firefoxAcceptLang(p.Env.Lang)
	}

	// CRITICAL: start with about:blank instead of the configured
	// homepage. Firefox needs a few seconds after launch before
	// Marionette accepts our addon install — during that window
	// it must NOT auto-open the user's homepage (which would make
	// network requests with no persona override applied).
	body += `
// Veil — start blank, never auto-open the homepage.
user_pref("browser.startup.page", 0);                  // 0 = blank
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtab.url", "about:blank");
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("startup.homepage_welcome_url", "about:blank");
user_pref("startup.homepage_welcome_url.additional", "about:blank");
user_pref("startup.homepage_override_url", "about:blank");
user_pref("browser.aboutHomeSnippets.updateUrl", "");  // no Mozilla snippet fetch

// CRITICAL: disable Firefox's built-in JSON viewer. When it's on,
// loading https://ipinfo.io/json renders a prettified tree UI; the
// IP probe reads document.body.innerText and gets "JSON raw data"
// (the tab label) plus formatted tree text — NOT the raw JSON.
// Veil's parser then can't decode it. With the viewer off, Firefox
// shows raw JSON in <pre>, document.body.innerText returns it
// cleanly, and our IPInfo struct unmarshals correctly.
user_pref("devtools.jsonview.enabled", false);

// Do Not Track + Global Privacy Control. Whoer-style fingerprint
// scanners flag the absence of these as "tracking-block disabled".
// Both are header-only signals (DNT in HTTP request, Sec-GPC in
// HTTP request); no behavioral effect on Veil's chain — they just
// make the test sites stop nagging without hurting blendability.
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.globalprivacycontrol.enabled", true);
user_pref("privacy.globalprivacycontrol.functionality.enabled", true);
`

	if p != nil && p.AntiFingerprint.IsOn() {
		body += firefoxRFP
	}

	if pers != nil {
		body += firefoxPersona(pers)
	}

	if p != nil && p.DNSMatchExit {
		body += firefoxDNSMatchExit(p.DNSMatchEndpoint)
	}

	return os.WriteFile(path, []byte(body), 0o644)
}

// firefoxDNSMatchExit returns user.js prefs that put Firefox into
// TRR-only DoH mode pointed at an IP-literal anycast resolver. The DoH
// connection itself rides the configured SOCKS5 proxy (Tor / WG / etc),
// so the resolver IP that ultimately queries upstream auth NS records
// is geographically near the chain's exit — making whoer-style
// "DNS doesn't match exit" tests pass.
//
// Bootstrap address is critical: TRR-only with mode 3 means Firefox
// uses ONLY TRR for DNS, so without a bootstrap (an IP literal for the
// TRR endpoint itself) Firefox would have no way to reach the resolver
// in the first place. Mullvad's 194.242.2.2 endpoint is its own
// bootstrap: the URL is already an IP literal.
func firefoxDNSMatchExit(endpoint string) string {
	if endpoint == "" {
		endpoint = "https://194.242.2.2/dns-query"
	}
	// Pull the host out of the URL for bootstrapAddress. We trust
	// validation already verified it's an IP literal.
	bootstrap := "194.242.2.2"
	if u, err := url.Parse(endpoint); err == nil && u.Hostname() != "" {
		bootstrap = u.Hostname()
	}
	return fmt.Sprintf(`
// --- DNS match exit (DoH-via-tunnel) ---
// TRR-only mode: no system DNS, every lookup via DoH.
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", %q);
user_pref("network.trr.bootstrapAddress", %q);
// CRITICAL: this pref's name is misleading. true = STRICT (never
// fall back to native DNS, even on TRR transient errors). false
// allows the fallback to native DNS, which under our setup means
// the iptables REDIRECT catches it and sends to Tor's DNSPort —
// which is a DIFFERENT Tor circuit than the data, so whoer sees a
// resolver IP that doesn't match the exit IP. true makes mode=3
// truly leakproof: any TRR failure becomes an explicit network
// error rather than a silent native-DNS fallback.
user_pref("network.trr.strict_native_fallback", true);
user_pref("network.trr.wait-for-portal", false);
user_pref("network.trr.allow-rfc1918", false);
// Skip the confirmationNS probe — it's an extra DNS query at
// startup that under mode=3 would just race with the first real
// query for no benefit. "skip" disables the probe entirely.
user_pref("network.trr.confirmationNS", "skip");
// Use POST so the query payload doesn't appear in URL caches /
// proxy logs as plaintext domain names.
user_pref("network.trr.useGET", false);
// Disable DNS prefetch + speculative connections — they can
// otherwise emit lookups that race the TRR setup.
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
`, endpoint, bootstrap)
}

// firefoxPersona writes overrides for every navigator.* field that
// Firefox exposes a pref for. Goal: when the user picks a persona,
// EVERY identifying property Firefox publishes via navigator.* should
// match the persona, not Firefox's defaults.
//
// **Hard limit: Firefox cannot perfectly impersonate Chrome.** Many JS
// APIs (`InstallTrigger`, `mozInnerScreenX`, `Components`, document.alinkColor
// behavior) are Firefox-engine signatures we can't override via prefs.
// Sites doing `typeof InstallTrigger !== "undefined"` will still detect
// Firefox. Use Chromium with the persona for true Chrome impersonation.
func firefoxPersona(pers *PersonaConfig) string {
	var b strings.Builder
	b.WriteString("\n// --- Persona ---\n")
	if pers.UserAgent != "" {
		fmt.Fprintf(&b, "user_pref(\"general.useragent.override\", %q);\n", pers.UserAgent)
		// Derive oscpu, appVersion, buildID from the UA so they don't
		// leak the host's actual values.
		oscpu, appVer, buildID := deriveFromUA(pers.UserAgent, pers.Platform)
		if oscpu != "" {
			fmt.Fprintf(&b, "user_pref(\"general.oscpu.override\", %q);\n", oscpu)
		}
		if appVer != "" {
			fmt.Fprintf(&b, "user_pref(\"general.appversion.override\", %q);\n", appVer)
		}
		if buildID != "" {
			fmt.Fprintf(&b, "user_pref(\"general.buildID.override\", %q);\n", buildID)
			fmt.Fprintf(&b, "user_pref(\"browser.startup.homepage_override.buildID\", %q);\n", buildID)
		}
		// Static appName: every Firefox / Chrome / Safari builds report
		// "Netscape" historically. Override anyway for parity.
		fmt.Fprintf(&b, "user_pref(\"general.appname.override\", %q);\n", "Netscape")
	}
	if pers.Platform != "" {
		fmt.Fprintf(&b, "user_pref(\"general.platform.override\", %q);\n", pers.Platform)
	}
	if pers.AcceptLanguage != "" {
		fmt.Fprintf(&b, "user_pref(\"intl.accept_languages\", %q);\n", pers.AcceptLanguage)
	}
	if pers.HardwareConcurrency > 0 {
		fmt.Fprintf(&b, "user_pref(\"dom.maxHardwareConcurrency\", %d);\n", pers.HardwareConcurrency)
	}
	if pers.ScreenWidth > 0 && pers.ScreenHeight > 0 {
		fmt.Fprintf(&b, "user_pref(\"privacy.window.maxInnerWidth\", %d);\n", pers.ScreenWidth)
		fmt.Fprintf(&b, "user_pref(\"privacy.window.maxInnerHeight\", %d);\n", pers.ScreenHeight)
	}
	return b.String()
}

// deriveFromUA extracts oscpu, appVersion, buildID values that match
// the supplied User-Agent string. Imperfect but covers Chrome / Firefox
// / Safari UA patterns.
func deriveFromUA(ua, platform string) (oscpu, appVersion, buildID string) {
	low := strings.ToLower(ua)
	switch {
	case strings.Contains(low, "windows nt 10"):
		oscpu = "Windows NT 10.0; Win64; x64"
	case strings.Contains(low, "windows nt 11"):
		oscpu = "Windows NT 11.0; Win64; x64"
	case strings.Contains(low, "mac os x"):
		oscpu = "Intel Mac OS X 10.15"
	case strings.Contains(low, "iphone") || strings.Contains(low, "ios"):
		oscpu = "iPhone"
	case strings.Contains(low, "android"):
		oscpu = "Linux armv8l"
	case strings.Contains(low, "x11; linux"):
		oscpu = "Linux x86_64"
	}
	if oscpu == "" && platform != "" {
		// Fall back to using platform as oscpu hint.
		oscpu = platform
	}
	// appVersion in Firefox is everything after "Mozilla/" — i.e., the UA
	// without the "Mozilla/5.0 " prefix.
	if strings.HasPrefix(ua, "Mozilla/5.0 ") {
		appVersion = strings.TrimPrefix(ua, "Mozilla/5.0 ")
	} else {
		appVersion = ua
	}
	// buildID: 14-digit datestamp YYYYMMDDHHMMSS. Pick a value matching
	// the Firefox-ESR-128 release cadence so we blend with that cohort.
	buildID = "20240701000000"
	return
}

// setChromiumProxyArg ensures --proxy-server (and optionally anti-
// fingerprinting flags + persona overrides) are present in args,
// replacing prior values.
func setChromiumProxyArg(args *[]string, proxyURL string, p *profile.Profile, pers *PersonaConfig) {
	// Strip EVERY flag Veil ever adds to a Chromium-family launch.
	// Without this comprehensive purge, repeated launches accumulate
	// duplicates: a profile relaunched 5 times ends up with 5x
	// `--no-sandbox`, multiple `--dns-over-https-server=` (one per
	// version of dns_match_endpoint the user ever set), conflicting
	// `--user-data-dir=`, etc. Chromium's flag handling for duplicates
	// is undefined per-flag (some take first, some last, many cause
	// silent misconfiguration). Result: browser uses wrong DoH
	// upstream / wrong proxy / wrong data dir → exactly the
	// "behaves weirdly with multiple profiles / restarts" symptom.
	veilPrefixes := []string{
		// proxy + resolver
		"--proxy-server=",
		"--proxy-bypass-list=",
		"--host-resolver-rules=",
		// fingerprint shaping
		"--user-agent=",
		"--accept-lang=",
		"--window-size=",
		"--window-position=",
		"--force-device-scale-factor=",
		// features toggles
		"--disable-features=",
		"--enable-features=",
		// boolean flags
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--disable-quic",
		"--disable-webrtc-encryption",
		"--disable-reading-from-canvas",
		"--disable-3d-apis-deprecated",
		"--no-pings",
		"--disable-domain-reliability",
		"--disable-component-update",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-translate",
		"--no-default-browser-check",
		"--no-first-run",
		"--use-mock-keychain",
		// DoH
		"--dns-over-https-mode=",
		"--dns-over-https-server=",
		// remote debugging
		"--remote-debugging-port=",
		"--remote-debugging-address=",
		"--remote-allow-origins=",
		"--remote-allow-system-access",
		// persona / extension
		"--veil-persona=",
		"--load-extension=",
		"--disable-extensions-except=",
	}
	out := (*args)[:0]
	for _, a := range *args {
		drop := false
		for _, pfx := range veilPrefixes {
			// pfx with "=" matches by prefix; bool flags must match
			// exactly so we don't drop unrelated args sharing the
			// stem (none today, but defensive).
			if strings.HasSuffix(pfx, "=") {
				if strings.HasPrefix(a, pfx) {
					drop = true
					break
				}
			} else if a == pfx {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, a)
		}
	}
	if proxyURL != "" {
		out = append(out, "--proxy-server="+proxyURL)
		out = append(out, "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1")
		// Chromium ALREADY bypasses 127.0.0.1/localhost by default —
		// no flag needed. Adding --proxy-bypass-list=<-loopback>
		// would actually REVERSE the implicit bypass and route
		// loopback through the proxy. So we leave it alone.
	}
	// Chromium's per-renderer sandbox uses CLONE_NEWUSER. When veil's
	// engine launches the browser inside a user-ns (the new privilege
	// path), Chromium's nested user-ns setup interacts badly with
	// bounding-set + uid mapping and the renderers fail silently —
	// Brave then exits without opening a window. Veil's netns IS the
	// sandbox boundary, so disabling Chromium's in-process sandbox
	// here is equivalent (no security regression) and fixes the
	// silent-exit. Also pass --disable-dev-shm-usage because /dev/shm
	// is sometimes too small inside the namespace and Chromium falls
	// over allocating shared memory there.
	out = append(out,
		"--no-sandbox",
		"--disable-dev-shm-usage",
	)
	if p != nil && p.Env.Lang != "" {
		out = append(out, "--accept-lang="+localeToAcceptLang(p.Env.Lang))
	}
	if p != nil && p.AntiFingerprint.IsOn() {
		// Chromium has no Mozilla-RFP equivalent, but the user's
		// stated threat model on Chromium-family is "don't tie this
		// to my real machine, don't link my profiles together" — and
		// that's exactly what Brave Shields' farbling does (per-eTLD
		// per-session randomization, real hardware values masked).
		// We force everything to maximum:
		//
		//   1. CLI flags below close every Chromium-flag-controllable
		//      fingerprint channel (UA, Client Hints, WebRTC, canvas
		//      read, telemetry, hyperlink auditing, captive portal).
		//   2. For Brave specifically, the launcher writes a
		//      Preferences JSON to the data_dir BEFORE launch
		//      (chromiumAntiFingerprintPrefs in this package) that
		//      sets Brave Shields fingerprinting protection to
		//      Aggressive — the strongest farbling level.
		//
		// Combined effect: real GPU/CPU/audio/font signatures are
		// hidden, every profile's data_dir gets a different farbling
		// seed, telemetry beacons are off. Different from Firefox-RFP
		// (cohort blending) but achieves the same threat-model goal:
		// no attribution to your machine, no linkability between
		// profiles.
		out = append(out, "--user-agent="+ChromiumGenericUA)
		out = append(out,
			// CRITICAL: --disable-quic prevents the browser from
			// switching to HTTP/3 (UDP QUIC) for h3-advertising
			// sites (Alt-Svc: h3). QUIC bypasses our TCP MITM
			// entirely → site would see the REAL host TLS
			// handshake + REAL HTTP headers without any of our
			// persona shaping.
			"--disable-quic",
			// CRITICAL: disable Brave/Chromium's built-in DoH and
			// any encrypted-DNS path. Otherwise DNS leaves the
			// netns directly to Cloudflare/Google over HTTPS,
			// bypassing the chain.
			"--disable-features=WebRtcHideLocalIpsWithMdns,UserAgentClientHint,UserAgentClientHintsGREASE,Translate,InterestFeedContentSuggestions,PrivacySandboxSettings4,FedCm,WebOTP,DnsOverHttps,DnsOverHttpsUpgrade,EncryptedClientHello,Http2ConcurrentStreams",
			"--enable-features=ReducedAcceptLanguage,ReducedUserAgentMinorVersion,UACHPlatformIsLinuxNotChromeOS",
			"--disable-webrtc-encryption",
			"--disable-reading-from-canvas",
			"--disable-3d-apis-deprecated",
			"--no-pings",                   // <a ping=> hyperlink auditing
			"--disable-domain-reliability", // Google's DR pings
			"--disable-component-update",   // component-update beacons
			"--disable-background-networking",
			"--disable-features=DialMediaRouteProvider,InterestFeedV2",
			"--disable-sync",
			"--disable-translate",
			"--no-default-browser-check",
			"--no-first-run",
			"--use-mock-keychain", // don't touch host keychain (linkable)

			// Hardware-revealing surfaces NOT covered by Brave farbling.
			// Without these, screen.width/height, devicePixelRatio, and
			// navigator.languages leak the user's real monitor/display
			// setup and language preferences — those CAN be uniquely
			// identifying (ultrawide monitor, multi-language users).
			// Forcing the standard 1920x1080 / DPR=1 / en-US drops every
			// user into the most-populated cohort.
			"--window-size=1920,1080",
			"--window-position=0,0",
			"--force-device-scale-factor=1",
			"--accept-lang=en-US,en;q=0.9",
		)
	} else {
		// Even without anti-fingerprint, we still must prevent the
		// browser from bypassing Veil's chain via QUIC or DoH —
		// those would leave the netns over UDP/TCP-443 and
		// completely defeat the chain (no MITM, no DNS shaping).
		out = append(out,
			"--disable-quic",
			"--disable-features=WebRtcHideLocalIpsWithMdns,DnsOverHttps,DnsOverHttpsUpgrade,EncryptedClientHello",
		)
	}
	// dns_match_exit overrides the disable-DoH defaults: instead of
	// blocking DoH, FORCE it to a known anycast resolver and let the
	// proxy carry the DoH connection through the chain. The resolver
	// IP that queries upstream auth NS records ends up geographically
	// near the chain's exit (anycast → nearest PoP from exit's POV),
	// making whoer-style mismatch tests pass without weakening the
	// leak guarantee. We strip any prior DnsOverHttps blocks first
	// so the enable wins.
	if p != nil && p.DNSMatchExit {
		ep := p.DNSMatchEndpoint
		if ep == "" {
			ep = "https://194.242.2.2/dns-query"
		}
		out = stripDoHBlocks(out)
		out = append(out,
			"--enable-features=DnsOverHttps",
			"--dns-over-https-mode=secure",
			"--dns-over-https-server="+ep,
		)
	}
	// Persona overrides win over AntiFingerprint's generic UA.
	if pers != nil {
		// Drop any prior --user-agent we just appended.
		filtered := out[:0]
		for _, a := range out {
			if !strings.HasPrefix(a, "--user-agent=") {
				filtered = append(filtered, a)
			}
		}
		out = filtered
		if pers.UserAgent != "" {
			out = append(out, "--user-agent="+pers.UserAgent)
		}
		if pers.AcceptLanguage != "" {
			// Replace the LANG-derived accept-lang we appended above.
			noAL := out[:0]
			for _, a := range out {
				if !strings.HasPrefix(a, "--accept-lang=") {
					noAL = append(noAL, a)
				}
			}
			out = append(noAL, "--accept-lang="+pers.AcceptLanguage)
		}
		if pers.ScreenWidth > 0 && pers.ScreenHeight > 0 {
			out = append(out, fmt.Sprintf("--window-size=%d,%d", pers.ScreenWidth, pers.ScreenHeight))
		}
		if pers.DevicePixelRatio > 0 {
			out = append(out, fmt.Sprintf("--force-device-scale-factor=%g", pers.DevicePixelRatio))
		}
	}
	*args = out
}

// stripDoHBlocks rewrites every --disable-features=... arg to remove
// the DoH-related entries (DnsOverHttps, DnsOverHttpsUpgrade,
// EncryptedClientHello) so a subsequent --enable-features=DnsOverHttps
// actually takes effect. Chrome resolves --disable-features wins over
// --enable-features for the same name, so we MUST drop the disables
// when dns_match_exit is on.
func stripDoHBlocks(args []string) []string {
	const prefix = "--disable-features="
	dropDoH := []string{"DnsOverHttps", "DnsOverHttpsUpgrade", "EncryptedClientHello"}
	out := args[:0]
	for _, a := range args {
		if !strings.HasPrefix(a, prefix) {
			out = append(out, a)
			continue
		}
		feats := strings.Split(strings.TrimPrefix(a, prefix), ",")
		kept := feats[:0]
		for _, f := range feats {
			drop := false
			for _, bad := range dropDoH {
				if f == bad {
					drop = true
					break
				}
			}
			if !drop {
				kept = append(kept, f)
			}
		}
		if len(kept) > 0 {
			out = append(out, prefix+strings.Join(kept, ","))
		}
	}
	return out
}

// ChromiumGenericUA is a generic recent-Chrome desktop UA used when
// AntiFingerprint is on for Chromium-family browsers. It rotates as
// upstream Chrome's UA does; pinning to a stable major version makes
// Veil users blend with the global Chrome population.
const ChromiumGenericUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

func parseProxy(proxyURL string) (host string, port int, scheme string, err error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", 0, "", err
	}
	scheme = strings.ToLower(u.Scheme)
	host = u.Hostname()
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		return "", 0, "", fmt.Errorf("proxy URL %q has no port: %w", proxyURL, err)
	}
	return host, p, scheme, nil
}

// firefoxProxyJS returns a user.js body that locks Firefox to a SOCKS5
// proxy, routes DNS through the proxy, disables WebRTC, and turns off
// every "phone home" feature that could create a non-proxied request.
func firefoxProxyJS(scheme, host string, port int) string {
	// Mozilla supports SOCKS via prefs; HTTP/HTTPS proxies are also
	// supported but use a different pref set.
	switch scheme {
	case "socks5", "socks5h", "socks":
		return fmt.Sprintf(`// Generated by Veil — do not edit by hand.
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", %q);
user_pref("network.proxy.socks_port", %d);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
user_pref("network.proxy.no_proxies_on", "127.0.0.1, localhost");  // bypass proxy for persona probe
user_pref("network.proxy.allow_hijacking_localhost", true);

// Belt-and-suspenders: every dial-out feature that could bypass the proxy.
user_pref("media.peerconnection.enabled", false);          // WebRTC off
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.update.enabled", false);
user_pref("extensions.update.enabled", false);
user_pref("services.settings.server", "");
`, host, port)
	case "http", "https":
		return fmt.Sprintf(`// Generated by Veil — do not edit by hand.
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", %q);
user_pref("network.proxy.http_port", %d);
user_pref("network.proxy.ssl", %q);
user_pref("network.proxy.ssl_port", %d);
user_pref("network.proxy.no_proxies_on", "127.0.0.1, localhost");  // bypass proxy for persona probe
user_pref("media.peerconnection.enabled", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
`, host, port, host, port)
	default:
		return firefoxNoProxy
	}
}

const firefoxNoProxy = `// Generated by Veil — no proxy in this profile's chain.
user_pref("network.proxy.type", 0);
user_pref("media.peerconnection.enabled", false);
`

// firefoxAcceptLang sets intl.accept_languages so the browser's
// Accept-Language HTTP header matches the launched locale. Without
// this, sites see e.g. an exit IP in Switzerland but Accept-Language:
// en-US — a small fingerprint inconsistency.
func firefoxAcceptLang(lang string) string {
	return fmt.Sprintf("user_pref(\"intl.accept_languages\", %q);\nuser_pref(\"general.useragent.locale\", %q);\n",
		localeToAcceptLang(lang), localeToBCP47(lang))
}

// localeToAcceptLang converts a libc locale ("de_CH.UTF-8") into an
// Accept-Language header value ("de-ch,de;q=0.7,en;q=0.3").
func localeToAcceptLang(lang string) string {
	bcp := localeToBCP47(lang)
	if bcp == "" {
		return "en-US,en;q=0.5"
	}
	parts := strings.SplitN(bcp, "-", 2)
	primary := parts[0]
	if len(parts) == 2 {
		return fmt.Sprintf("%s,%s;q=0.7,en;q=0.3", strings.ToLower(bcp), primary)
	}
	return fmt.Sprintf("%s,en;q=0.5", primary)
}

// localeToBCP47 converts "de_CH.UTF-8" into "de-CH".
func localeToBCP47(lang string) string {
	s := lang
	if i := strings.Index(s, "."); i >= 0 {
		s = s[:i]
	}
	return strings.ReplaceAll(s, "_", "-")
}

// firefoxRFP turns on Mozilla's resistFingerprinting suite (uniform UA,
// canvas / WebGL / audio / font / screen / hardwareConcurrency
// randomization) plus extra hardening prefs that close adjacent leaks
// not covered by RFP itself.
//
// What this DOESN'T cover: TLS fingerprinting (JA3/JA4), HTTP/2
// SETTINGS frame, TCP-stack fingerprint. Those need either Tor
// Browser's patched build or a TLS-rewriting MITM proxy.
const firefoxRFP = `// Anti-fingerprint (Mozilla RFP + extras).
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.fingerprintingProtection", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.firstparty.isolate", true);

// Network-state partitioning by site (defends against cache-based
// cross-site fingerprinting / supercookies).
user_pref("privacy.partition.network_state", true);
user_pref("privacy.partition.serviceWorkers", true);
user_pref("network.cookie.cookieBehavior", 5);

// WebGL: don't disable outright (breaks too many sites) — RFP randomizes.
user_pref("webgl.disabled", false);
user_pref("webgl.min_capability_mode", true);

// WebRTC: only host candidates; no STUN; no peer connection IP leak.
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.identity.timeout", 1);
user_pref("media.peerconnection.turn.disable", true);
user_pref("media.peerconnection.use_document_iceservers", false);

// Disable APIs that leak hardware / environment / behavior.
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("dom.battery.enabled", false);
user_pref("dom.netinfo.enabled", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vibrator.enabled", false);
user_pref("dom.vr.enabled", false);
user_pref("dom.webaudio.enabled", true);   // RFP randomizes; full disable breaks audio playback
user_pref("device.sensors.enabled", false);
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");

// Tracking pings.
user_pref("browser.send_pings", false);
user_pref("beacon.enabled", false);

// Referrer policies.
user_pref("network.http.referer.spoofSource", true);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// Alt-Svc (Alternative-Services tracking via HTTP/3 advertisements).
user_pref("network.http.altsvc.enabled", false);
user_pref("network.http.altsvc.oe", false);

// Trust the Veil CA (installed in system store via veil mitm install-ca).
// Without this Firefox would reject the CA even if it's in /usr/local/share.
user_pref("security.enterprise_roots.enabled", true);

// Relax HPKP / static-pin enforcement when the chain ends in an
// enterprise root. Without this, Firefox would refuse the substituted
// cert for HPKP-pinned sites (Google, Mozilla, banks). Setting to 0
// disables built-in pin enforcement; relying on cert-chain validation
// alone — which is what every corporate MITM environment does. Same
// behavior Chrome gets implicitly when an enterprise CA is detected.
user_pref("security.cert_pinning.enforcement_level", 0);

// HSTS-preload list: still honored for HTTPS upgrade, but the cert-
// pin enforcement above is what would refuse our substituted cert.
// Leave HSTS at default; only relaxing the pin check.

// Reduce HTTP/2 + HTTP/3 fingerprint surface.
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.predictor.enable-prefetch", false);

// IPv6 leaks: RFP doesn't disable v6, but transparent-Tor mode does.
// We leave this default; transparent-mode handles it at the kernel layer.

// WebSockets stay enabled (sites need them); extension restrictions
// are handled by RFP's webgl.min_capability_mode and friends.

// Hardware-API leaks: kill every API that exposes physical-device info.
user_pref("dom.webusb.enabled", false);
user_pref("dom.webhid.enabled", false);
user_pref("dom.webmidi.enabled", false);
user_pref("dom.serialport.enabled", false);
user_pref("dom.webnfc.enabled", false);
user_pref("dom.webbluetooth.enabled", false);
user_pref("dom.webxr.enabled", false);
user_pref("dom.webgpu.enabled", false);                // Newer than RFP — explicit kill.

// MediaDevices.enumerateDevices() leaks audio/video device names.
user_pref("media.devices.enumerate.legacy.enabled", false);
user_pref("media.navigator.enabled", false);            // getUserMedia overall

// Performance.memory leaks JS heap size — distinguishes hardware tiers.
user_pref("dom.enable_performance_observer", false);
user_pref("dom.enable_resource_timing", false);

// Service workers persist state in a way that survives across sessions
// (cache/scope), giving sites a long-lived identifier.
user_pref("dom.serviceWorkers.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.push.serverURL", "");

// Permissions API: returning real values fingerprints which permissions
// have been asked for. RFP partially handles; explicit silence is safer.
user_pref("permissions.default.geo", 2);                // 2 = always block
user_pref("permissions.default.camera", 2);
user_pref("permissions.default.microphone", 2);
user_pref("permissions.default.desktop-notification", 2);

// HTTP/2 + QUIC fingerprinting reduction (full HTTP/2 spoofing is
// done in our TLS-MITM proxy; this is belt-and-suspenders).
user_pref("network.http.spdy.websockets", false);
user_pref("network.http.http3.enable", false);          // QUIC fingerprint differs from TCP — disable.
user_pref("network.http.http3.enable_kyber", false);
user_pref("network.http.http3.alt-svc-mapping-for-testing", "");

// CRITICAL: DNS-over-HTTPS would let Firefox resolve hostnames
// outside our netns (Cloudflare/NextDNS direct), bypassing the
// chain. Force DoH off (TRR mode 5 = explicitly disabled).
user_pref("network.trr.mode", 5);
user_pref("network.trr.uri", "");
user_pref("network.trr.bootstrapAddress", "");
// Encrypted Client Hello — Firefox may use it independently of
// DoH and leak SNI that we can't see in MITM. Off.
user_pref("network.dns.echconfig.enabled", false);
user_pref("network.dns.use_https_rr_as_altsvc", false);

// Reading-mode and other preview features that fetch out-of-band.
user_pref("reader.parse-on-load.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("browser.search.suggest.enabled", false);

// Disable speech / synthesizer APIs.
user_pref("media.webspeech.synth.enabled", false);
user_pref("media.webspeech.recognition.enable", false);

// Page-visibility timing leaks tab-switch behavior.
user_pref("dom.visibilityAPI.enabled", true);            // sites need it; can't safely disable
`
