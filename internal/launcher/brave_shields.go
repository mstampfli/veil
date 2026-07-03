package launcher

// Brave Shields pre-population for AntiFingerprint mode.
//
// Brave's farbling — per-eTLD per-session randomization of canvas,
// audio, fonts, WebGL strings, hardware values — is the closest thing
// Chromium-family has to Firefox's RFP. Default install is "Standard"
// strength; we want "Aggressive" (max). Brave doesn't expose the level
// as a CLI flag, but the setting lives in the per-profile Preferences
// JSON file, which we can write BEFORE the browser starts.
//
// Strategy:
//   1. Before launch, ensure <data_dir>/Default/ exists.
//   2. Read existing Preferences (if any) so we don't clobber user
//      settings on subsequent launches.
//   3. Merge in our shields-aggressive defaults.
//   4. Write back.
//
// Best-effort: schema versions across Brave releases shift; if some
// keys are ignored, the CLI flags in browser_config.go provide
// belt-and-suspenders coverage. Failure to write Preferences doesn't
// abort launch — the browser will run, just with weaker shields.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// chromiumAntiFingerprintPrefs writes / merges Brave Shields settings
// into the data_dir's Preferences JSON. Caller is responsible for
// determining when to invoke this (typically: AntiFingerprint=true
// AND IsChromiumPreset=true).
//
// Returns nil on success or "soft" failures (no data_dir, perms);
// returns an error only when something genuinely surprising happens.
// Either way the caller proceeds with launch — Preferences are best-
// effort hardening, not load-bearing.
func chromiumAntiFingerprintPrefs(dataDir string) error {
	return writeChromiumPrefs(dataDir, true)
}

// chromiumBasePrefs writes the always-on Chromium hardening prefs
// (DNT header, safebrowsing off, autofill off, search-suggest off,
// alternate-error-pages off, WebRTC IP-handling locked down) without
// the Brave-Shields-aggressive parts. Used for every Chromium-family
// launch so DNT-style fingerprint flags are addressed even when the
// profile doesn't have anti_fingerprint=strict.
func chromiumBasePrefs(dataDir string) error {
	return writeChromiumPrefs(dataDir, false)
}

// writeChromiumPrefs is the shared backend for both prefs writers.
// braveShields=true also injects Brave's per-eTLD farbling and
// fingerprinting/cookie/tracker exceptions. braveShields=false
// produces the minimal "stop nagging me" baseline.
func writeChromiumPrefs(dataDir string, braveShields bool) error {
	if dataDir == "" {
		return nil
	}
	// "Default" is the per-profile subdirectory inside the user-data-dir
	// where Chromium stores per-profile state. With --user-data-dir=X,
	// the active profile lives at X/Default/.
	profileDir := filepath.Join(dataDir, "Default")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return err
	}
	prefsPath := filepath.Join(profileDir, "Preferences")

	// Load existing prefs if present so we don't wipe user state on
	// subsequent launches.
	prefs := map[string]any{}
	if data, err := os.ReadFile(prefsPath); err == nil {
		_ = json.Unmarshal(data, &prefs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Helper: ensure m[key] is a map, creating if missing.
	mp := func(m map[string]any, key string) map[string]any {
		if v, ok := m[key].(map[string]any); ok {
			return v
		}
		nm := map[string]any{}
		m[key] = nm
		return nm
	}

	profile := mp(prefs, "profile")

	if braveShields {
		cs := mp(profile, "content_settings")
		exceptions := mp(cs, "exceptions")

		// last_modified is an arbitrary "WebKit timestamp" in microseconds
		// since 1601. Anything in the past works; Brave just needs a value
		// that beats the default (which is 0 / unset).
		const ts = "13380000000000000"

		// Brave Shields content-setting types. Each is a key under
		// "exceptions"; the wildcard "*,*" means "applies to all sites".
		//
		// setting values:
		//   1 = "Allow" (block trackers, off)
		//   2 = "Block" (Aggressive — full shields)
		//   3 = "Ask" (n/a here)
		//
		// Multiple keys are touched because Brave's shields are split
		// across several content-setting types in the modern schema.
		for _, key := range []string{
			"brave-fingerprinting-v2", // The main one we care about: Aggressive farbling.
			"brave-shields",           // Master shields toggle
			"brave-cookies",           // Block third-party cookies
			"brave-trackers",          // Block trackers
			"brave-https-upgrades",    // Force HTTPS where possible
			"brave-referrers",         // Reduce referrer granularity
		} {
			k := mp(exceptions, key)
			k["*,*"] = map[string]any{
				"setting":       2,
				"expiration":    "0",
				"last_modified": ts,
				"model":         0,
			}
		}

		// Brave-specific top-level prefs: turn off Rewards, Wallet, AI,
		// Talk, news, sponsored content — every "phone home" surface that
		// could leak even with Shields on.
		brave := mp(prefs, "brave")
		for k, v := range map[string]any{
			"rewards": map[string]any{"enabled": false},
			"wallet":  map[string]any{"auto_lock_minutes": 1},
			"new_tab_page": map[string]any{
				"show_branded_background_image": false,
				"show_brave_news":               false,
				"show_clock":                    false,
				"show_rewards":                  false,
				"show_stats":                    false,
			},
			"talk": map[string]any{"disabled_by_policy": true},
			"shields": map[string]any{
				"advanced_view_enabled": true,
				"stats_badge_visible":   false,
			},
			"news":    map[string]any{"opted_in": false},
			"ai_chat": map[string]any{"opt_in": false},
		} {
			brave[k] = v
		}
	}

	// WebRTC IP handling: belt to the suspenders the CLI flag wears.
	// 4 = "default_public_interface_only" — never reveal local IPs.
	mp(profile, "webrtc")["ip_handling_policy"] = "default_public_interface_only"
	mp(profile, "webrtc")["multiple_routes_enabled"] = false
	mp(profile, "webrtc")["nonproxied_udp_enabled"] = false

	// Spell-check, autofill, address book — these can phone home
	// for suggestions or to remote dictionaries.
	if sc := mp(profile, "spellcheck"); sc != nil {
		sc["dictionaries"] = []any{}
		sc["use_spelling_service"] = false
	}
	mp(profile, "autofill")["enabled"] = false
	mp(profile, "search")["suggest_enabled"] = false
	mp(profile, "alternate_error_pages")["enabled"] = false
	mp(profile, "safebrowsing")["enabled"] = false // Google Safe Browsing pings

	// Do Not Track header. Whoer-style scanners flag the absence as
	// "tracking-block disabled". Header-only signal — costs nothing,
	// just makes the test sites stop nagging.
	prefs["enable_do_not_track"] = true

	out, err := json.MarshalIndent(prefs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(prefsPath, out, 0o600)
}
