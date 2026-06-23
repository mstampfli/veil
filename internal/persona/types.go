// Package persona models a reusable browser identity (UA, locale, TZ,
// screen size, platform) that can be applied to any profile. The data
// is browser-agnostic; launcher.ApplyPersona translates it to whatever
// the actual browser understands (Firefox prefs, Chromium flags, env
// vars).
//
// This file holds the PUBLIC data shapes only. They are referenced by
// the engine, launcher, GUI, and CLI and are not themselves the IP, so
// they stay in the free build (untagged). The real algorithm (the forge
// generator, the bundled persona library, and the store apply/load
// logic) lives behind //go:build pro; the free build ships no-op/error
// stubs in stub.go.
package persona

import "time"

// Persona is the data we apply at launch to make the browser look like
// a specific identity. None of these fields are required -- leaving one
// blank means "don't override".
type Persona struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	UserAgent      string `yaml:"user_agent,omitempty" json:"user_agent,omitempty"`
	AcceptLanguage string `yaml:"accept_language,omitempty" json:"accept_language,omitempty"`
	Locale         string `yaml:"locale,omitempty" json:"locale,omitempty"`
	Timezone       string `yaml:"timezone,omitempty" json:"timezone,omitempty"`

	// Platform identifier as the browser would expose via navigator.platform
	// (e.g. "Linux x86_64", "MacIntel", "Win32", "iPhone"). Currently
	// only Firefox honors it (general.platform.override) and Chromium
	// just inherits from --user-agent.
	Platform string `yaml:"platform,omitempty" json:"platform,omitempty"`

	// Screen dimensions for sites that key off window.screen.*. Firefox
	// can override via privacy.window.maxInnerWidth/Height when RFP
	// is on; for now we use these as launch flags (Chromium --window-size).
	ScreenWidth      int     `yaml:"screen_width,omitempty" json:"screen_width,omitempty"`
	ScreenHeight     int     `yaml:"screen_height,omitempty" json:"screen_height,omitempty"`
	DevicePixelRatio float64 `yaml:"device_pixel_ratio,omitempty" json:"device_pixel_ratio,omitempty"`

	// HardwareConcurrency value for navigator.hardwareConcurrency.
	HardwareConcurrency int `yaml:"hardware_concurrency,omitempty" json:"hardware_concurrency,omitempty"`

	// Extended identity fields used by veil-browser (the patched
	// Chromium fork). Stock browsers either ignore them or pick up a
	// subset (e.g. Firefox honors OSCPU via general.oscpu.override).

	Vendor         string `yaml:"vendor,omitempty" json:"vendor,omitempty"`           // navigator.vendor
	VendorSub      string `yaml:"vendor_sub,omitempty" json:"vendor_sub,omitempty"`   // navigator.vendorSub
	ProductSub     string `yaml:"product_sub,omitempty" json:"product_sub,omitempty"` // navigator.productSub
	OSCPU          string `yaml:"oscpu,omitempty" json:"oscpu,omitempty"`             // navigator.oscpu (Firefox)
	AppVersion     string `yaml:"app_version,omitempty" json:"app_version,omitempty"` // navigator.appVersion
	DeviceMemory   int    `yaml:"device_memory,omitempty" json:"device_memory,omitempty"`
	MaxTouchPoints int    `yaml:"max_touch_points,omitempty" json:"max_touch_points,omitempty"`
	ColorDepth     int    `yaml:"color_depth,omitempty" json:"color_depth,omitempty"`

	WebGLVendor           string `yaml:"webgl_vendor,omitempty" json:"webgl_vendor,omitempty"`
	WebGLRenderer         string `yaml:"webgl_renderer,omitempty" json:"webgl_renderer,omitempty"`
	WebGLUnmaskedVendor   string `yaml:"webgl_unmasked_vendor,omitempty" json:"webgl_unmasked_vendor,omitempty"`
	WebGLUnmaskedRenderer string `yaml:"webgl_unmasked_renderer,omitempty" json:"webgl_unmasked_renderer,omitempty"`

	// Country is the ISO 3166-1 alpha-2 code (DE, US, JP, ...) the
	// persona claims to live in. Used to anchor the network exit:
	// when Profile.LockedEndpoint is on, the engine refuses to launch
	// unless the actual exit IP geolocates to this country. Prevents
	// "Berlin Chrome user exiting through New York" inconsistency
	// across sessions, which is a correlation signal.
	//
	// Auto-derived from Locale by Forge (en_US -> US, de_DE -> DE).
	Country string `yaml:"country,omitempty" json:"country,omitempty"`

	// Engine selects which browser engine SHAPE to impersonate. Veil-
	// browser is a Chromium fork at the binary level -- but with the
	// right surface-spoofing patches it can present as Gecko (Firefox)
	// or WebKit (Safari) at the JS/DOM layer.
	//
	//   "blink"  (default) -- no engine spoofing; values pinned only
	//   "gecko"  -- adds Firefox-only globals (InstallTrigger,
	//              mozInnerScreen*, mozPaintCount), Gecko-style
	//              Function.prototype.toString output, SpiderMonkey-
	//              style error messages
	//   "webkit" -- adds Safari-only globals (webkit* prefixes,
	//              ApplePay APIs), WebKit-style Function.toString,
	//              JavaScriptCore-style error messages
	//
	// CAVEAT: even with engine spoofing, a small fraction of deep
	// checks (JIT compile timing, GC pause histograms) still detect the
	// underlying V8/Blink. Engine spoofing is for the bulk of detectors
	// that probe the surface (globals, error text, toString format).
	Engine string `yaml:"engine,omitempty" json:"engine,omitempty"`

	// Client Hints (sec-ch-ua-* headers + navigator.userAgentData).
	ClientHints *ClientHints `yaml:"client_hints,omitempty" json:"client_hints,omitempty"`

	CreatedAt time.Time `yaml:"created_at,omitempty" json:"created_at,omitempty"`
	UpdatedAt time.Time `yaml:"updated_at,omitempty" json:"updated_at,omitempty"`
}

// ClientHints describes the sec-ch-ua-* values reported by the browser
// (used by veil-browser to pin navigator.userAgentData and request
// headers).
type ClientHints struct {
	Platform        string             `yaml:"platform,omitempty" json:"platform,omitempty"` // "Windows", "macOS", "Linux", "Android", "iOS"
	PlatformVersion string             `yaml:"platform_version,omitempty" json:"platform_version,omitempty"`
	Architecture    string             `yaml:"architecture,omitempty" json:"architecture,omitempty"` // "x86", "arm"
	Bitness         string             `yaml:"bitness,omitempty" json:"bitness,omitempty"`           // "64", "32"
	Model           string             `yaml:"model,omitempty" json:"model,omitempty"`               // empty for desktop
	Mobile          bool               `yaml:"mobile,omitempty" json:"mobile,omitempty"`
	WoW64           bool               `yaml:"wow64,omitempty" json:"wow64,omitempty"`
	FullVersionList []ClientHintsBrand `yaml:"full_version_list,omitempty" json:"full_version_list,omitempty"`
}

// ClientHintsBrand is a single (brand, version) tuple in the
// brand_version_list (used to render "Chromium";v="134", ...).
type ClientHintsBrand struct {
	Brand   string `yaml:"brand" json:"brand"`
	Version string `yaml:"version" json:"version"`
}

// Store persists personas to disk. The directory is the only state; the
// real I/O methods (Load/Save/etc.) and the bundled seed library live in
// the Pro build, with error stubs in the free build.
type Store struct{ Dir string }

// ForgeOptions lets callers pin specific fields at forge time so the
// generated persona aligns with operational reality (e.g. matches
// the country of the WireGuard endpoint the profile uses).
//
// Empty fields fall through to the deterministic distribution so
// Forge(name) is equivalent to ForgeWith(name, ForgeOptions{}).
//
// FormFactor / OS / Browser are CONSTRAINED -- incoherent combinations
// (e.g. desktop+android, ios+firefox) return an error from Validate.
type ForgeOptions struct {
	// Country (ISO 3166-1 alpha-2) overrides the locale distribution
	// pick. Forge then chooses a locale entry matching this country
	// (if available) or fabricates one with sensible defaults.
	Country string

	// FormFactor: "desktop" | "mobile" | "" (auto). Filters OS picks
	// when OS is unspecified; rejects incoherent OS pins (e.g.
	// FormFactor=desktop + OS=android -> error).
	FormFactor string

	// OS: "windows" | "macos" | "linux" | "android" | "ios" | "".
	// When empty, picked from the OS distribution filtered by FormFactor.
	OS string

	// Browser: "chrome" | "firefox" | "safari" | "edge" | "".
	// When empty, picked from the per-OS browser distribution for the
	// chosen OS. Validated against ValidBrowsersForOS.
	Browser string

	// Seed: arbitrary string mixed into the deterministic stream.
	// Used by the GUI's "re-roll" button so the same profile name
	// can produce different forged personas without renaming the
	// profile. Empty seed = original deterministic-from-name behavior.
	Seed string
}

// ForgeCatalog enumerates the GUI-facing option universe so the
// frontend can populate dropdowns without hardcoding the lists.
type ForgeCatalog struct {
	FormFactors  []string            `json:"form_factors"`
	OSes         []string            `json:"oses"`
	OSesByForm   map[string][]string `json:"oses_by_form"`
	Browsers     []string            `json:"browsers"`
	BrowsersByOS map[string][]string `json:"browsers_by_os"`
	Countries    []ForgeCountry      `json:"countries"`
}

// ForgeCountry is a (code, display name) pair for the catalog's country
// dropdown.
type ForgeCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}
