// Package veilbrowser bridges Veil's persona system to the veil-browser
// fork. It writes a persona.json into the profile's data dir and
// supplies the binary path + flags Veil passes when launching.
//
// veil-browser is a Brave-derived Chromium fork that pins fingerprint-
// relevant values to the JSON contents at the C++ layer. See the
// veil-browser/ project at the repo root for build instructions.
package veilbrowser

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/mstampfli/veil/internal/osutil"
	"github.com/mstampfli/veil/internal/persona"
)

// PersonaJSON is the on-disk schema veil-browser reads from
// --veil-persona=<path>. Keep field tags in sync with
// veil-browser/src/veil_persona.cc::ParseInto().
type PersonaJSON struct {
	UserAgent           string         `json:"user_agent,omitempty"`
	Platform            string         `json:"platform,omitempty"`
	Vendor              string         `json:"vendor,omitempty"`
	VendorSub           string         `json:"vendor_sub,omitempty"`
	ProductSub          string         `json:"product_sub,omitempty"`
	OSCPU               string         `json:"oscpu,omitempty"`
	AppVersion          string         `json:"app_version,omitempty"`
	WebDriver           bool           `json:"webdriver"`
	Engine              string         `json:"engine,omitempty"` // "blink" | "gecko" | "webkit"
	HardwareConcurrency int            `json:"hardware_concurrency,omitempty"`
	DeviceMemory        int            `json:"device_memory,omitempty"`
	MaxTouchPoints      int            `json:"max_touch_points"`
	Screen              ScreenJSON     `json:"screen,omitempty"`
	Timezone            string         `json:"timezone,omitempty"`
	Locale              string         `json:"locale,omitempty"`
	Languages           []string       `json:"languages,omitempty"`
	ClientHints         *ClientHintsJSON `json:"client_hints,omitempty"`
	WebGL               *WebGLJSON     `json:"webgl,omitempty"`
	AudioSeed           string         `json:"audio_seed,omitempty"`  // string-encoded uint64
	CanvasSeed          string         `json:"canvas_seed,omitempty"`
	FontSeed            string         `json:"font_seed,omitempty"`
}

type ScreenJSON struct {
	Width            int     `json:"width,omitempty"`
	Height           int     `json:"height,omitempty"`
	AvailWidth       int     `json:"avail_width,omitempty"`
	AvailHeight      int     `json:"avail_height,omitempty"`
	ColorDepth       int     `json:"color_depth,omitempty"`
	PixelDepth       int     `json:"pixel_depth,omitempty"`
	DevicePixelRatio float64 `json:"device_pixel_ratio,omitempty"`
}

type ClientHintsJSON struct {
	Platform        string             `json:"platform,omitempty"`
	PlatformVersion string             `json:"platform_version,omitempty"`
	Architecture    string             `json:"architecture,omitempty"`
	Bitness         string             `json:"bitness,omitempty"`
	Model           string             `json:"model,omitempty"`
	WoW64           bool               `json:"wow64,omitempty"`
	Mobile          bool               `json:"mobile,omitempty"`
	FullVersionList []BrandVersionJSON `json:"full_version_list,omitempty"`
}

type BrandVersionJSON struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type WebGLJSON struct {
	Vendor           string `json:"vendor,omitempty"`
	Renderer         string `json:"renderer,omitempty"`
	UnmaskedVendor   string `json:"unmasked_vendor,omitempty"`
	UnmaskedRenderer string `json:"unmasked_renderer,omitempty"`
}

// FromPersona converts a Veil persona to the on-disk JSON schema. All
// fingerprint-relevant fields propagate; missing fields stay empty
// (veil-browser falls back to upstream/Brave behavior for those).
func FromPersona(p *persona.Persona) PersonaJSON {
	if p == nil {
		return PersonaJSON{}
	}
	out := PersonaJSON{
		UserAgent:           p.UserAgent,
		Platform:            p.Platform,
		Vendor:              p.Vendor,
		VendorSub:           p.VendorSub,
		ProductSub:          p.ProductSub,
		OSCPU:               p.OSCPU,
		AppVersion:          p.AppVersion,
		WebDriver:           false,
		Engine:              normalizeEngine(p.Engine),
		HardwareConcurrency: p.HardwareConcurrency,
		DeviceMemory:        p.DeviceMemory,
		MaxTouchPoints:      p.MaxTouchPoints,
		Timezone:            p.Timezone,
		Locale:              localeBCP47(p.Locale),
		Languages:           parseAcceptLanguage(p.AcceptLanguage),
	}
	if p.ScreenWidth > 0 {
		out.Screen = ScreenJSON{
			Width:            p.ScreenWidth,
			Height:           p.ScreenHeight,
			AvailWidth:       p.ScreenWidth,
			AvailHeight:      p.ScreenHeight - 40, // typical taskbar offset
			ColorDepth:       coalesce(p.ColorDepth, 24),
			PixelDepth:       coalesce(p.ColorDepth, 24),
			DevicePixelRatio: p.DevicePixelRatio,
		}
	}
	if p.WebGLVendor != "" || p.WebGLRenderer != "" || p.WebGLUnmaskedVendor != "" || p.WebGLUnmaskedRenderer != "" {
		out.WebGL = &WebGLJSON{
			Vendor:           p.WebGLVendor,
			Renderer:         p.WebGLRenderer,
			UnmaskedVendor:   p.WebGLUnmaskedVendor,
			UnmaskedRenderer: p.WebGLUnmaskedRenderer,
		}
	}
	if p.ClientHints != nil {
		ch := &ClientHintsJSON{
			Platform:        p.ClientHints.Platform,
			PlatformVersion: p.ClientHints.PlatformVersion,
			Architecture:    p.ClientHints.Architecture,
			Bitness:         p.ClientHints.Bitness,
			Model:           p.ClientHints.Model,
			WoW64:           p.ClientHints.WoW64,
			Mobile:          p.ClientHints.Mobile,
		}
		for _, b := range p.ClientHints.FullVersionList {
			ch.FullVersionList = append(ch.FullVersionList, BrandVersionJSON{
				Brand: b.Brand, Version: b.Version,
			})
		}
		out.ClientHints = ch
	}
	// Deterministic farbling seeds: same persona → same canvas/audio/
	// font output, regardless of session or origin. This is the opposite
	// of Brave's per-session randomization and is required for reliable
	// impersonation.
	out.AudioSeed = seedFromName(p.Name, "audio")
	out.CanvasSeed = seedFromName(p.Name, "canvas")
	out.FontSeed = seedFromName(p.Name, "font")
	return out
}

// Write writes the persona JSON to <dataDir>/persona.json and returns
// the absolute path. Callers (the launcher) pass it via
// --veil-persona=<path> when launching veil-browser.
func Write(dataDir string, p *persona.Persona) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("veilbrowser.Write: dataDir empty")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	pj := FromPersona(p)
	data, err := json.MarshalIndent(pj, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, "persona.json")
	if err := osutil.WriteFileAtomic(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Binary returns the path to the veil-browser binary, or empty string
// if not found. Search order:
//  1. $VEIL_BROWSER_BIN (explicit override)
//  2. "veil-browser" in $PATH
//  3. "brave" / "brave-browser" / "chromium" / "google-chrome" as
//     last-resort fallbacks (they won't honor --veil-persona but they
//     won't error on the unknown flag either; values fall back to
//     upstream behavior).
func Binary() string {
	if p := os.Getenv("VEIL_BROWSER_BIN"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, name := range []string{"veil-browser", "brave-browser", "brave", "chromium", "chromium-browser", "google-chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

// IsVeilBrowser reports whether the supplied binary path is the
// veil-browser fork (vs a stock Chromium / Brave fallback). Used by
// callers that want to enable persona JSON output only when a real
// veil-browser is present.
func IsVeilBrowser(bin string) bool {
	if bin == "" {
		return false
	}
	base := filepath.Base(bin)
	return base == "veil-browser"
}

// localeBCP47 converts a libc locale ("de_CH.UTF-8") into a BCP-47
// language tag ("de-CH"). Empty input yields empty output.
func localeBCP47(lang string) string {
	if lang == "" {
		return ""
	}
	s := lang
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			s = s[:i]
			break
		}
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			out[i] = '-'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

// parseAcceptLanguage extracts the bare language tags from an Accept-
// Language header value. "de-CH,de;q=0.7,en;q=0.3" → ["de-CH","de","en"].
func parseAcceptLanguage(al string) []string {
	if al == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(al); i++ {
		if i == len(al) || al[i] == ',' {
			tok := al[start:i]
			// strip leading whitespace and any ;q=... suffix
			for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') {
				tok = tok[1:]
			}
			if j := indexByte(tok, ';'); j >= 0 {
				tok = tok[:j]
			}
			if tok != "" {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// seedFromName derives a deterministic uint64 seed from the persona
// name + a category tag. Returned as a decimal string because the
// JSON schema uses string encoding for seeds (avoids double precision
// loss on the C++ side).
func seedFromName(name, kind string) string {
	if name == "" {
		return ""
	}
	h := sha256.Sum256([]byte(name + ":" + kind))
	v := binary.BigEndian.Uint64(h[:8])
	if v == 0 {
		v = 1 // 0 is the "no seed" sentinel on the C++ side
	}
	return fmt.Sprintf("%d", v)
}

func coalesce(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

// normalizeEngine maps user-friendly aliases to the three canonical
// engine kinds the C++ side understands.
func normalizeEngine(e string) string {
	switch e {
	case "gecko", "firefox", "Gecko", "Firefox":
		return "gecko"
	case "webkit", "safari", "WebKit", "Safari":
		return "webkit"
	case "", "blink", "chromium", "chrome":
		return "" // empty = default = blink
	default:
		return ""
	}
}
