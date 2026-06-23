package veilbrowser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mstampfli/veil/internal/persona"
)

func TestFromPersonaWindowsChrome(t *testing.T) {
	p := &persona.Persona{
		Name:                "windows-chrome",
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		AcceptLanguage:      "en-US,en;q=0.9",
		Locale:              "en_US.UTF-8",
		Timezone:            "America/New_York",
		Platform:            "Win32",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		DevicePixelRatio:    1.0,
		HardwareConcurrency: 8,
		Vendor:              "Google Inc.",
		ProductSub:          "20030107",
		OSCPU:               "Windows NT 10.0; Win64; x64",
		DeviceMemory:        8,
		ColorDepth:          24,
		WebGLVendor:         "Google Inc. (Intel)",
		WebGLRenderer:       "ANGLE (Intel)",
		WebGLUnmaskedVendor: "Intel Inc.",
		WebGLUnmaskedRenderer: "Intel UHD",
		ClientHints: &persona.ClientHints{
			Platform:        "Windows",
			PlatformVersion: "15.0.0",
			Architecture:    "x86",
			Bitness:         "64",
			FullVersionList: []persona.ClientHintsBrand{
				{Brand: "Chromium", Version: "134.0.0.0"},
			},
		},
	}
	pj := FromPersona(p)
	if pj.UserAgent != p.UserAgent {
		t.Errorf("user_agent mismatch: %q vs %q", pj.UserAgent, p.UserAgent)
	}
	if pj.Vendor != "Google Inc." {
		t.Errorf("vendor not propagated: %q", pj.Vendor)
	}
	if pj.Screen.Width != 1920 || pj.Screen.Height != 1080 {
		t.Errorf("screen mismatch: %+v", pj.Screen)
	}
	if pj.Screen.ColorDepth != 24 {
		t.Errorf("color_depth not set: %d", pj.Screen.ColorDepth)
	}
	if pj.WebGL == nil || pj.WebGL.UnmaskedRenderer != "Intel UHD" {
		t.Errorf("webgl mismatch: %+v", pj.WebGL)
	}
	if pj.ClientHints == nil || pj.ClientHints.Platform != "Windows" {
		t.Errorf("client_hints mismatch: %+v", pj.ClientHints)
	}
	if len(pj.ClientHints.FullVersionList) != 1 {
		t.Errorf("brand list not propagated")
	}
	if pj.AudioSeed == "" || pj.CanvasSeed == "" || pj.FontSeed == "" {
		t.Errorf("seeds not generated: audio=%q canvas=%q font=%q",
			pj.AudioSeed, pj.CanvasSeed, pj.FontSeed)
	}
	if !strings.Contains(strings.Join(pj.Languages, ","), "en-US") {
		t.Errorf("languages not parsed: %v", pj.Languages)
	}
}

func TestSeedsDeterministic(t *testing.T) {
	p1 := &persona.Persona{Name: "alpha"}
	p2 := &persona.Persona{Name: "alpha"}
	p3 := &persona.Persona{Name: "beta"}

	a := FromPersona(p1)
	b := FromPersona(p2)
	c := FromPersona(p3)

	if a.CanvasSeed != b.CanvasSeed || a.AudioSeed != b.AudioSeed {
		t.Errorf("same persona name should produce identical seeds")
	}
	if a.CanvasSeed == c.CanvasSeed {
		t.Errorf("different persona names should produce different seeds")
	}
}

func TestWriteRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := &persona.Persona{
		Name:      "test",
		UserAgent: "TestAgent/1.0",
		Platform:  "Win32",
		Timezone:  "Europe/Berlin",
	}
	path, err := Write(dir, p)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if filepath.Base(path) != "persona.json" {
		t.Errorf("unexpected path: %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var pj PersonaJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pj.UserAgent != "TestAgent/1.0" {
		t.Errorf("roundtrip lost user_agent: %q", pj.UserAgent)
	}
	if pj.Timezone != "Europe/Berlin" {
		t.Errorf("roundtrip lost timezone: %q", pj.Timezone)
	}
}

func TestParseAcceptLanguage(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"en-US,en;q=0.9", []string{"en-US", "en"}},
		{"de-CH,de;q=0.7,en;q=0.3", []string{"de-CH", "de", "en"}},
		{"", nil},
	}
	for _, c := range cases {
		got := parseAcceptLanguage(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseAcceptLanguage(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseAcceptLanguage(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestLocaleBCP47(t *testing.T) {
	cases := map[string]string{
		"en_US.UTF-8":    "en-US",
		"de_CH":          "de-CH",
		"":               "",
		"fr_FR.ISO88591": "fr-FR",
	}
	for in, want := range cases {
		if got := localeBCP47(in); got != want {
			t.Errorf("localeBCP47(%q) = %q, want %q", in, got, want)
		}
	}
}
