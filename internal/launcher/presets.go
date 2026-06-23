// Package launcher resolves app presets and builds platform-specific
// launch arguments.
package launcher

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/mstampfli/veil/internal/profile"
)

// Preset describes a built-in app launcher (Firefox, Chromium, …).
type Preset struct {
	Name    string
	Linux   PresetCmd
	Windows PresetCmd
	Darwin  PresetCmd
}

type PresetCmd struct {
	// Binary candidates (first found on PATH wins).
	Binaries []string
	// Args returns launch args given a per-profile data dir. May be nil.
	Args func(dataDir string) []string
}

var presets = map[string]Preset{
	"mullvad-browser": {
		Name: "Mullvad Browser (cohort-blending mode — every user looks identical)",
		Linux: PresetCmd{
			// Mullvad Browser is Tor Browser's anti-fingerprint patches
			// without Tor. Designed for UNIFORMITY: all users present
			// the same fingerprint, so an observer can tell "this is a
			// Mullvad Browser user" but cannot single out *which* one.
			// Different goal from veil-browser (per-profile impersonation);
			// use this preset when you want to disappear into a large
			// cohort rather than impersonate a specific identity.
			//
			// Note: Mullvad Browser actively resists persona pinning.
			// Don't pair this preset with a forge_persona profile —
			// the persona JSON is ignored and the prefs are locked.
			Binaries: []string{
				"mullvad-browser",
				"start-mullvad-browser",
				"/opt/mullvad-browser/start-mullvad-browser",
				"/usr/lib/mullvad-browser/start-mullvad-browser",
			},
			Args: func(d string) []string {
				return []string{"--detach"}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{
				`C:\Program Files\Mullvad Browser\Browser\firefox.exe`,
				`C:\Mullvad Browser\Browser\firefox.exe`,
			},
		},
		Darwin: PresetCmd{
			Binaries: []string{
				"/Applications/Mullvad Browser.app/Contents/MacOS/firefox",
			},
		},
	},
	"tor-browser": {
		Name: "Tor Browser",
		Linux: PresetCmd{
			Binaries: []string{
				"torbrowser-launcher",
				"start-tor-browser",
				"tor-browser",
				"/opt/tor-browser/start-tor-browser",
				"/usr/share/tor-browser/start-tor-browser",
			},
			// Tor Browser already routes through its bundled Tor; when
			// run inside a Veil profile that ALSO has a Tor hop, its
			// internal Tor connects through Veil's outer chain. With
			// --unregister-user-handler we avoid the desktop integration
			// dialog. Profile dir is auto-managed by Tor Browser.
			Args: func(d string) []string {
				return []string{"--detach"}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{
				`C:\Program Files\Tor Browser\Browser\firefox.exe`,
				`C:\Tor Browser\Browser\firefox.exe`,
			},
		},
	},
	"firefox": {
		Name: "Firefox",
		Linux: PresetCmd{
			Binaries: []string{"firefox", "firefox-esr", "firefox-developer-edition", "librewolf"},
			Args: func(d string) []string {
				if d == "" {
					return []string{"--no-remote"}
				}
				return []string{"--no-remote", "--profile", d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"firefox.exe", `C:\Program Files\Mozilla Firefox\firefox.exe`},
			Args: func(d string) []string {
				if d == "" {
					return []string{"-no-remote"}
				}
				return []string{"-no-remote", "-profile", d}
			},
		},
	},
	"chromium": {
		Name: "Chromium",
		Linux: PresetCmd{
			Binaries: []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "brave-browser"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
	},
	"brave": {
		Name: "Brave",
		Linux: PresetCmd{
			Binaries: []string{"brave-browser", "brave"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"brave.exe", `C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
	},
	"veil-browser": {
		Name: "Veil Browser (persona-pinned Chromium fork)",
		Linux: PresetCmd{
			// Search order: explicit veil-browser binary → Brave → ungoogled-
			// chromium → chromium → google-chrome. Only the first matches a
			// fork that honors --veil-persona; the others get the flag silently
			// ignored and behave as their stock selves (the persona JSON file
			// is still written but does nothing).
			Binaries: []string{
				"veil-browser",
				"/opt/veil-browser/veil-browser",
				"brave-browser", "brave",
				"ungoogled-chromium",
				"chromium", "chromium-browser",
				"google-chrome", "google-chrome-stable",
			},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{
				"veil-browser.exe",
				`C:\Program Files\Veil Browser\veil-browser.exe`,
				"brave.exe",
				`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`,
				"chrome.exe",
				`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
	},
	"signal": {
		Name: "Signal Desktop",
		Linux: PresetCmd{
			Binaries: []string{"signal-desktop"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"Signal.exe"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
	},
	"telegram": {
		Name: "Telegram",
		Linux: PresetCmd{
			Binaries: []string{"telegram-desktop", "Telegram"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"-workdir", d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"Telegram.exe"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"-workdir", d}
			},
		},
	},
	"element": {
		Name: "Element",
		Linux: PresetCmd{
			Binaries: []string{"element-desktop"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--profile-dir", d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"Element.exe"},
		},
	},
	"bitwarden": {
		Name: "Bitwarden",
		Linux: PresetCmd{
			Binaries: []string{"bitwarden", "bitwarden-desktop", "Bitwarden"},
			Args: func(d string) []string {
				if d == "" {
					return nil
				}
				return []string{"--user-data-dir=" + d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"Bitwarden.exe"},
		},
	},
	"keepassxc": {
		Name: "KeePassXC",
		Linux: PresetCmd{
			Binaries: []string{"keepassxc"},
		},
		Windows: PresetCmd{
			Binaries: []string{"KeePassXC.exe", `C:\Program Files\KeePassXC\KeePassXC.exe`},
		},
	},
	"thunderbird": {
		Name: "Thunderbird",
		Linux: PresetCmd{
			Binaries: []string{"thunderbird"},
			Args: func(d string) []string {
				if d == "" {
					return []string{"--no-remote"}
				}
				return []string{"--no-remote", "--profile", d}
			},
		},
		Windows: PresetCmd{
			Binaries: []string{"thunderbird.exe", `C:\Program Files\Mozilla Thunderbird\thunderbird.exe`},
		},
	},
	"shell": {
		Name: "Shell",
		Linux: PresetCmd{
			Binaries: []string{"bash", "sh"},
		},
		Windows: PresetCmd{
			Binaries: []string{"powershell.exe", "cmd.exe"},
		},
	},
	"curl": {
		Name: "curl",
		Linux: PresetCmd{
			Binaries: []string{"curl"},
		},
		Windows: PresetCmd{
			Binaries: []string{"curl.exe"},
		},
	},
}

// Presets returns names of all known presets.
func Presets() []string {
	out := make([]string, 0, len(presets))
	for k := range presets {
		out = append(out, k)
	}
	return out
}

// Resolve fills in App.Binary/App.Args from the preset, if a preset is set
// and Binary is empty. Returns the (possibly modified) Profile pointer.
func Resolve(p *profile.Profile) error {
	if p.App.Preset == "" {
		return nil
	}
	preset, ok := presets[p.App.Preset]
	if !ok {
		return fmt.Errorf("unknown preset %q (try: %v)", p.App.Preset, Presets())
	}
	cmd := preset.Linux
	switch runtime.GOOS {
	case "windows":
		cmd = preset.Windows
	case "darwin":
		cmd = preset.Darwin
	}
	if len(cmd.Binaries) == 0 {
		return fmt.Errorf("preset %q not available on %s", p.App.Preset, runtime.GOOS)
	}
	if p.App.Binary == "" {
		for _, cand := range cmd.Binaries {
			if path, err := exec.LookPath(cand); err == nil {
				p.App.Binary = path
				break
			}
		}
		if p.App.Binary == "" {
			return fmt.Errorf("preset %q: none of %v found on PATH", p.App.Preset, cmd.Binaries)
		}
	}
	// DataDir defaulting for browser presets is handled in the engine —
	// it knows the target user's home directory after privilege drop.
	if len(p.App.Args) == 0 && cmd.Args != nil {
		p.App.Args = cmd.Args(p.DataDir)
	}
	return nil
}

// IsBrowserPreset reports whether a preset launches a browser whose
// profile/data directory should be isolated per Veil profile.
func IsBrowserPreset(name string) bool {
	switch name {
	case "firefox", "chromium", "brave", "veil-browser", "thunderbird",
		"tor-browser", "mullvad-browser":
		return true
	}
	return false
}

// IsChromiumPreset reports whether a preset launches a Chromium-based
// browser (controls whether --veil-persona is appended to args).
func IsChromiumPreset(name string) bool {
	switch name {
	case "chromium", "brave", "veil-browser":
		return true
	}
	return false
}
