package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportMullvad scans common Mullvad config locations (or the user-provided
// dir) for WireGuard configs and creates one Veil profile per server.
//
// Mullvad gives users WireGuard config archives named e.g. "mullvad-ch-zrh-wg-001.conf".
// The basename is used as the profile name, with the "mullvad-" prefix stripped.
func (s *Store) ImportMullvad(dir, preset string, killSwitch bool) ([]string, error) {
	if dir == "" {
		dir = guessMullvadDir()
	}
	files, err := scanConfigs(dir, ".conf")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no Mullvad .conf files found at %s — download them from https://mullvad.net/account/wireguard-config/ and unzip", dir)
	}
	return s.bulkProvider(files, BackendWireGuard, preset, killSwitch, "mullvad-", "")
}

// ImportProton scans for ProtonVPN WireGuard configs.
//
// Proton names their files "<COUNTRY>-<CITY>-<NUM>.conf".
func (s *Store) ImportProton(dir, preset string, killSwitch bool) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("ProtonVPN: provide a directory (no standard download path)")
	}
	files, err := scanConfigs(dir, ".conf")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no ProtonVPN .conf files at %s — download from https://account.protonvpn.com/downloads", dir)
	}
	return s.bulkProvider(files, BackendWireGuard, preset, killSwitch, "", "proton-")
}

// ImportIVPN scans for IVPN WireGuard configs.
func (s *Store) ImportIVPN(dir, preset string, killSwitch bool) ([]string, error) {
	if dir == "" {
		return nil, fmt.Errorf("IVPN: provide a directory")
	}
	files, err := scanConfigs(dir, ".conf")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no IVPN .conf files at %s", dir)
	}
	return s.bulkProvider(files, BackendWireGuard, preset, killSwitch, "ivpn-", "")
}

// bulkProvider is the same as bulk() but applies a name prefix-strip + a
// rename prefix so profile names stay short and provider-prefixed.
func (s *Store) bulkProvider(files []string, kind BackendKind, preset string, killSwitch bool, stripPrefix, addPrefix string) ([]string, error) {
	var created []string
	for _, f := range files {
		name := profileNameFromFile(f)
		if stripPrefix != "" {
			name = strings.TrimPrefix(name, stripPrefix)
		}
		if addPrefix != "" && !strings.HasPrefix(name, addPrefix) {
			name = addPrefix + name
		}
		if name == "" {
			continue
		}
		if _, err := s.Load(name); err == nil {
			continue // already imported
		}
		p := &Profile{
			Name:        name,
			Description: "Imported from " + filepath.Base(f),
			Chain: []Backend{{
				Kind:       kind,
				ConfigPath: f,
			}},
			App:        App{Preset: preset},
			KillSwitch: killSwitch,
		}
		if err := s.Save(p); err != nil {
			return created, fmt.Errorf("save %s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, nil
}

// guessMullvadDir returns the most likely default location for Mullvad
// WireGuard configs.
func guessMullvadDir() string {
	for _, p := range []string{
		"/etc/wireguard",
		"~/Downloads/mullvad-wireguard",
	} {
		if strings.HasPrefix(p, "~/") {
			home, _ := os.UserHomeDir()
			p = filepath.Join(home, p[2:])
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/etc/wireguard"
}
