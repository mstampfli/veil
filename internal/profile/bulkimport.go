package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BulkImportWG scans a path for WireGuard .conf files and creates one
// profile per file. dataDirRoot, if non-empty, is the root for per-profile
// isolated browser/data dirs (each profile gets <root>/<name>).
//
// Returns the names of profiles created.
func (s *Store) BulkImportWG(path, preset, dataDirRoot string, killSwitch bool) ([]string, error) {
	files, err := scanConfigs(path, ".conf")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .conf files found at %s", path)
	}
	return s.bulk(files, BackendWireGuard, preset, dataDirRoot, killSwitch)
}

// BulkImportOVPN does the same for OpenVPN .ovpn files.
func (s *Store) BulkImportOVPN(path, preset, dataDirRoot string, killSwitch bool) ([]string, error) {
	files, err := scanConfigs(path, ".ovpn")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .ovpn files found at %s", path)
	}
	return s.bulk(files, BackendOpenVPN, preset, dataDirRoot, killSwitch)
}

func (s *Store) bulk(files []string, kind BackendKind, preset, dataDirRoot string, killSwitch bool) ([]string, error) {
	var created []string
	for _, f := range files {
		name := profileNameFromFile(f)
		if name == "" {
			continue
		}
		// Skip if a profile with this name already exists.
		if _, err := s.Load(name); err == nil {
			continue
		}
		dataDir := ""
		if dataDirRoot != "" {
			dataDir = filepath.Join(dataDirRoot, name)
		}
		desc := fmt.Sprintf("Imported from %s", filepath.Base(f))
		p := &Profile{
			Name:        name,
			Description: desc,
			Chain: []Backend{{
				Kind:       kind,
				ConfigPath: f,
			}},
			App: App{
				Preset: preset,
			},
			DataDir:    dataDir,
			KillSwitch: killSwitch,
			// Single-hop WG/OVPN imports default to ip+asn+country
			// locks — peer IP from kernel = exit IP for these
			// provider architectures. Harmless until LockedEndpoint
			// is on; saves the user a config step.
			LockCountry:         true,
			LockASN:             true,
			LockIP:              true,
			GeoVerificationMode: "local",
		}
		if err := s.Save(p); err != nil {
			return created, fmt.Errorf("save %s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, nil
}

// scanConfigs returns config-file paths under path. If path is a single
// file with the matching extension, returns just that.
func scanConfigs(path, ext string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Ext(path), ext) {
			return []string{path}, nil
		}
		return nil, fmt.Errorf("%s is not a %s file", path, ext)
	}
	var out []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ext) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

var nameSanRE = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

// profileNameFromFile makes a valid Veil profile name from a config path.
//
//	mullvad-ch-zrh-wg-001.conf -> mullvad-ch-zrh-wg-001
//	US-NY#21.protonvpn.udp.ovpn -> US-NY-21-protonvpn-udp
func profileNameFromFile(p string) string {
	base := filepath.Base(p)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = nameSanRE.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-_")
	if len(base) > 60 {
		base = base[:60]
	}
	if base == "" {
		return ""
	}
	if !nameRE.MatchString(base) {
		// Force a leading alnum.
		base = "vpn-" + base
	}
	if len(base) > 63 {
		base = base[:63]
	}
	return base
}
