package profile

import (
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Store loads and saves profiles from a directory.
type Store struct {
	Dir string
}

// DefaultStore returns a Store rooted at the platform's user config dir.
//
//	Linux:   $XDG_CONFIG_HOME/veil/profiles or ~/.config/veil/profiles
//	Windows: %APPDATA%\veil\profiles
//	macOS:   ~/Library/Application Support/veil/profiles
func DefaultStore() (*Store, error) {
	dir, err := DefaultDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// DefaultDir returns the OS-specific profile directory without creating it.
//
// When running with elevated privileges (sudo / pkexec) we resolve to the
// invoking user's config dir, not root's, so profiles created/edited as
// root land in the same place the unprivileged GUI/CLI looks.
func DefaultDir() (string, error) {
	cfg, err := userConfigDir()
	if err != nil {
		return "", err
	}
	root := filepath.Join(cfg, "veil")
	if runtime.GOOS == "linux" {
		root = filepath.Join(cfg, "veil")
	}
	return filepath.Join(root, "profiles"), nil
}

// userConfigDir returns the config dir of the *target* user. If we're
// running as root because of sudo/pkexec, that's the invoking user's
// $HOME/.config; otherwise it's os.UserConfigDir().
func userConfigDir() (string, error) {
	if os.Geteuid() == 0 {
		if home := invokingHome(); home != "" {
			return filepath.Join(home, ".config"), nil
		}
	}
	return os.UserConfigDir()
}

// invokingHome resolves $HOME of the invoking unprivileged user when veil
// runs under sudo/pkexec. Returns "" when no such hint exists.
func invokingHome() string {
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := osuser.Lookup(name); err == nil {
			return u.HomeDir
		}
	}
	if uid := os.Getenv("PKEXEC_UID"); uid != "" {
		if u, err := osuser.LookupId(uid); err == nil {
			return u.HomeDir
		}
	}
	return ""
}

// List returns all profile names available in the store.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if name == e.Name() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Load reads a single profile by name.
func (s *Store) Load(name string) (*Profile, error) {
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("invalid profile name %q", name)
	}
	path := filepath.Join(s.Dir, name+".yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if p.Name == "" {
		p.Name = name
	}
	return &p, nil
}

// LoadAll loads every profile in the store.
func (s *Store) LoadAll() ([]*Profile, error) {
	names, err := s.List()
	if err != nil {
		return nil, err
	}
	profs := make([]*Profile, 0, len(names))
	for _, n := range names {
		p, err := s.Load(n)
		if err != nil {
			return nil, err
		}
		profs = append(profs, p)
	}
	return profs, nil
}

// Save writes a profile (atomic via temp+rename).
func (s *Store) Save(p *Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt = time.Now().UTC()
	data, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(s.Dir, p.Name+".yaml")
	tmp, err := os.CreateTemp(s.Dir, p.Name+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	// If we're root (sudo / pkexec), chown the file to the invoking user
	// so the unprivileged CLI/GUI can read it later.
	if os.Geteuid() == 0 {
		if uid, gid, ok := invokingUser(); ok {
			_ = os.Chown(tmpName, uid, gid)
		}
	}
	return os.Rename(tmpName, final)
}

// invokingUser returns the (uid, gid) of the user who launched the
// privileged process (via sudo/pkexec). Returns (0,0,false) when no
// such hint is available.
func invokingUser() (int, int, bool) {
	for _, env := range []string{"SUDO_UID", "PKEXEC_UID"} {
		if v := os.Getenv(env); v != "" {
			uid, err := strconv.Atoi(v)
			if err != nil {
				continue
			}
			gid := uid
			if u, err := osuser.LookupId(v); err == nil {
				if g, err := strconv.Atoi(u.Gid); err == nil {
					gid = g
				}
			}
			return uid, gid, true
		}
	}
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if u, err := osuser.Lookup(name); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			return uid, gid, true
		}
	}
	return 0, 0, false
}

// Delete removes a profile.
func (s *Store) Delete(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid profile name %q", name)
	}
	return os.Remove(filepath.Join(s.Dir, name+".yaml"))
}
