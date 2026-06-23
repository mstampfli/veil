// Package runtime persists running-session metadata so `veil stop` and
// `veil status` can find sessions started by other processes.
package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

// syscall0 = signal 0, the no-op probe. Defined as a package-level
// var so the windows build (which doesn't use it) doesn't break.
var syscall0 = syscall.Signal(0)

// Session is the on-disk state of a running profile.
type Session struct {
	Profile     string    `json:"profile"`
	PID         int       `json:"pid"`
	NetnsName   string    `json:"netns_name,omitempty"`
	Subnet      string    `json:"subnet,omitempty"`
	Chain       string    `json:"chain"`
	StartedAt   time.Time `json:"started_at"`
	TorCtrlPort int       `json:"tor_ctrl_port,omitempty"`
	TorCookie   string    `json:"tor_cookie,omitempty"`
	IfaceVeth   string    `json:"iface_veth,omitempty"`
	TUNDevices  []string  `json:"tun_devices,omitempty"`
}

// Dir returns the runtime state directory. When running as root via
// sudo/pkexec we resolve to the invoking user's config dir.
func Dir() (string, error) {
	cfg, err := userConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(cfg, "veil", "run")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

func userConfigDir() (string, error) {
	if os.Geteuid() == 0 {
		if home := invokingHome(); home != "" {
			return filepath.Join(home, ".config"), nil
		}
	}
	return os.UserConfigDir()
}

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

// Save writes session state atomically (temp + rename) so a crash
// mid-write can't leave a zero-length / partial JSON file.
func Save(s *Session) error {
	d, err := Dir()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(d, s.Profile+".json"), b, 0o600)
}

// atomicWrite is duplicated here (rather than imported from osutil) to
// avoid an import cycle: osutil depends on no-one, runtime depends on
// no-one. Keeping it self-contained.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// Load reads a session by profile name.
func Load(name string) (*Session, error) {
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(d, name+".json"))
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadAll returns all known running sessions.
func LoadAll() ([]*Session, error) {
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Session
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		s, err := Load(name)
		if err != nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Profile < out[j].Profile })
	return out, nil
}

// Remove deletes a session record.
func Remove(name string) error {
	d, err := Dir()
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(d, name+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SignalStop sends a stop signal to a session's process. On Linux/macOS
// this is SIGTERM; on Windows it uses os.Process.Kill.
func SignalStop(s *Session) error {
	proc, err := os.FindProcess(s.PID)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return proc.Kill()
	}
	return proc.Signal(os.Interrupt)
}

// IsAlive returns true if the session's PID is still running. On
// Linux/macOS we use signal 0 (no-op signal) which returns ESRCH if
// the process is gone. Windows: FindProcess always succeeds, so we
// check Process.Wait state.
func IsAlive(s *Session) bool {
	if s == nil || s.PID <= 0 {
		return false
	}
	proc, err := os.FindProcess(s.PID)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// Best-effort: try sending a no-op kill; if it errors, dead.
		return proc.Signal(os.Interrupt) == nil
	}
	// Signal 0 = ESRCH if dead, no-op if alive.
	if err := proc.Signal(syscall0); err != nil {
		return false
	}
	return true
}

// Stale returns the subset of all known sessions whose owner PID is
// no longer running. Used by engine.RecoverStale() to identify
// state files left behind by crashed Veil processes.
func Stale() ([]*Session, error) {
	all, err := LoadAll()
	if err != nil {
		return nil, err
	}
	var dead []*Session
	for _, s := range all {
		if !IsAlive(s) {
			dead = append(dead, s)
		}
	}
	return dead, nil
}

// ReapDead removes the on-disk records of sessions whose owner PID is no
// longer running and returns the reaped profile names. Pure file ops, so
// it is safe in non-root / userns mode where host-level netns and veth
// cleanup does not apply (and where engine.RecoverStale is never run).
// Live sessions — including those owned by other live Veil processes —
// are kept, via the same liveness check Stale uses.
func ReapDead() []string {
	dead, err := Stale()
	if err != nil {
		return nil
	}
	var reaped []string
	for _, s := range dead {
		if err := Remove(s.Profile); err == nil {
			reaped = append(reaped, s.Profile)
		}
	}
	return reaped
}

// String for debug.
func (s *Session) String() string {
	return fmt.Sprintf("%s pid=%d chain=%s started=%s", s.Profile, s.PID, s.Chain, s.StartedAt.Format(time.RFC3339))
}
