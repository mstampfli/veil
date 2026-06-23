// Package audit writes an append-only, JSON-lines security log.
//
// Every event Veil takes that has security or operational significance
// (profile launch, locked-endpoint failure, drift detection, persona
// forging, kill-switch trip, DNS leak probe result, watchdog action)
// is recorded with timestamp + event type + structured context.
//
// The log lives at <user-config>/veil/audit.log. It is append-only:
// existing entries are never modified or deleted by Veil. A separate
// `veil audit rotate` command (TODO) handles size-based rotation when
// users opt in.
//
// File mode is 0600 (user-read-only). Writes are O_APPEND so concurrent
// writers don't interleave partial lines. Each entry is a single
// newline-terminated JSON object so standard tools (jq, grep, fluent-bit)
// can consume the log directly.
//
// Failure mode: if the log file can't be opened (permission, disk full,
// etc.) Veil logs a warning and continues. The audit log is best-effort
// — Veil functionality is never blocked by an audit-write failure.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"sync"
	"time"
)

// Event is one row in the audit log.
type Event struct {
	Timestamp time.Time      `json:"timestamp"`
	Type      string         `json:"type"`
	Profile   string         `json:"profile,omitempty"`
	Persona   string         `json:"persona,omitempty"`
	PID       int            `json:"pid,omitempty"`
	Severity  string         `json:"severity,omitempty"` // info|warn|error
	Detail    map[string]any `json:"detail,omitempty"`
}

// Common event types. Add new ones here so callers can tab-complete.
const (
	EventProfileLaunch         = "profile.launch"
	EventProfileTeardown       = "profile.teardown"
	EventLockedEndpointPass    = "locked_endpoint.pass"
	EventLockedEndpointFail    = "locked_endpoint.fail"
	EventEndpointCaptured      = "endpoint.captured"
	EventDriftDetected         = "drift.detected"
	EventPersonaForged         = "persona.forged"
	EventKillSwitchInstalled   = "killswitch.installed"
	EventKillSwitchVerifyPass  = "killswitch.verify.pass"
	EventKillSwitchVerifyFail  = "killswitch.verify.fail"
	EventDNSLeakProbePass      = "dns_leak.pass"
	EventDNSLeakProbeFail      = "dns_leak.fail"
	EventScheduleGuardBlock    = "schedule_guard.block"
	EventStaleSessionRecovered = "stale.recovered"
	EventChainDown             = "chain.down"
)

// Severity values.
const (
	SeverityInfo  = "info"
	SeverityWarn  = "warn"
	SeverityError = "error"
)

var (
	mu       sync.Mutex
	pathOnce sync.Once
	cached   string
	cacheErr error

	warnOnce sync.Once
)

// canWriteAppend reports whether path can be opened for append (creating
// it if absent). Used to detect a canonical audit.log left unwritable by
// a stale foreign owner (e.g. an old root run) before we silently drop
// every event into it.
func canWriteAppend(path string) bool {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// resolveWritable returns the audit path to actually write, given the
// canonical one. If the canonical path isn't appendable (typically a
// root-owned audit.log from a pre-user-ns run that the now-unprivileged
// process can't touch), it falls back to a user-owned sibling so the
// security trail keeps recording instead of silently dying. Pure +
// side-effect-free except for creating the target file; unit tested.
func resolveWritable(canon string) (path string, fellBack bool) {
	if canWriteAppend(canon) {
		return canon, false
	}
	fallback := filepath.Join(filepath.Dir(canon), "audit-uns.log")
	if canWriteAppend(fallback) {
		return fallback, true
	}
	return canon, false // neither writable; caller best-efforts as before
}

// effectivePath resolves the writable audit path on each call (audit is
// low-frequency, so the extra stat is negligible and it correctly follows
// any change to the canonical path). Warns to stderr exactly once if it
// had to fall back off the canonical file.
func effectivePath() (string, error) {
	canon, err := Path()
	if err != nil {
		return "", err
	}
	p, fellBack := resolveWritable(canon)
	if fellBack {
		warnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "[veil] warning: audit log %s is not writable (stale owner?) — recording the security trail to %s instead\n", canon, p)
		})
	}
	return p, nil
}

// Path returns the audit log path. Resolved per invoking user (handles
// sudo / pkexec — log lives in the real user's config dir, not root's).
func Path() (string, error) {
	pathOnce.Do(func() {
		dir, err := configDir()
		if err != nil {
			cacheErr = err
			return
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			cacheErr = err
			return
		}
		cached = filepath.Join(dir, "audit.log")
	})
	return cached, cacheErr
}

func configDir() (string, error) {
	if os.Geteuid() == 0 {
		if home := invokingHome(); home != "" {
			return filepath.Join(home, ".config", "veil"), nil
		}
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg, "veil"), nil
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

// Log writes an event to the audit log. Best-effort: errors are
// swallowed (returning would force every call site to handle them,
// and the right behavior is "audit is best-effort, never block work").
func Log(ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Severity == "" {
		ev.Severity = SeverityInfo
	}
	mu.Lock()
	defer mu.Unlock()

	path, err := effectivePath()
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(ev) // single-line JSON + \n
}

// LogProfileLaunch is a typed convenience for the most common event.
func LogProfileLaunch(profile, persona string, pid int) {
	Log(Event{
		Type: EventProfileLaunch, Profile: profile, Persona: persona,
		PID: pid, Severity: SeverityInfo,
	})
}

// LogLockedEndpoint emits a pass/fail event with context.
func LogLockedEndpoint(profile, persona, requiredCountry, gotCountry, ip string, ok bool) {
	t := EventLockedEndpointPass
	sev := SeverityInfo
	if !ok {
		t = EventLockedEndpointFail
		sev = SeverityError
	}
	Log(Event{
		Type: t, Profile: profile, Persona: persona, Severity: sev,
		Detail: map[string]any{
			"required_country": requiredCountry,
			"got_country":      gotCountry,
			"ip":               ip,
		},
	})
}

// LogPersonaForged records that a forge produced a persona.
func LogPersonaForged(profile, persona string) {
	Log(Event{
		Type: EventPersonaForged, Profile: profile, Persona: persona,
		Severity: SeverityInfo,
	})
}

// Read returns the last n events from the log. n <= 0 = all. Reads from
// the same effective path Log writes to (the user-owned fallback when the
// canonical file is unwritable).
func Read(n int) ([]Event, error) {
	path, err := effectivePath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Event
	dec := json.NewDecoder(f)
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		out = append(out, ev)
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// errorf formats and returns an error annotated for audit-context.
// Currently unused but exposed for future audit-aware error chaining.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
