package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
)

// CrashReport snapshots all available state on a critical failure
// (locked-endpoint fail, kill switch verify fail, DNS probe fail,
// watchdog fire, panic). Persisted as a single JSON file at
// <auditdir>/crashes/crash-<timestamp>.json so post-incident analysis
// has everything in one place.
type CrashReport struct {
	Timestamp     time.Time      `json:"timestamp"`
	Reason        string         `json:"reason"`
	Profile       string         `json:"profile,omitempty"`
	Persona       string         `json:"persona,omitempty"`
	GoVersion     string         `json:"go_version"`
	OS            string         `json:"os"`
	Arch          string         `json:"arch"`
	NumGoroutine  int            `json:"num_goroutine"`
	Stack         string         `json:"stack,omitempty"` // when triggered by panic
	RecentEvents  []Event        `json:"recent_events"`   // last N from audit log
	ProfileState  map[string]any `json:"profile_state,omitempty"`
}

// Crash writes a crash report. Called from emergency-cleanup paths
// (signal handlers, panic recovery, locked-endpoint failures with
// crash-on-fail policy). Best-effort like the rest of audit; never
// blocks shutdown.
func Crash(reason, profileName, personaName string, profileState map[string]any) {
	dir, err := crashDir()
	if err != nil {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}

	recent, _ := Read(50)

	report := CrashReport{
		Timestamp:    time.Now().UTC(),
		Reason:       reason,
		Profile:      profileName,
		Persona:      personaName,
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		NumGoroutine: runtime.NumGoroutine(),
		Stack:        string(debug.Stack()),
		RecentEvents: recent,
		ProfileState: profileState,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(dir,
		fmt.Sprintf("crash-%s.json", report.Timestamp.Format("20060102-150405")))
	_ = os.WriteFile(path, data, 0o600)

	// Mirror to audit log so the event shows up in normal forensic flow.
	Log(Event{
		Type:     "crash.report",
		Profile:  profileName,
		Persona:  personaName,
		Severity: SeverityError,
		Detail: map[string]any{
			"reason": reason, "report_path": path,
		},
	})
}

func crashDir() (string, error) {
	// Derive from the audit log path so test mocks of `cached` apply
	// here too. In production `cached` is <config>/veil/audit.log so
	// crashDir is <config>/veil/crashes — same as before.
	p, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "crashes"), nil
}

// LatestCrashes returns the n most recent crash reports.
func LatestCrashes(n int) ([]CrashReport, error) {
	dir, err := crashDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var reports []CrashReport
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r CrashReport
		if err := json.Unmarshal(data, &r); err != nil {
			continue
		}
		reports = append(reports, r)
	}
	// Sort by timestamp desc.
	for i := 0; i < len(reports); i++ {
		for j := i + 1; j < len(reports); j++ {
			if reports[j].Timestamp.After(reports[i].Timestamp) {
				reports[i], reports[j] = reports[j], reports[i]
			}
		}
	}
	if n > 0 && len(reports) > n {
		reports = reports[:n]
	}
	return reports, nil
}
