package audit

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestCrashReportRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pathOnce = sync.Once{}
	cached = filepath.Join(dir, "audit.log")
	cacheErr = nil
	pathOnce.Do(func() {})

	Crash("locked_endpoint failed", "alpha", "windows-chrome",
		map[string]any{"required_country": "DE", "got_country": "US"})

	reports, err := LatestCrashes(0)
	if err != nil {
		t.Fatalf("LatestCrashes: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.Reason != "locked_endpoint failed" {
		t.Errorf("reason = %q", r.Reason)
	}
	if r.Profile != "alpha" {
		t.Errorf("profile = %q", r.Profile)
	}
	if r.Stack == "" {
		t.Errorf("stack should be captured")
	}
	if r.OS == "" || r.GoVersion == "" {
		t.Errorf("environment metadata missing")
	}
	if r.NumGoroutine < 1 {
		t.Errorf("num_goroutine should be > 0")
	}
}
