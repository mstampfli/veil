package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLogRoundtrip(t *testing.T) {
	dir := t.TempDir()
	// Override Path() resolution to point at tempdir.
	pathOnce = sync.Once{}
	cached = filepath.Join(dir, "audit.log")
	cacheErr = nil
	pathOnce.Do(func() {})
	defer func() { pathOnce = sync.Once{}; cached = ""; cacheErr = nil }()

	Log(Event{Type: EventProfileLaunch, Profile: "alpha", PID: 12345})
	Log(Event{Type: EventLockedEndpointFail, Profile: "alpha", Severity: SeverityError,
		Detail: map[string]any{"required_country": "DE", "got_country": "US"}})

	events, err := Read(0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Type != EventProfileLaunch || events[0].Profile != "alpha" {
		t.Errorf("event[0] mismatch: %+v", events[0])
	}
	if events[1].Severity != SeverityError {
		t.Errorf("event[1] severity = %q, want error", events[1].Severity)
	}
	if events[0].Timestamp.IsZero() {
		t.Errorf("auto-timestamp not applied")
	}
}

// Format must be JSON-lines (one event per line).
func TestJSONLinesFormat(t *testing.T) {
	dir := t.TempDir()
	pathOnce = sync.Once{}
	cached = filepath.Join(dir, "audit.log")
	cacheErr = nil
	pathOnce.Do(func() {})

	Log(Event{Type: "x"})
	Log(Event{Type: "y"})
	data, _ := os.ReadFile(cached)
	lines := 0
	dec := json.NewDecoder(nil)
	_ = dec
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("expected 2 newline-terminated entries, got %d", lines)
	}
}

func TestTopNTail(t *testing.T) {
	dir := t.TempDir()
	pathOnce = sync.Once{}
	cached = filepath.Join(dir, "audit.log")
	cacheErr = nil
	pathOnce.Do(func() {})

	for i := 0; i < 10; i++ {
		Log(Event{Type: EventProfileLaunch, Profile: "p" + string(rune('0'+i))})
	}
	tail, err := Read(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 3 {
		t.Errorf("got %d, want 3", len(tail))
	}
	if tail[0].Profile != "p7" {
		t.Errorf("tail[0] = %q, want p7", tail[0].Profile)
	}
}
