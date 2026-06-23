package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mstampfli/veil/internal/profile"
)

func TestGeoStalenessWarning(t *testing.T) {
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)

	// Fresh DB (5 days old) → silent.
	if w := geoStalenessWarning(now.AddDate(0, 0, -5), true, true, now); w != "" {
		t.Errorf("fresh DB should be silent, got %q", w)
	}
	// Just under the threshold → silent.
	if w := geoStalenessWarning(now.Add(-GeoIPStaleAfter+time.Hour), true, true, now); w != "" {
		t.Errorf("DB just under threshold should be silent, got %q", w)
	}
	// Stale DB (40 days old) → warns with the build date and age.
	if w := geoStalenessWarning(now.AddDate(0, 0, -40), true, true, now); !strings.Contains(w, "40 days old") || !strings.Contains(w, "2026-05-07") {
		t.Errorf("stale DB warning missing date/age: %q", w)
	}
	// No DB at all → warns it can't verify.
	if w := geoStalenessWarning(time.Time{}, false, false, now); !strings.Contains(w, "no GeoIP database installed") {
		t.Errorf("missing DB should warn, got %q", w)
	}
	// DB loaded but metadata lacked a build epoch (haveBuildTime=false,
	// available=true) → silent (we can't judge age, don't false-alarm).
	if w := geoStalenessWarning(time.Time{}, false, true, now); w != "" {
		t.Errorf("loaded DB without build epoch should be silent, got %q", w)
	}
}

func TestProfileReliesOnLocalGeoIP(t *testing.T) {
	cases := []struct {
		name string
		p    profile.Profile
		want bool
	}{
		{"empty", profile.Profile{}, false},
		{"lock_country", profile.Profile{LockCountry: true}, true},
		{"lock_asn", profile.Profile{LockASN: true}, true},
		{"require_exit_country", profile.Profile{RequireExitCountry: "GB"}, true},
		{"tor_exit_country in chain", profile.Profile{
			Chain: []profile.Backend{{Kind: profile.BackendTor, TorExitCountry: "gb"}},
		}, true},
		{"plain direct chain", profile.Profile{
			Chain: []profile.Backend{{Kind: profile.BackendDirect}},
		}, false},
	}
	for _, c := range cases {
		if got := profileReliesOnLocalGeoIP(&c.p); got != c.want {
			t.Errorf("%s: reliesOnGeo=%v want %v", c.name, got, c.want)
		}
	}
}

func TestFileYoungerThan(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh")
	if err := os.WriteFile(fresh, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := fileYoungerThan(fresh, time.Hour); err != nil || !ok {
		t.Errorf("just-written file should be young: ok=%v err=%v", ok, err)
	}

	old := filepath.Join(dir, "old")
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if ok, _ := fileYoungerThan(old, time.Hour); ok {
		t.Errorf("48h-old file should not be young within 1h")
	}

	// Missing file → (false, err), so callers treat it as "needs refresh".
	if ok, err := fileYoungerThan(filepath.Join(dir, "nope"), time.Hour); ok || err == nil {
		t.Errorf("missing file: ok=%v err=%v (want false, non-nil)", ok, err)
	}
}
