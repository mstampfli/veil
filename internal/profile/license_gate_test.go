package profile

import (
	"strings"
	"testing"

	"github.com/mstampfli/veil/internal/license"
)

// A profile that exercises every Pro-tier surface must be refused on the
// free tier and allowed on Pro.
func TestRequireLicensed_FreeRejectsProAllowsPro(t *testing.T) {
	p := &Profile{
		Name:             "pro-profile",
		Persona:          "work",
		ForgePersona:     true,
		LockedEndpoint:   true,
		ScheduleWindow:   "08:00-22:00",
		BehavioralJitter: true,
		CPUThrottle:      "30%",
		TCPPersona:       "windows",
		App:              App{Binary: "firefox", Preset: "veil-browser"},
		Chain: []Backend{
			{Kind: BackendTLSMITM},
			{Kind: BackendTor, UseBridges: true, TorExitCountry: "ch"},
		},
	}

	err := p.RequireLicensed(license.CapsFor(license.Free))
	if err == nil {
		t.Fatal("free tier must refuse a profile that uses Pro features")
	}
	for _, want := range []string{
		"persona", "persona forge", "locked endpoint", "schedule guard",
		"behavioral jitter", "CPU throttle", "TCP fingerprint",
		"TLS-MITM", "Tor circuit control", "veil-browser",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("free-tier error should name %q; got: %v", want, err)
		}
	}

	if err := p.RequireLicensed(license.CapsFor(license.Pro)); err != nil {
		t.Errorf("pro tier must allow a Pro profile, got: %v", err)
	}
	if err := p.RequireLicensed(license.CapsFor(license.Lifetime)); err != nil {
		t.Errorf("lifetime tier must allow a Pro profile, got: %v", err)
	}
}

// A pure free-tier profile (chains + kill switch only) must pass on free and
// report no Pro features.
func TestRequireLicensed_FreeProfilePasses(t *testing.T) {
	p := &Profile{
		Name:       "free-profile",
		KillSwitch: true,
		App:        App{Binary: "firefox"},
		Chain: []Backend{
			{Kind: BackendWireGuard, ConfigPath: "/tmp/wg.conf"},
			{Kind: BackendTor, ManagedTor: true},
		},
	}
	if err := p.RequireLicensed(license.CapsFor(license.Free)); err != nil {
		t.Errorf("a free-tier profile must pass on the free tier, got: %v", err)
	}
	if got := p.ProFeaturesUsed(); len(got) != 0 {
		t.Errorf("free profile should use no Pro features, got: %v", got)
	}
}
