package profile

import (
	"fmt"
	"strings"

	"github.com/mstampfli/veil/internal/license"
)

// proFeature pairs a Pro-tier feature with whether this profile uses it and
// whether the active capability set permits it.
type proFeature struct {
	name    string
	used    bool
	allowed bool
}

func (p *Profile) proFeatures(caps license.Capabilities) []proFeature {
	mitm, torAdv := false, false
	for i := range p.Chain {
		b := &p.Chain[i]
		if b.Kind == BackendTLSMITM {
			mitm = true
		}
		if b.TorExitCountry != "" || b.UseBridges || len(b.Bridges) > 0 || b.PluggableTransport != "" {
			torAdv = true
		}
	}
	return []proFeature{
		{"anti-fingerprint stack", p.AntiFingerprint.IsOn(), caps.AntiDetect},
		{"persona", p.Persona != "", caps.Persona},
		{"persona forge", p.ForgePersona, caps.ForgePersona},
		{"locked endpoint", p.LockedEndpoint || p.AnyLockEnabled(), caps.LockedEndpoint},
		{"schedule guard", p.ScheduleWindow != "", caps.ScheduleGuard},
		{"behavioral jitter", p.BehavioralJitter || p.MouseJitter, caps.BehavioralJitter},
		{"CPU throttle", p.CPUThrottle != "", caps.CPUThrottle},
		{"TCP fingerprint", p.TCPPersona != "", caps.TCPFingerprint},
		{"TLS-MITM / HTTP-2 mediator", mitm, caps.MITM},
		{"Tor circuit control (exit country / bridges)", torAdv, caps.TorAdvanced},
		{"veil-browser", p.App.Preset == "veil-browser", caps.VeilBrowser},
	}
}

// ProFeaturesUsed returns the names of the Pro-tier features this profile
// requests, regardless of license. Empty for a pure free-tier profile.
func (p *Profile) ProFeaturesUsed() []string {
	var out []string
	for _, f := range p.proFeatures(license.CapsFor(license.Pro)) {
		if f.used {
			out = append(out, f.name)
		}
	}
	return out
}

// RequireLicensed returns an error if the profile requests any Pro-tier
// feature the given capability set does not include. This is the single
// fail-closed gate: the engine calls it before bringing a profile up, so a
// free-tier binary refuses to launch a profile that uses paid features.
func (p *Profile) RequireLicensed(caps license.Capabilities) error {
	var missing []string
	for _, f := range p.proFeatures(caps) {
		if f.used && !f.allowed {
			missing = append(missing, f.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("profile %q uses Veil Pro features not in your license: %s (upgrade to Veil Pro, or remove them for the free tier)",
		p.Name, strings.Join(missing, ", "))
}
