package profile

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAntiFingerprintMode_UnmarshalYAML(t *testing.T) {
	cases := []struct {
		in   string
		want AntiFingerprintMode
	}{
		{"true", AFBasic},
		{"false", AFOff},
		{"\"\"", AFOff},
		{"basic", AFBasic},
		{"strict", AFStrict},
		{"BASIC", AFBasic},
		{"\"strict\"", AFStrict},
		{"on", AFBasic},
		{"off", AFOff},
		{"ultra", AFStrict},
	}
	for _, tc := range cases {
		var got AntiFingerprintMode
		if err := yaml.Unmarshal([]byte(tc.in), &got); err != nil {
			t.Fatalf("unmarshal %q: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("yaml %q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAntiFingerprintMode_UnmarshalYAML_Invalid(t *testing.T) {
	var got AntiFingerprintMode
	err := yaml.Unmarshal([]byte("nonsense"), &got)
	if err == nil {
		t.Fatalf("expected error for invalid value, got %q", got)
	}
}

func TestAntiFingerprintMode_Helpers(t *testing.T) {
	if AFOff.IsOn() {
		t.Error("AFOff should not be on")
	}
	if !AFBasic.IsOn() {
		t.Error("AFBasic should be on")
	}
	if !AFStrict.IsOn() {
		t.Error("AFStrict should be on")
	}
	if AFBasic.IsStrict() {
		t.Error("AFBasic should not be strict")
	}
	if !AFStrict.IsStrict() {
		t.Error("AFStrict should be strict")
	}
}

func TestPropagateAntiFingerprintMITM_OnlyStrictAutoInserts(t *testing.T) {
	for _, tc := range []struct {
		mode    AntiFingerprintMode
		wantHop bool
	}{
		{AFOff, false},
		{AFBasic, false},
		{AFStrict, true},
	} {
		p := &Profile{
			Name:            "x",
			AntiFingerprint: tc.mode,
			App:             App{Preset: "firefox"},
			Chain:           []Backend{{Kind: BackendWireGuard, ConfigPath: "/x"}},
		}
		p.PropagateAntiFingerprintMITM()
		hasMITM := false
		for _, b := range p.Chain {
			if b.Kind == BackendTLSMITM {
				hasMITM = true
				break
			}
		}
		if hasMITM != tc.wantHop {
			t.Errorf("mode=%q: got mitm-hop=%v, want %v", tc.mode, hasMITM, tc.wantHop)
		}
	}
}

func TestPropagateAntiFingerprintMITM_PersonaAlsoTriggers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		profile  Profile
		wantMITM bool
	}{
		{
			name:     "named persona triggers MITM",
			profile:  Profile{Name: "p", Persona: "alice", App: App{Preset: "brave"}, Chain: []Backend{{Kind: BackendDirect}}},
			wantMITM: true,
		},
		{
			name:     "forge_persona triggers MITM",
			profile:  Profile{Name: "p", ForgePersona: true, App: App{Preset: "brave"}, Chain: []Backend{{Kind: BackendDirect}}},
			wantMITM: true,
		},
		{
			name:     "anti_fingerprint=basic alone does NOT trigger",
			profile:  Profile{Name: "p", AntiFingerprint: AFBasic, App: App{Preset: "brave"}, Chain: []Backend{{Kind: BackendDirect}}},
			wantMITM: false,
		},
		{
			name:     "anti_fingerprint=basic + persona DOES trigger (persona wins)",
			profile:  Profile{Name: "p", AntiFingerprint: AFBasic, Persona: "alice", App: App{Preset: "brave"}, Chain: []Backend{{Kind: BackendDirect}}},
			wantMITM: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.profile
			p.PropagateAntiFingerprintMITM()
			has := false
			for _, b := range p.Chain {
				if b.Kind == BackendTLSMITM {
					has = true
				}
			}
			if has != tc.wantMITM {
				t.Errorf("got mitm=%v, want %v (chain=%v)", has, tc.wantMITM, p.Chain)
			}
		})
	}
}

func TestPropagateAntiFingerprintMITM_RespectsManualHop(t *testing.T) {
	p := &Profile{
		Name:            "x",
		AntiFingerprint: AFStrict,
		App:             App{Preset: "firefox"},
		Chain: []Backend{
			{Kind: BackendWireGuard, ConfigPath: "/x"},
			{Kind: BackendTLSMITM, TLSFingerprint: "tor"},
		},
	}
	p.PropagateAntiFingerprintMITM()
	mitmCount := 0
	for _, b := range p.Chain {
		if b.Kind == BackendTLSMITM {
			mitmCount++
		}
	}
	if mitmCount != 1 {
		t.Errorf("manual mitm hop should not be duplicated; count=%d", mitmCount)
	}
	last := p.Chain[len(p.Chain)-1]
	if last.TLSFingerprint != "tor" {
		t.Errorf("manual fingerprint should be preserved, got %q", last.TLSFingerprint)
	}
}
