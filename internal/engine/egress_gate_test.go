//go:build linux

package engine

import "testing"

// TestEgressUnblockDecision locks the fail-closed contract of the
// post-launch persona egress gate: an unverified browser must fail
// closed; everything else may unblock.
func TestEgressUnblockDecision(t *testing.T) {
	cases := []struct {
		name            string
		isBrowser       bool
		personaVerified bool
		wantFailClosed  bool
	}{
		{"verified browser unblocks", true, true, false},
		{"unverified browser fails closed", true, false, true},
		{"non-browser app unblocks (no browser-JS persona)", false, false, false},
		{"non-browser verified unblocks", false, true, false},
	}
	for _, c := range cases {
		if got := egressUnblockDecision(c.isBrowser, c.personaVerified); got != c.wantFailClosed {
			t.Errorf("%s: egressUnblockDecision(isBrowser=%v, verified=%v)=%v want %v",
				c.name, c.isBrowser, c.personaVerified, got, c.wantFailClosed)
		}
	}
}
