//go:build linux && !pro

package engine

import (
	"context"
	"time"

	"github.com/mstampfli/veil/internal/persona"
)

// FREE-build stubs for the Linux engine's Pro logic. The real
// implementations live in the `//go:build linux && pro` files
// (locked_endpoint_linux.go, persona_probe_linux.go,
// persona_probe_cdp_linux.go, marionette_linux.go,
// firefox_addon_linux.go, tor_geo_linux_pro.go, schedule.go). These
// stubs let engine_linux.go (compiled without the pro tag) build and
// fail closed: every gated path returns a Pro-only error or a no-op.

// verifyLockedEndpoint: locked-endpoint / geo verification is Pro.
func (e *linuxEngine) verifyLockedEndpoint(s *Session, personaName string, fullPersona *persona.Persona) error {
	return errProOnly
}

// applyTorCountryPin: Tor exit-country pinning is Pro. No-op in free
// so a chain without a country pin still launches normally.
func (e *linuxEngine) applyTorCountryPin(sess *Session, st *linuxState) error {
	return nil
}

// CheckScheduleWindow: schedule windows are Pro. Empty window is the
// free default (always allowed); any configured window is gated.
func CheckScheduleWindow(window, tz string) error {
	if window == "" {
		return nil
	}
	return errProOnly
}

// installFirefoxAddon: persona extension auto-install via Marionette
// is Pro.
func installFirefoxAddon(port int, extDir string, deadline time.Time) error {
	return errProOnly
}

// verifyPersonaViaCDP: persona verification over CDP is Pro.
func verifyPersonaViaCDP(ctx context.Context, debugPort int, browserWSURL string, expectedPersona []byte, deadline time.Duration) error {
	return errProOnly
}

// firefoxProbe: driving Firefox via Marionette is Pro.
func firefoxProbe(ctx context.Context, port int, target string, timeout time.Duration) (string, error) {
	return "", errProOnly
}

// personaProbeServer is the persona load-confirmation listener. The
// real implementation (HTTP handlers + persona validation) is Pro;
// the free stub carries the field type that linuxState references and
// returns a Pro-only error if any path tries to arm it.
type personaProbeServer struct{}

// newPersonaProbeServer: the persona probe server is Pro.
func newPersonaProbeServer(expectedPersonaJSON []byte) (*personaProbeServer, error) {
	return nil, errProOnly
}

// Start is a no-op stub; the free build never constructs a real
// server (newPersonaProbeServer errors first).
func (p *personaProbeServer) Start() (int, error) { return 0, errProOnly }

// URL returns the empty string in the free build.
func (p *personaProbeServer) URL() string { return "" }

// Token returns the empty string in the free build.
func (p *personaProbeServer) Token() string { return "" }

// Close is a no-op in the free build.
func (p *personaProbeServer) Close() error { return nil }
