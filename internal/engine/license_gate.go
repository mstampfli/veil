package engine

import (
	"github.com/mstampfli/veil/internal/license"
	"github.com/mstampfli/veil/internal/profile"
)

// gateLicense refuses to bring up a profile that uses Pro-tier features the
// active license does not include. Fail-closed: every platform engine calls
// this at the top of Up, so a free-tier binary will not launch paid features.
func gateLicense(p *profile.Profile) error {
	return p.RequireLicensed(license.ActiveCaps())
}
