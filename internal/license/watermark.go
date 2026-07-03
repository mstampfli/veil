package license

import (
	"os"
	"path/filepath"
	"strings"
)

// BuildLicensee is an optional buyer watermark baked into a Pro build via
// -ldflags "-X github.com/mstampfli/veil/internal/license.BuildLicensee=<email-or-order-id>".
// It makes a leaked binary traceable to the buyer even if the license file is
// stripped. It does not gate anything; it is forensic only.
var BuildLicensee = ""

// RevokedIDs is a comma-separated list of revoked license IDs (jti), baked at
// build time via -ldflags "-X .../internal/license.RevokedIDs=id1,id2". This is
// the offline revocation list for known-leaked licenses.
var RevokedIDs = ""

// isRevoked reports whether a license id appears on the baked revocation list
// or in the local revocation file (~/.config/veil/revoked.txt, one id per
// line), which the updater refreshes from the licensed feed. Offline-friendly:
// no network is required and the absence of the file means "nothing revoked".
func isRevoked(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range strings.Split(RevokedIDs, ",") {
		if strings.TrimSpace(r) == id {
			return true
		}
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join(cfg, "veil", "revoked.txt"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == id {
			return true
		}
	}
	return false
}
