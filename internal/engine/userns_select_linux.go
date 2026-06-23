//go:build linux

package engine

import (
	"github.com/mstampfli/veil/internal/bridge"
	"github.com/mstampfli/veil/internal/userns"

	"github.com/mstampfli/veil/internal/logger"
)

// tryUsernsEngine constructs and returns a parent-side user-ns
// engine when the prerequisites are met:
//   - kernel supports unprivileged user namespaces (always required)
//   - an uplink for the child netns is available, which is EITHER:
//       * pasta (passt) on PATH — userspace, needs NO host capability
//         (the zero-capability path, preferred), OR
//       * the veil-bridge binary present with CAP_NET_ADMIN (fallback)
//
// Returns (nil, false) when the kernel blocks userns or neither uplink
// is usable — Active() then falls back to the legacy linuxEngine path.
// Logs the reason so users debugging "why is it still asking for my
// password?" can see it in journalctl.
func tryUsernsEngine() (Engine, bool) {
	level := userns.Detect()
	if level == userns.SupportNone {
		logger.L().Warn("user-ns engine path unavailable: kernel does not allow unprivileged user namespaces")
		return nil, false
	}
	// Uplink check. pasta short-circuits the privileged bridge entirely:
	// when it is present the userns path needs nothing with a capability,
	// so we must NOT gate selection on bridge.Doctor() (a zero-cap install
	// has no working bridge by design — gating on it here would wrongly
	// fall back to the root-requiring legacy engine).
	if pastaAvailable() {
		logger.L().Info("user-ns engine path active",
			"level", level.String(), "uplink", "pasta (no host capability)")
		return newUsernsEngine(), true
	}
	if _, err := bridge.Doctor(); err != nil {
		logger.L().Warn("user-ns engine path unavailable: pasta not found and bridge unusable",
			"err", err.Error(),
			"hint", "install passt for the zero-capability path, or run: sudo veil setup --install-helpers")
		return nil, false
	}
	logger.L().Info("user-ns engine path active",
		"level", level.String(), "uplink", "veil-bridge (cap_net_admin)")
	return newUsernsEngine(), true
}
