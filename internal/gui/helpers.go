package gui

import (
	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/engine"
	"github.com/mstampfli/veil/internal/profile"
)

// torBackendFromSession returns the *tor.Backend in a session, if any.
//
// Note: in the userns engine path the parent's Session has empty
// .Backends because the actual backend instances live inside the
// userns child. Callers that need to act on the Tor backend (e.g.
// new-circuit signal) should use chainHasTorBackend() to check the
// CHAIN config, then issue an RPC for the action — don't rely on
// this returning non-nil to gate UX features.
func torBackendFromSession(s *engine.Session) *tor.Backend {
	if s == nil {
		return nil
	}
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			return t
		}
	}
	return nil
}

// chainHasTorBackend checks the Profile's CHAIN config (not the
// runtime Backends slice) for a Tor hop. This works for both the
// host engine (Backends populated) and the userns engine (Backends
// empty in parent — only chain config is reliable).
func chainHasTorBackend(s *engine.Session) bool {
	if s == nil || s.Profile == nil {
		return false
	}
	for _, b := range s.Profile.Chain {
		if b.Kind == profile.BackendTor {
			return true
		}
	}
	return false
}

// nsNameFromSession returns the Linux netns name for a session — empty
// on platforms that don't use namespaces. Veil consistently names them
// "veil-<profile>" so we don't need to peek at platform state types.
func nsNameFromSession(s *engine.Session) string {
	if s == nil || s.Profile == nil {
		return ""
	}
	return "veil-" + s.Profile.Name
}
