//go:build windows && !pro

package engine

// FREE-build stubs for the Windows engine's Pro logic. The real
// implementation (WinDivert TTL-rewrite TCP persona) lives in
// tcp_persona_windows.go under `//go:build windows && pro`. These
// stubs let engine_windows.go (compiled without the pro tag) build.

// tcpPersonaSession is the WinDivert TTL-rewrite handle. The real
// session lives in the pro build; the free stub carries the type that
// the windows engine state references.
type tcpPersonaSession struct{}

// Close is a no-op in the free build.
func (s *tcpPersonaSession) Close() {}

// installTCPPersona: TCP stack persona via WinDivert is Pro. Returns
// a Pro-only error so the windows engine logs and continues without a
// TTL rewrite (its caller treats a nil session as "skip").
func (e *winEngine) installTCPPersona(pid int, persona string) (*tcpPersonaSession, error) {
	return nil, errProOnly
}
