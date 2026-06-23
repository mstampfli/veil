//go:build !pro

package tcpfp

// Free edition: TCP-fingerprint SYN rewriting is a Veil Pro feature. The
// real NFQUEUE-based rewriter lives in the Pro build (//go:build pro) and
// is not shipped in the free binary, so there is no rewriting code here to
// unlock.

// Listener is an opaque handle in the free edition. The real listener with
// its NFQUEUE rewrite loop is Pro-only.
type Listener struct{}

// Builtin reports that built-in personas require Veil Pro by returning nil.
func Builtin(name string) *Persona { return nil }

// Start reports that the SYN rewriter requires Veil Pro.
func Start(nsName string, queueNum uint16, persona *Persona) (*Listener, error) {
	return nil, ErrProOnly
}

// Stop is a no-op on the free-edition listener.
func (l *Listener) Stop() error { return nil }
