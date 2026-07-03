//go:build linux && !pro

package inputjitter

// Free edition: behavioral input jitter is a Veil Pro feature. The real
// uinput-based implementation lives in the Pro build (//go:build pro) and is
// not shipped in the free binary, so there is no jitter code here to unlock.

// Start reports that keyboard jitter requires Veil Pro.
func Start(opts Options) (Jitter, error) { return nil, ErrProOnly }

// StartMouse reports that mouse jitter requires Veil Pro.
func StartMouse(opts Options) (Jitter, error) { return nil, ErrProOnly }
