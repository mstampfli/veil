package license

// ActivationResult is the outcome of a license activation ping. Activation is a
// logging-only registration (no seat cap, never gates Pro). Shared by both
// editions (the free edition's Activate is a no-op stub).
type ActivationResult struct {
	OK       bool
	Already  bool // this machine was already registered (idempotent re-ping)
	Reason   string
	Machines int // distinct machines this license is currently logged on (informational)
}
