//go:build !pro

package license

import "fmt"

// The free edition never activates and never touches the network: license
// activation is a Pro-only concern.

// Activate is a no-op in the free edition.
func Activate(version string) (ActivationResult, error) {
	return ActivationResult{}, fmt.Errorf("license activation is a Veil Pro feature")
}

// Deactivate is a no-op in the free edition.
func Deactivate(version string) (ActivationResult, error) {
	return ActivationResult{}, fmt.Errorf("license activation is a Veil Pro feature")
}

// MachineID is unused in the free edition but kept for API symmetry.
func MachineID() string { return "" }
