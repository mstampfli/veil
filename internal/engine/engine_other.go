//go:build !linux && !windows && !darwin

package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/mstampfli/veil/internal/profile"
)

func active() Engine { return &stubEngine{} }

type stubEngine struct{}

func (s *stubEngine) Up(ctx context.Context, p *profile.Profile) (*Session, error) {
	return nil, fmt.Errorf("veil engine: %s not yet supported", runtime.GOOS)
}
func (s *stubEngine) Launch(*Session) (int, error)                          { return 0, fmt.Errorf("unsupported") }
func (s *stubEngine) Down(*Session) error                                    { return nil }
func (s *stubEngine) ExternalIP(context.Context, *Session) (string, error)   { return "", fmt.Errorf("unsupported") }
func (s *stubEngine) ExternalIPInfo(context.Context, *Session) (IPInfo, error) {
	return IPInfo{}, fmt.Errorf("unsupported")
}
func (s *stubEngine) TrafficStats(*Session) (TrafficStats, error) {
	return TrafficStats{}, fmt.Errorf("unsupported")
}
func (s *stubEngine) Doctor(context.Context) ([]Check, error) {
	return []Check{{Name: "platform", OK: false, Detail: runtime.GOOS + " not supported"}}, nil
}
func (s *stubEngine) BrowserProbeIP(context.Context, *Session, string) (string, error) {
	return "", fmt.Errorf("unsupported")
}
func (s *stubEngine) ProbeLeaks(context.Context, *Session) []ProbeResult { return nil }
func (s *stubEngine) TorNewCircuit(*Session) error                       { return fmt.Errorf("unsupported") }
func (s *stubEngine) TorCircuitStatus(*Session) (string, error)          { return "", fmt.Errorf("unsupported") }
func (s *stubEngine) TorRelayIP(*Session, string) (string, error)        { return "", fmt.Errorf("unsupported") }

// CleanupAllOrphans is a no-op on unsupported platforms.
func CleanupAllOrphans() {}

// RecoverStale is a no-op on unsupported platforms.
func RecoverStale() {}
