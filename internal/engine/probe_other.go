//go:build !linux

package engine

// ProbeResult is one row from a leak probe.
// Lives here (not just probe_linux.go) so the type is visible to all
// platforms — necessary because Engine.ProbeLeaks is in the cross-
// platform interface.
type ProbeResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}
