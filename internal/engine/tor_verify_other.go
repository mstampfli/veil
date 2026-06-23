//go:build !linux

package engine

// TorExitInfoLocal stub for non-Linux. Tor exit-IP-via-control-proto
// is currently wired only on Linux because verifyTorExit + the Tor
// backend's control endpoint accessor are Linux-build-tagged. Returns
// ok=false on Windows / macOS — caller falls through to CDP.
func TorExitInfoLocal(s *Session) (IPInfo, bool) {
	return IPInfo{}, false
}
