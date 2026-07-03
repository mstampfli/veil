//go:build !linux

package wireguard

// Stub. On Windows / macOS, leaked Wintun adapters or utun devices
// have different naming and cleanup semantics; not implemented here.
func cleanLeakedVeilWG() {}
