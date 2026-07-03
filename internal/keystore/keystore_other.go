//go:build !linux && !windows

package keystore

// Stub backend for platforms Veil doesn't ship secrets storage on yet
// (notably macOS — Keychain integration lands when the macOS engine
// port does). Always reports unavailable; callers fall back to disk.

func Available() bool                              { return false }
func Get(name string) ([]byte, error)              { return nil, ErrUnsupported }
func Set(name string, secret []byte) error         { return ErrUnsupported }
func Delete(name string) error                     { return ErrUnsupported }
