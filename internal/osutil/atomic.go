// Package osutil provides crash-safe file primitives.
//
// WriteFileAtomic writes data to a temporary file in the same directory
// as path, fsyncs it, then renames it over path. The rename is atomic
// on Linux/macOS/Windows (within the same filesystem) — readers see
// either the old contents or the new, never a partial write.
//
// Use this for any file Veil cares about across crashes:
//   - session state (runtime/runtime.go)
//   - persona JSON written for veil-browser
//   - generated CA cert/key
//   - generated systemd units
//   - sudoers.d entries
//
// Don't use it for files that are regenerated every launch (user.js,
// resolv.conf, torrc) — there the cost-benefit doesn't justify the
// extra fsync.
package osutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path with the given mode, atomically.
// Existing file is replaced. Parent directory must exist.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// If anything below fails, leave no temp behind.
		if _, err := os.Stat(tmpName); err == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	// fsync ensures the bytes are durable before the rename, so a
	// crash between rename and fsync can't expose a zero-length file.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp to %s: %w", path, err)
	}
	return nil
}

// WriteFileAtomicChown is WriteFileAtomic + chown to the given uid/gid
// after rename. Used when writing files as root that should be owned
// by the invoking sudo user (audit logs, persona JSON, profile YAML
// in user's config dir).
func WriteFileAtomicChown(path string, data []byte, perm os.FileMode, uid, gid int) error {
	if err := WriteFileAtomic(path, data, perm); err != nil {
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}
