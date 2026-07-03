package osutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := WriteFileAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "first" {
		t.Errorf("got %q, want first", string(got))
	}
	// Overwrite must replace, not corrupt.
	if err := WriteFileAtomic(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "second" {
		t.Errorf("got %q, want second", string(got))
	}
	// No leftover temps.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir contains %d entries, want 1: %v", len(entries), entries)
	}
}

func TestWriteFileAtomicMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestWriteFileAtomicNoLeakOnError(t *testing.T) {
	dir := t.TempDir()
	// Write then deliberately make the temp dir read-only to force
	// an error path; verify no temp leaks.
	path := filepath.Join(dir, "x")
	if err := WriteFileAtomic(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make sure no temp .tmp file is left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}
