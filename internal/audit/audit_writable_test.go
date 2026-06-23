package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveWritableFallback proves that when the canonical audit.log is
// not appendable (the stale-root-owner bug), audit falls back to a
// user-owned sibling so the security trail keeps recording instead of
// silently dropping every event.
func TestResolveWritableFallback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: file mode bits don't block the owner, can't simulate unwritable")
	}
	dir := t.TempDir()
	canon := filepath.Join(dir, "audit.log")

	// 1) Writable canonical → use it, no fallback.
	if p, fb := resolveWritable(canon); p != canon || fb {
		t.Fatalf("writable canon: got (%q, fellBack=%v), want (%q, false)", p, fb, canon)
	}

	// 2) Canonical exists but is read-only (simulates the foreign-owned,
	//    unwritable file) → fall back to audit-uns.log. Step 1 already
	//    created canon (0600) via canWriteAppend, and os.WriteFile won't
	//    change an existing file's mode, so chmod explicitly.
	if err := os.WriteFile(canon, []byte("old root entry\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(canon, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(canon, 0o600) })

	p, fb := resolveWritable(canon)
	want := filepath.Join(dir, "audit-uns.log")
	if p != want || !fb {
		t.Fatalf("unwritable canon: got (%q, fellBack=%v), want (%q, true)", p, fb, want)
	}
	// The fallback must actually be appendable (the whole point).
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("fallback %q not appendable: %v", p, err)
	}
	_ = f.Close()

	// The original (unwritable) file must be left intact for forensics.
	b, err := os.ReadFile(canon)
	if err != nil || string(b) != "old root entry\n" {
		t.Fatalf("canonical log was disturbed: %q err=%v", string(b), err)
	}
}

func TestCanWriteAppend(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits don't block owner")
	}
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.log")
	if !canWriteAppend(ok) {
		t.Errorf("canWriteAppend on fresh path = false, want true")
	}
	ro := filepath.Join(dir, "ro.log")
	if err := os.WriteFile(ro, nil, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o600) })
	if canWriteAppend(ro) {
		t.Errorf("canWriteAppend on 0400 file = true, want false")
	}
}
