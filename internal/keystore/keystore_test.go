package keystore

import (
	"bytes"
	"testing"
)

// TestRoundTrip is a smoke test that exercises Set → Get → Delete on
// whatever backend the host provides. Skipped when no keystore is
// available — CI may run inside a headless container without libsecret.
func TestRoundTrip(t *testing.T) {
	if !Available() {
		t.Skip("no keystore backend available on this host")
	}
	name := "veil-keystore-test-roundtrip"
	secret := []byte("the quick brown fox jumps over the lazy dog\x00\xff")

	defer func() { _ = Delete(name) }()

	if err := Set(name, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get(name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch:\n want %q\n  got %q", secret, got)
	}
	if err := Delete(name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(name); err != ErrNotFound {
		t.Fatalf("Get after Delete: want ErrNotFound, got %v", err)
	}
}

func TestGetMissing(t *testing.T) {
	if !Available() {
		t.Skip("no keystore backend available")
	}
	if _, err := Get("veil-keystore-test-definitely-not-stored"); err != ErrNotFound {
		t.Fatalf("missing entry: want ErrNotFound, got %v", err)
	}
}

func TestDeleteIdempotent(t *testing.T) {
	if !Available() {
		t.Skip("no keystore backend available")
	}
	// Twice — second call is the idempotent one.
	if err := Delete("veil-keystore-test-idempotent"); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := Delete("veil-keystore-test-idempotent"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}
