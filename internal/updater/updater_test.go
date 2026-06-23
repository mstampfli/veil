package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"runtime"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		remote, local string
		want          bool
	}{
		// strictly newer
		{"v1.2.0", "v1.1.0", true},
		{"1.2.0", "1.1.9", true},
		{"v2.0.0", "1.9.9", true},
		{"1.0.1", "1.0.0", true},
		{"v1.10.0", "v1.9.0", true}, // numeric, not lexical
		// equal / older
		{"1.2.0", "1.2", false}, // missing trailing field treated as 0 -> equal
		{"1.1.0", "1.1.0", false},
		{"v1.1.0", "1.1.0", false}, // leading v stripped
		{"1.0.0", "1.0.1", false},
		{"1.1.0", "v1.2.0", false},
		{"1.2.3", "1.2.3", false},
		// dev handling: dev is always oldest
		{"v1.0.0", "dev", true},
		{"0.0.1", "dev", true},
		{"dev", "v1.0.0", false},
		{"dev", "dev", false},
		// pre-release / build suffix ignored for the numeric core
		{"v1.2.0-rc1", "v1.1.0", true},
		{"1.2.0+build5", "1.2.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.remote, c.local); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.remote, c.local, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	if compareVersions("1.0.0", "1.0.0") != 0 {
		t.Error("equal versions should compare 0")
	}
	if compareVersions("2.0.0", "1.9.9") <= 0 {
		t.Error("2.0.0 should be > 1.9.9")
	}
	if compareVersions("1.9.0", "1.10.0") >= 0 {
		t.Error("1.9.0 should be < 1.10.0 (numeric)")
	}
	if compareVersions("dev", "dev") != 0 {
		t.Error("dev == dev")
	}
	if compareVersions("dev", "0.0.1") >= 0 {
		t.Error("dev should sort below any real version")
	}
}

func TestParseSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello veil")
	sig := ed25519.Sign(priv, msg)

	// raw 64 bytes
	got, err := parseSignature(sig)
	if err != nil {
		t.Fatalf("raw sig: %v", err)
	}
	if !ed25519.Verify(pub, msg, got) {
		t.Error("raw-parsed signature failed to verify")
	}

	// base64 std
	b64 := []byte(base64.StdEncoding.EncodeToString(sig))
	got, err = parseSignature(b64)
	if err != nil {
		t.Fatalf("b64 sig: %v", err)
	}
	if !ed25519.Verify(pub, msg, got) {
		t.Error("base64-parsed signature failed to verify")
	}

	// base64 with whitespace
	got, err = parseSignature([]byte("  " + base64.StdEncoding.EncodeToString(sig) + "\n"))
	if err != nil {
		t.Fatalf("b64+ws sig: %v", err)
	}
	if !ed25519.Verify(pub, msg, got) {
		t.Error("base64+whitespace signature failed to verify")
	}

	// garbage
	if _, err := parseSignature([]byte("not a signature at all")); err == nil {
		t.Error("expected error for garbage signature input")
	}
}

func TestDecodePubKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	got, err := decodePubKey(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !pub.Equal(got) {
		t.Error("decoded key mismatch")
	}

	if _, err := decodePubKey("@@@not-base64@@@"); err == nil {
		t.Error("expected error for non-base64 key")
	}
	if _, err := decodePubKey(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected error for wrong-length key")
	}
}

// TestSignatureVerifyHappySad exercises the same ed25519.Verify path Apply
// uses, with a key pair generated in the test (happy = valid sig, sad =
// tampered bytes).
func TestSignatureVerifyHappySad(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("pretend this is the downloaded veil binary")
	sig := ed25519.Sign(priv, payload)

	// happy path
	if !ed25519.Verify(pub, payload, sig) {
		t.Error("valid signature should verify")
	}
	// sad path: tamper with one byte of the payload
	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xFF
	if ed25519.Verify(pub, tampered, sig) {
		t.Error("tampered payload must NOT verify")
	}
	// sad path: wrong key
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if ed25519.Verify(otherPub, payload, sig) {
		t.Error("signature must NOT verify under a different key")
	}
}

func TestAssetMatchesHost(t *testing.T) {
	// Build a name that matches the current host and assert it matches; a
	// clearly-foreign name should not.
	osTok := runtime.GOOS
	if osTok == "darwin" {
		osTok = "macos"
	}
	good := "veil-" + osTok + "-" + archTokens()[0] + ".tar.gz"
	if !assetMatchesHost(good) {
		t.Errorf("expected %q to match host", good)
	}
	if assetMatchesHost("veil-plan9-sparc.zip") {
		t.Error("foreign asset should not match host")
	}
}
