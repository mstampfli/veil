package bridge

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLocate_Missing(t *testing.T) {
	t.Setenv(HelperPathEnv, "/definitely/not/a/real/path/veil-bridge")
	t.Setenv("PATH", "/var/empty") // suppress PATH lookup for the test binary
	// Hermetic: ignore any veil-bridge actually installed at a fixed path on
	// the build machine (e.g. /usr/local/libexec after `make install`).
	oldPaths := bridgeSearchPaths
	bridgeSearchPaths = nil
	t.Cleanup(func() { bridgeSearchPaths = oldPaths })

	_, err := Locate()
	if !errors.Is(err, ErrHelperMissing) {
		t.Errorf("expected ErrHelperMissing, got %v", err)
	}
}

func TestLocate_EnvOverride(t *testing.T) {
	tmp := t.TempDir()
	stub := tmp + "/veil-bridge"
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho '{}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(HelperPathEnv, stub)

	got, err := Locate()
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if got != stub {
		t.Errorf("got %q, want %q", got, stub)
	}
}

// TestParseHelperError_JSON exercises the stderr-JSON parsing path
// the helper uses to return structured errors.
func TestParseHelperError_JSON(t *testing.T) {
	err := parseHelperError(errors.New("exit status 1"),
		[]byte(`{"error":"invalid --profile"}`),
		[]string{"create-veth"})
	if !strings.Contains(err.Error(), "invalid --profile") {
		t.Errorf("expected 'invalid --profile' in %v", err)
	}
}

func TestParseHelperError_PlainText(t *testing.T) {
	err := parseHelperError(errors.New("exit status 1"),
		[]byte(`some non-json failure`),
		[]string{"add-nat"})
	if !strings.Contains(err.Error(), "some non-json failure") {
		t.Errorf("expected raw stderr in %v", err)
	}
}
