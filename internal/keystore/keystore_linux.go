//go:build linux

package keystore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Linux backend: libsecret via secret-tool. Most desktop installs
// already ship it (gnome-keyring on GNOME, kwallet-gnome or
// KeePassXC's Secret Service plugin on KDE, etc.). We invoke the CLI
// rather than dialing D-Bus directly to keep the dependency surface
// small and avoid pulling cgo D-Bus bindings into the main Veil
// binary.

// Available reports whether secret-tool is installed AND a session
// Secret Service is reachable. If either is false, callers should
// fall back to disk and warn the user.
func Available() bool {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return false
	}
	// Even with secret-tool installed, headless / minimal X sessions
	// often have no running gnome-keyring-daemon. Probe by attempting
	// a no-op lookup; secret-tool returns 1 for "not found" (good —
	// service IS reachable) and >1 for "no Secret Service available".
	c := exec.Command("secret-tool", "lookup", "service", Service, "name", "__veil_probe__")
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = nil
	err := c.Run()
	if err == nil {
		return true
	}
	// Exit code 1 means "no match" — service is up.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode() == 1
	}
	return false
}

// Get retrieves a secret previously stored under name. Returns
// ErrNotFound if nothing is stored, ErrUnsupported when secret-tool
// is missing or the Secret Service isn't reachable.
func Get(name string) ([]byte, error) {
	if !Available() {
		return nil, ErrUnsupported
	}
	var stdout, stderr bytes.Buffer
	c := exec.Command("secret-tool", "lookup", "service", Service, "name", name)
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	if err == nil {
		// secret-tool prints the secret followed by a trailing newline.
		out := stdout.Bytes()
		out = bytes.TrimRight(out, "\n")
		if len(out) == 0 {
			return nil, ErrNotFound
		}
		return out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return nil, ErrNotFound
	}
	return nil, fmt.Errorf("secret-tool lookup: %w (%s)", err, strings.TrimSpace(stderr.String()))
}

// Set stores or replaces the secret under name. The label is only for
// human-facing keyring browsers (seahorse) — labels include the name
// so users can audit what Veil has stashed.
func Set(name string, secret []byte) error {
	if !Available() {
		return ErrUnsupported
	}
	c := exec.Command("secret-tool", "store",
		"--label=Veil tls_mitm CA private key — "+name,
		"service", Service,
		"name", name,
	)
	c.Stdin = bytes.NewReader(secret)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("secret-tool store: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Delete removes a secret under name. Idempotent — returns nil if no
// such entry exists.
func Delete(name string) error {
	if !Available() {
		return ErrUnsupported
	}
	c := exec.Command("secret-tool", "clear", "service", Service, "name", name)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		// Non-zero on "no match" is acceptable for a Delete contract.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil
		}
		return fmt.Errorf("secret-tool clear: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// init is a no-op on Linux; environment quirks (no DBUS_SESSION_BUS_ADDRESS,
// etc.) are handled per-call by Available. Intentionally avoid panicking
// at package load — Veil should still launch on minimal/headless installs.
func init() { _ = os.Getenv }
