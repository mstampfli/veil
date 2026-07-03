// Package keystore provides a tiny cross-platform secret store used
// for material that should not sit on disk in plaintext — primarily
// the per-profile tls_mitm CA private key.
//
// Backends (one per platform):
//
//	Linux   — libsecret via the `secret-tool` CLI (gnome-keyring /
//	          KDE wallet / KeePassXC etc., whatever the user's session
//	          exposes on the Secret Service D-Bus).
//	Windows — DPAPI: CryptProtectData encrypts as the current user;
//	          ciphertext is stored under %LOCALAPPDATA%\Veil\keystore.
//	          Only the same Windows user profile can decrypt.
//	macOS   — stub for now (returns ErrUnsupported); macOS port of
//	          Veil is deferred and so is its Keychain integration.
//
// When no backend is available — secret-tool not installed, no
// session keyring unlocked, DPAPI call fails — Get/Set/Delete return
// ErrUnsupported and the caller is expected to fall back to whatever
// less-protected on-disk path it had before. Available() lets callers
// check this once and warn the user instead of silently downgrading.
package keystore

import "errors"

// ErrUnsupported is returned when the host has no working keystore.
// Callers should fall back to disk storage and surface a warning.
var ErrUnsupported = errors.New("keystore: not available on this host")

// ErrNotFound is returned by Get when no secret is stored under the
// requested name.
var ErrNotFound = errors.New("keystore: not found")

// Service is the constant we register every Veil secret under so
// libsecret/DPAPI groupings stay coherent and `secret-tool clear
// service veil-ca` wipes everything Veil ever stored.
const Service = "veil-ca"
