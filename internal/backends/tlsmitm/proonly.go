//go:build !pro

// Package tlsmitm in the free edition ships only the registration and
// API surface the rest of Veil links against. The TLS-MITM proxy, uTLS
// impersonation, HTTP/1.1 + HTTP/2 mediators, and per-profile CA
// management are a Veil Pro feature; the real implementation lives in
// the Pro build (//go:build pro) and is not compiled into the free
// binary, so there is no algorithm code here to unlock.
//
// Everything below is a no-op / error stub that satisfies the same
// types, functions, and backend registration as the Pro build so the
// free edition compiles and links. The free-edition profile gate
// already refuses the tls_mitm backend before it ever starts, so the
// stub Start simply reports ErrProOnly.
package tlsmitm

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/profile"
)

// ErrProOnly is returned by the free-edition stubs for the TLS-MITM
// Pro feature.
var ErrProOnly = errors.New("TLS-MITM requires Veil Pro")

// CA mirrors the Pro CA type's exported surface so callers that read
// the certificate / PEM bytes still compile in the free build. The
// free build never returns a populated CA (LoadOrGenerate reports
// ErrProOnly), so these fields are always zero here.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	KeyPEM  []byte
}

// LoadOrGenerate reports that the TLS-MITM CA requires Veil Pro.
func LoadOrGenerate() (*CA, error) { return nil, ErrProOnly }

// LoadOrGenerateForProfile reports that the per-profile TLS-MITM CA
// requires Veil Pro.
func LoadOrGenerateForProfile(dataDir string) (*CA, error) { return nil, ErrProOnly }

// CACertPath reports that the TLS-MITM CA requires Veil Pro.
func CACertPath() (string, error) { return "", ErrProOnly }

// CACertPathForProfile returns no path in the free build. The TLS-MITM
// CA is a Veil Pro feature, so no per-profile CA is ever written.
func CACertPathForProfile(dataDir string) string { return "" }

// EnsureInstalledForProfile reports that per-profile CA install
// requires Veil Pro.
func EnsureInstalledForProfile(dataDir string) error { return ErrProOnly }

// SelfCheck is a no-op in the free build: the TLS-MITM proxy never runs
// here (the profile gate rejects tls_mitm before Up reaches this), so
// there is no uTLS rewrite to verify.
func SelfCheck(fp string) error { return nil }

// Backend is the free-edition stub for the TLS-MITM backend. It
// satisfies backends.Backend so the registry and chain wiring compile,
// but Start refuses with ErrProOnly. In the free build the profile
// license gate already rejects tls_mitm before Start is reached.
type Backend struct{}

func init() {
	backends.Register(profile.BackendKind("tls_mitm"), func(b profile.Backend) (backends.Backend, error) {
		return &Backend{}, nil
	})
}

// Kind reports the backend kind this stub stands in for.
func (b *Backend) Kind() profile.BackendKind { return profile.BackendKind("tls_mitm") }

// Start refuses: the TLS-MITM proxy is a Veil Pro feature.
func (b *Backend) Start(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	return nil, ErrProOnly
}

// Stop is a no-op; the free-edition backend never starts.
func (b *Backend) Stop() error { return nil }

// Status reports that the backend is a Pro-only feature.
func (b *Backend) Status() string { return "tls_mitm requires Veil Pro" }
