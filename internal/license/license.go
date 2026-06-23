// Package license validates Veil license keys offline.
//
// A license is a JWT signed with Ed25519 by the issuer. The issuer's
// public key is baked into the binary at build time via -ldflags
// "-X github.com/mstampfli/veil/internal/license.IssuerPubKey=<base64>".
//
// Free tier: no license needed; capabilities limited to 2 profiles and CLI only.
// Pro tier: license required; full capabilities.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssuerPubKey is the base64-encoded Ed25519 public key, set at build time.
// Empty string means "no built-in key" — license features disabled (free
// tier always works).
var IssuerPubKey = ""

// Tier of the active license.
type Tier int

const (
	Free Tier = iota
	Pro
	Lifetime
)

func (t Tier) String() string {
	switch t {
	case Pro:
		return "pro"
	case Lifetime:
		return "lifetime"
	default:
		return "free"
	}
}

// Claims carried in the JWT. The RegisteredClaims ID (jti) is the license's
// unique id, used for revocation.
type Claims struct {
	Email   string `json:"email,omitempty"`
	OrderID string `json:"order_id,omitempty"`
	Tier    string `json:"tier"`
	Issued  int64  `json:"iat,omitempty"`
	Expires int64  `json:"exp,omitempty"`
	jwt.RegisteredClaims
}

// Status describes the active license.
type Status struct {
	Tier    Tier
	Email   string
	OrderID string
	ID      string // jti, the license's unique id (for revocation)
	Expires time.Time
	Valid   bool
	Reason  string
}

// FreeStatus returns the implicit free tier status.
func FreeStatus() Status { return Status{Tier: Free, Valid: true} }

// LoadFromDefault attempts to read and verify a license token from the
// default location (~/.config/veil/license.jwt or %APPDATA%\veil\license.jwt).
// Falls back to Free tier when no file is present.
func LoadFromDefault() Status {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return FreeStatus()
	}
	return LoadFromPath(filepath.Join(cfg, "veil", "license.jwt"))
}

// LoadFromPath reads and verifies a license file.
func LoadFromPath(path string) Status {
	b, err := os.ReadFile(path)
	if err != nil {
		return FreeStatus()
	}
	return Verify(strings.TrimSpace(string(b)))
}

// Verify validates a JWT against the baked-in IssuerPubKey.
func Verify(token string) Status {
	if IssuerPubKey == "" {
		return Status{Tier: Free, Valid: false, Reason: "binary built without issuer public key"}
	}
	keyBytes, err := base64.StdEncoding.DecodeString(IssuerPubKey)
	if err != nil {
		return Status{Tier: Free, Valid: false, Reason: "issuer key not base64"}
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return Status{Tier: Free, Valid: false, Reason: "issuer key wrong length"}
	}
	pub := ed25519.PublicKey(keyBytes)

	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "EdDSA" {
			return nil, fmt.Errorf("unexpected alg %s", t.Method.Alg())
		}
		return pub, nil
	})
	if err != nil {
		return Status{Tier: Free, Valid: false, Reason: err.Error()}
	}
	c, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return Status{Tier: Free, Valid: false, Reason: "claims invalid"}
	}
	tier := Free
	switch strings.ToLower(c.Tier) {
	case "pro":
		tier = Pro
	case "lifetime":
		tier = Lifetime
	default:
		return Status{Tier: Free, Valid: false, Reason: "unknown tier"}
	}
	exp := time.Time{}
	if c.Expires > 0 {
		exp = time.Unix(c.Expires, 0)
		if tier != Lifetime && time.Now().After(exp) {
			return Status{Tier: Free, Valid: false, Reason: "license expired", ID: c.ID, Email: c.Email, OrderID: c.OrderID}
		}
	}
	if isRevoked(c.ID) {
		return Status{Tier: Free, Valid: false, Reason: "license revoked", ID: c.ID, Email: c.Email, OrderID: c.OrderID}
	}
	return Status{Tier: tier, Email: c.Email, OrderID: c.OrderID, ID: c.ID, Expires: exp, Valid: true}
}

// Capabilities the host has under the given license.
//
// Free tier (vopono-equivalent): network isolation, all chain backends,
// kill switch, GUI, CLI, bulk import, basic Tor. Everything except the
// anti-detect / opsec stack.
//
// Pro tier: adds the differentiated features — TCP/TLS/HTTP-2 spoofing,
// persona system, persona forge, locked endpoint, schedule guard,
// behavioral jitter, CPU throttle, MITM, veil-browser binary updates,
// Tor circuit control (NEWNYM / ExitCountry / bridges).
type Capabilities struct {
	// Always-on (free tier)
	GUI         bool
	MaxProfiles int  // 0 = unlimited
	AllBackends bool // wireguard, openvpn, tor (system), socks5, http
	MultiHop    bool

	// Pro-gated anti-detect features
	AntiDetect       bool // master switch for the anti-detect stack
	Persona          bool // persona system (UA/locale/screen/hw)
	ForgePersona     bool // per-profile unique persona generation
	TCPFingerprint   bool // TCP TTL/MSS/options/window-scale rewrite
	TLSFingerprint   bool // uTLS ClientHello impersonation
	HTTP2Mediator    bool // HTTP/2 SETTINGS+WU+HPACK mediator
	LockedEndpoint   bool // per-profile pinned exit IP/city/ASN
	ScheduleGuard    bool // launch-window enforcement
	BehavioralJitter bool // keyboard + mouse jitter
	CPUThrottle      bool // cgroup CPU rate limiting
	TorAdvanced      bool // Tor circuit control, ExitCountry, bridges
	MITM             bool // TLS-MITM proxy + CA management
	VeilBrowser      bool // veil-browser binary updates / patch feed

	// Misc paid extras
	EncryptedExport bool
	ProviderHelpers bool
}

// CapsFor returns the capability set for a tier.
func CapsFor(t Tier) Capabilities {
	free := Capabilities{
		GUI:         true, // free has GUI now
		MaxProfiles: 0,    // unlimited profiles even on free
		AllBackends: true, // wireguard / openvpn / tor / socks5 / http
		MultiHop:    true,
	}
	if t == Free {
		return free
	}
	// Pro / Lifetime: free baseline + anti-detect stack.
	caps := free
	caps.AntiDetect = true
	caps.Persona = true
	caps.ForgePersona = true
	caps.TCPFingerprint = true
	caps.TLSFingerprint = true
	caps.HTTP2Mediator = true
	caps.LockedEndpoint = true
	caps.ScheduleGuard = true
	caps.BehavioralJitter = true
	caps.CPUThrottle = true
	caps.TorAdvanced = true
	caps.MITM = true
	caps.VeilBrowser = true
	caps.EncryptedExport = true
	caps.ProviderHelpers = true
	return caps
}

// IsPro reports whether the active license includes paid features.
// Convenience wrapper for callers that just want a boolean check.
func (s Status) IsPro() bool {
	return s.Valid && (s.Tier == Pro || s.Tier == Lifetime)
}

// Caps returns the active capability set.
func (s Status) Caps() Capabilities {
	if !s.Valid {
		return CapsFor(Free)
	}
	return CapsFor(s.Tier)
}

// ErrLimitExceeded is returned when an action exceeds the license's capabilities.
var ErrLimitExceeded = errors.New("license limit exceeded")

// ErrProRequired is returned when a free-tier user tries to use a
// pro-only feature. The string includes the feature name so the GUI
// can surface a meaningful "upgrade to use X" prompt.
type ErrProRequired struct{ Feature string }

func (e *ErrProRequired) Error() string {
	return fmt.Sprintf("%s requires Veil Pro", e.Feature)
}

// RequirePro returns ErrProRequired unless this is the Pro edition AND a valid
// signed license is installed. Use at feature entry points:
// `if err := license.RequirePro("persona forge"); err != nil { return err }`.
func RequirePro(feature string) error {
	if proActive() {
		return nil
	}
	return &ErrProRequired{Feature: feature}
}
