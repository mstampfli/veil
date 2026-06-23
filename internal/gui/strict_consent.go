package gui

// Strict-tier (anti_fingerprint: strict) installs a per-profile TLS
// interception CA into the browser data dir Veil owns. The user
// should know this is happening — quietly trusting a CA mid-launch
// would feel like the corporate-MITM tools we explicitly do NOT want
// to be confused with. So strict-tier launches are gated on a
// per-profile one-time consent: the GUI prompts on first launch,
// stores acceptance with a timestamp, and only then proceeds.
//
// Surfaces (Wails-bound):
//
//   StrictTierConsentInfo{name}     — returns dataDir path, CA cert
//                                     fingerprint, and whether the
//                                     user has already accepted.
//   AcceptStrictTier(name)          — records acceptance with the
//                                     current time; persists in the
//                                     profile YAML.
//   RevokeStrictTier(name)          — clears acceptance (re-prompts
//                                     on next launch).
//
// LaunchProfile checks NeedsStrictTierConsent() before bringing up
// the chain; if true, returns a typed error the JS frontend reads
// to know it should pop the consent modal instead of toasting an
// opaque failure.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mstampfli/veil/internal/backends/tlsmitm"
)

// StrictTierConsentInfo is the payload returned to the GUI for the
// consent modal. All fields are JSON-marshalable so Wails surfaces
// them directly.
type StrictTierConsentInfo struct {
	ProfileName       string `json:"profile_name"`
	Tier              string `json:"tier"` // "strict" or "" if not strict
	NeedsConsent      bool   `json:"needs_consent"`
	DataDir           string `json:"data_dir"`
	CACertPath        string `json:"ca_cert_path"`
	CAFingerprintHex  string `json:"ca_fingerprint_hex"`  // SHA-256 colon-formatted
	CASubject         string `json:"ca_subject"`
	KeystoreBacked    bool   `json:"keystore_backed"`     // true if private key is in OS keystore
	AcceptedAtUnix    int64  `json:"accepted_at_unix"`    // 0 = never accepted
	HumanScopeSummary string `json:"human_scope_summary"` // for the dialog body
}

// ErrStrictTierConsentRequired is returned by LaunchProfile when a
// strict-tier profile hasn't yet been acknowledged by the user. The
// JS frontend matches on this to decide between toast vs modal.
var ErrStrictTierConsentRequired = errors.New("strict-tier consent required")

// StrictTierConsent returns the consent payload for a profile. Safe
// to call for any profile — for non-strict profiles it returns
// Tier="" and NeedsConsent=false.
func (a *App) StrictTierConsent(name string) (info StrictTierConsentInfo, err error) {
	defer guiErr("StrictTierConsent", &err)
	if a.store == nil {
		return info, fmt.Errorf("profile store not ready")
	}
	p, err := a.store.Load(name)
	if err != nil {
		return info, err
	}
	info.ProfileName = p.Name
	if !p.AntiFingerprint.IsStrict() {
		return info, nil
	}
	info.Tier = "strict"
	info.NeedsConsent = p.NeedsStrictTierConsent()
	info.DataDir = p.DataDir
	info.AcceptedAtUnix = p.StrictMITMAcceptedAt.Unix()
	if p.StrictMITMAcceptedAt.IsZero() {
		info.AcceptedAtUnix = 0
	}
	info.CACertPath = tlsmitm.CACertPathForProfile(p.DataDir)
	if pemBytes, readErr := os.ReadFile(info.CACertPath); readErr == nil {
		if subj, fp := parseCAFingerprint(pemBytes); fp != "" {
			info.CASubject = subj
			info.CAFingerprintHex = fp
		}
	}
	if p.DataDir != "" {
		if _, statErr := os.Stat(filepath.Join(p.DataDir, "veil-ca", "root.key.in-keystore")); statErr == nil {
			info.KeystoreBacked = true
		}
	}
	info.HumanScopeSummary = strings.TrimSpace(`
This profile uses TLS interception ("strict" anti-fingerprint).
Veil will install a Veil-issued root certificate ONLY into the
browser data directory shown above. Your other browsers and the
system trust store are not modified.

Scope: this CA is trusted by browsers Veil launches against this
profile, and only this profile. Deleting the profile removes the CA
and (if the OS keystore is available) the private key.

Veil sees decrypted traffic for this profile while it's running —
that's how the TLS fingerprint coherence works. Disable strict tier
or switch the profile to "basic" if that's not what you want.
`)
	return info, nil
}

// AcceptStrictTier records the user's acceptance with the current
// time and persists it.
func (a *App) AcceptStrictTier(name string) (err error) {
	defer guiErr("AcceptStrictTier", &err)
	if a.store == nil {
		return fmt.Errorf("profile store not ready")
	}
	p, err := a.store.Load(name)
	if err != nil {
		return err
	}
	p.StrictMITMAcceptedAt = time.Now().UTC()
	p.UpdatedAt = p.StrictMITMAcceptedAt
	return a.store.Save(p)
}

// RevokeStrictTier clears acceptance — next LaunchProfile will
// re-prompt. Useful for "I want to re-review the CA" flows or after
// regenerating the CA.
func (a *App) RevokeStrictTier(name string) (err error) {
	defer guiErr("RevokeStrictTier", &err)
	if a.store == nil {
		return fmt.Errorf("profile store not ready")
	}
	p, err := a.store.Load(name)
	if err != nil {
		return err
	}
	p.StrictMITMAcceptedAt = time.Time{}
	p.UpdatedAt = time.Now().UTC()
	return a.store.Save(p)
}

// parseCAFingerprint extracts the subject and a colon-separated
// SHA-256 fingerprint of the first CERTIFICATE block in PEM bytes.
// Returns empty strings on parse failure (the consent dialog
// gracefully omits those fields rather than blocking the whole UI).
func parseCAFingerprint(pemBytes []byte) (subject, fp string) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	sum := sha256.Sum256(cert.Raw)
	hexed := hex.EncodeToString(sum[:])
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(strings.ToUpper(hexed[i : i+2]))
	}
	return cert.Subject.String(), b.String()
}
