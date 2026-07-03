// Package geoip provides offline IP-to-country lookup for Veil's
// pre-flight and locked-endpoint verification paths.
//
// Design priorities:
//   1. ZERO third-party calls. Lookups are file-based, microsecond-fast.
//   2. HONEST UNCERTAINTY. If the DB doesn't have the IP, we say so —
//      we never guess. Callers handle the unknown case explicitly
//      (warn, fail, or fall back to opt-in online lookup).
//   3. PURE INFORMATION. The pre-flight country is INFORMATIONAL only.
//      Real verification happens by querying the actual exit IP after
//      the chain comes up — that's ground truth.
//
// Database: this package consumes a MaxMind-format .mmdb file (the
// MaxMind Geolite2-Country format also supported by DB-IP, IP2Location,
// etc). The file is loaded from one of these paths in order:
//
//   1. $VEIL_GEOIP_DB              (env override)
//   2. <user-config>/veil/geoip-country.mmdb
//   3. /usr/local/share/veil/geoip-country.mmdb
//   4. /usr/share/veil/geoip-country.mmdb
//
// If no file is found, Lookup() returns (_, false) — caller must
// handle the unknown case. We do NOT bundle a database in the binary
// because (a) MaxMind GeoLite2 requires user signup and (b) keeping
// it as a separate file lets users update it without rebuilding Veil.
//
// Recommended free, freely-redistributable database:
//   https://db-ip.com/db/download/ip-to-country-lite (CC BY 4.0)
//
// Install via: `veil setup --install-geoip` (downloads + installs).
package geoip

import (
	"errors"
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

var (
	once    sync.Once
	db      *maxminddb.Reader
	err     error
	asnOnce sync.Once
	asnDB   *maxminddb.Reader
	asnErr  error
)

// Lookup returns the ISO 3166-1 alpha-2 country code for the given IP.
// ok=false means the database doesn't have a country for this IP —
// caller MUST handle the unknown case (do NOT default to a guess).
//
// First call lazily opens the database; subsequent calls are
// memoized. If no database is installed, ok is permanently false.
func Lookup(ip net.IP) (country string, ok bool) {
	once.Do(open)
	if db == nil || ip == nil {
		return "", false
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := db.Lookup(ip, &rec); err != nil {
		return "", false
	}
	if rec.Country.ISOCode == "" {
		return "", false
	}
	return rec.Country.ISOCode, true
}

// IsAvailable reports whether a GeoIP database is loaded. The GUI uses
// this to decide whether to show pre-flight country hints or "install
// the database for offline country preview" messaging.
func IsAvailable() bool {
	once.Do(open)
	return db != nil
}

// LoadError returns the reason the DB couldn't be loaded, or nil if
// loaded successfully or no path attempted.
func LoadError() error {
	once.Do(open)
	return err
}

// CountryDBBuildTime returns the date the loaded country database was
// built, read from the .mmdb metadata (build_epoch) — the authoritative
// data date, independent of file mtime. ok=false if no DB is loaded or
// the metadata lacks a build epoch.
//
// Callers use this to warn when the local DB is stale: lock_country /
// lock_asn verify the live exit IP against this offline DB, so address
// reassignments that happened after the build date can produce a false
// mismatch (a wrongly-blocked launch) or a false pass. DB-IP's free tier
// republishes monthly.
func CountryDBBuildTime() (time.Time, bool) {
	once.Do(open)
	if db == nil {
		return time.Time{}, false
	}
	if e := db.Metadata.BuildEpoch; e > 0 {
		return time.Unix(int64(e), 0).UTC(), true
	}
	return time.Time{}, false
}

// LookupString is a convenience wrapper that parses the IP string.
func LookupString(ipStr string) (country string, ok bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}
	return Lookup(ip)
}

func open() {
	for _, p := range candidatePaths() {
		if p == "" {
			continue
		}
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		r, openErr := maxminddb.Open(p)
		if openErr != nil {
			err = fmt.Errorf("geoip: open %s: %w", p, openErr)
			continue
		}
		db = r
		return
	}
	if err == nil {
		err = errors.New("geoip: no database found in standard paths — run `veil setup --install-geoip`")
	}
}

func candidatePaths() []string {
	out := []string{os.Getenv("VEIL_GEOIP_DB")}
	if home := userHome(); home != "" {
		out = append(out, filepath.Join(home, ".config", "veil", "geoip-country.mmdb"))
	}
	out = append(out,
		"/usr/local/share/veil/geoip-country.mmdb",
		"/usr/share/veil/geoip-country.mmdb",
	)
	return out
}

// LookupASN returns the autonomous system number + organization for an
// IP, or "" if the database isn't installed or the IP isn't mapped.
//
// Format: returns "AS#####" string (e.g. "AS9009"). Use AsnOrg() if
// you need the org name. Caller MUST handle the (_, false) case
// without guessing — same uncertainty discipline as Lookup().
//
// Database: GeoLite2-ASN.mmdb (or DB-IP equivalent), separate file
// from the country DB. Loaded from these paths in order:
//   1. $VEIL_GEOIP_ASN_DB
//   2. <user-config>/veil/geoip-asn.mmdb
//   3. /usr/local/share/veil/geoip-asn.mmdb
//   4. /usr/share/veil/geoip-asn.mmdb
func LookupASN(ip net.IP) (asn string, org string, ok bool) {
	asnOnce.Do(openASN)
	if asnDB == nil || ip == nil {
		return "", "", false
	}
	var rec struct {
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	}
	if err := asnDB.Lookup(ip, &rec); err != nil || rec.AutonomousSystemNumber == 0 {
		return "", "", false
	}
	return fmt.Sprintf("AS%d", rec.AutonomousSystemNumber), rec.AutonomousSystemOrganization, true
}

// LookupASNString is a convenience wrapper that parses the IP string.
func LookupASNString(ipStr string) (asn string, org string, ok bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", false
	}
	return LookupASN(ip)
}

// IsASNAvailable reports whether the ASN database is loaded.
func IsASNAvailable() bool {
	asnOnce.Do(openASN)
	return asnDB != nil
}

func openASN() {
	for _, p := range asnCandidatePaths() {
		if p == "" {
			continue
		}
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		r, openErr := maxminddb.Open(p)
		if openErr != nil {
			asnErr = fmt.Errorf("geoip-asn: open %s: %w", p, openErr)
			continue
		}
		asnDB = r
		return
	}
	if asnErr == nil {
		asnErr = errors.New("geoip-asn: no database found — install GeoLite2-ASN.mmdb")
	}
}

func asnCandidatePaths() []string {
	out := []string{os.Getenv("VEIL_GEOIP_ASN_DB")}
	if home := userHome(); home != "" {
		out = append(out, filepath.Join(home, ".config", "veil", "geoip-asn.mmdb"))
	}
	out = append(out,
		"/usr/local/share/veil/geoip-asn.mmdb",
		"/usr/share/veil/geoip-asn.mmdb",
	)
	return out
}

func userHome() string {
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			if u, err := osuser.Lookup(name); err == nil {
				return u.HomeDir
			}
		}
		if uid := os.Getenv("PKEXEC_UID"); uid != "" {
			if u, err := osuser.LookupId(uid); err == nil {
				return u.HomeDir
			}
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}
