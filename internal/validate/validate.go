// Package validate centralizes input validation for security-relevant
// fields. Every entry point that accepts user input (CLI args, GUI
// form fields, profile YAML, persona YAML) routes through here.
//
// Defense-in-depth: even though Veil is a local single-user tool, a
// malicious profile YAML or persona file could still inject command
// strings or path-traversal payloads if validation is sloppy.
//
// All validators return a wrapped error pointing at the field name,
// so caller can `if err := validate.Name(p.Name); err != nil { return
// fmt.Errorf("profile.name: %w", err) }`.
package validate

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	nameRE       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)
	countryRE    = regexp.MustCompile(`^[A-Z]{2}$`)
	asnRE        = regexp.MustCompile(`^AS\d+$`)
	hhmmwindowRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d-([01]\d|2[0-3]):[0-5]\d$`)
	bcp47RE      = regexp.MustCompile(`^[a-z]{2,3}(-[A-Z][a-z]{3})?(-[A-Z]{2})?$`)
)

// Name validates profile / persona names. ASCII alphanum + dash +
// underscore, must start with alphanum, max 63 chars. Same shape as
// DNS labels.
func Name(s string) error {
	if s == "" {
		return errors.New("name: empty")
	}
	if !nameRE.MatchString(s) {
		return fmt.Errorf("name %q: must match %s", s, nameRE.String())
	}
	return nil
}

// Country validates ISO 3166-1 alpha-2 country code. Two uppercase letters.
func Country(s string) error {
	if s == "" {
		return nil // optional field
	}
	if !countryRE.MatchString(s) {
		return fmt.Errorf("country %q: must be ISO 3166-1 alpha-2 (e.g. DE, US, JP)", s)
	}
	return nil
}

// ASN validates an Autonomous System Number in the form AS#####.
func ASN(s string) error {
	if s == "" {
		return nil
	}
	if !asnRE.MatchString(s) {
		return fmt.Errorf("asn %q: must be AS<digits> (e.g. AS9009)", s)
	}
	return nil
}

// IP validates an IPv4 or IPv6 literal. Empty allowed.
func IP(s string) error {
	if s == "" {
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("ip %q: not a valid IPv4/IPv6 address", s)
	}
	return nil
}

// CIDR validates an IPv4/IPv6 CIDR.
func CIDR(s string) error {
	if s == "" {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err != nil {
		return fmt.Errorf("cidr %q: %w", s, err)
	}
	return nil
}

// URL validates a URL with the supplied allowed schemes. Empty allowed.
func URL(s string, allowedSchemes ...string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("url %q: %w", s, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("url %q: missing scheme", s)
	}
	if len(allowedSchemes) > 0 {
		ok := false
		for _, a := range allowedSchemes {
			if strings.EqualFold(u.Scheme, a) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("url %q: scheme %q not in %v", s, u.Scheme, allowedSchemes)
		}
	}
	return nil
}

// ProxyURL validates a proxy URL (must use socks5/socks5h/http/https).
func ProxyURL(s string) error {
	return URL(s, "socks5", "socks5h", "http", "https")
}

// AbsPath validates that a path is absolute and contains no traversal
// elements (`..`). Empty allowed.
func AbsPath(s string) error {
	if s == "" {
		return nil
	}
	if !filepath.IsAbs(s) {
		return fmt.Errorf("path %q: must be absolute", s)
	}
	clean := filepath.Clean(s)
	if clean != s {
		return fmt.Errorf("path %q: not in canonical form (got %q)", s, clean)
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("path %q: contains parent-directory reference", s)
	}
	return nil
}

// ScheduleWindow validates "HH:MM-HH:MM".
func ScheduleWindow(s string) error {
	if s == "" {
		return nil
	}
	if !hhmmwindowRE.MatchString(s) {
		return fmt.Errorf("schedule_window %q: must be HH:MM-HH:MM", s)
	}
	return nil
}

// Locale validates a BCP-47 language tag (e.g. en-US, de-DE, fr).
// Strict shape check — for full ICU validation, use language.Parse.
func Locale(s string) error {
	if s == "" {
		return nil
	}
	// Accept libc-style "en_US.UTF-8" too — strip suffix.
	core := s
	if i := strings.Index(core, "."); i >= 0 {
		core = core[:i]
	}
	core = strings.ReplaceAll(core, "_", "-")
	if !bcp47RE.MatchString(core) {
		return fmt.Errorf("locale %q: not a recognized BCP-47 / libc locale", s)
	}
	return nil
}

// Timezone validates an IANA timezone (e.g. Europe/Berlin).
func Timezone(s string) error {
	if s == "" {
		return nil
	}
	if _, err := time.LoadLocation(s); err != nil {
		return fmt.Errorf("timezone %q: %w", s, err)
	}
	return nil
}

// ExecArg validates one argv entry — rejects null bytes, leading dashes
// that look like our own flags (defense against profile YAML injecting
// flags into the launched app), and whitespace-only.
func ExecArg(s string) error {
	if strings.ContainsRune(s, 0) {
		return fmt.Errorf("arg %q: contains null byte", s)
	}
	return nil
}

// PortRange validates "<start>-<end>" with start <= end and both in
// the ephemeral port range.
func PortRange(s string) error {
	if s == "" {
		return nil
	}
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("port_range %q: must be START-END", s)
	}
	a, err := atoiPort(parts[0])
	if err != nil {
		return fmt.Errorf("port_range %q start: %w", s, err)
	}
	b, err := atoiPort(parts[1])
	if err != nil {
		return fmt.Errorf("port_range %q end: %w", s, err)
	}
	if a > b {
		return fmt.Errorf("port_range %q: start > end", s)
	}
	if a < 1024 {
		return fmt.Errorf("port_range %q: start below 1024 (privileged)", s)
	}
	return nil
}

func atoiPort(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("out of range")
	}
	return n, nil
}
