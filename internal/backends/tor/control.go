package tor

import (
	"bufio"
	b64pkg "encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// base64Std is Go's std-encoding base64 with our preferred padding
// behavior; alias to avoid repeating the package qualifier.
var base64Std = b64pkg.StdEncoding

// Control is a minimal Tor control-port client. Implements the small
// subset of commands Veil needs: AUTHENTICATE, GETINFO, SIGNAL.
//
// See https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/control-spec.txt
type Control struct {
	conn net.Conn
	r    *bufio.Reader
}

// Dial connects to a Tor control port and authenticates using the cookie
// file at cookiePath (the standard Tor cookie auth flow).
func Dial(addr, cookiePath string) (*Control, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return WrapControl(c, cookiePath)
}

// WrapControl wraps an already-open connection (e.g. one made from inside
// a netns) and authenticates it.
func WrapControl(c net.Conn, cookiePath string) (*Control, error) {
	ctrl := &Control{conn: c, r: bufio.NewReader(c)}
	if err := ctrl.authCookie(cookiePath); err != nil {
		_ = c.Close()
		return nil, err
	}
	return ctrl, nil
}

func (c *Control) authCookie(cookiePath string) error {
	if cookiePath == "" {
		// Try null auth first (only works if torrc has CookieAuthentication 0)
		_, err := c.do("AUTHENTICATE")
		return err
	}
	cookie, err := os.ReadFile(cookiePath)
	if err != nil {
		return fmt.Errorf("read cookie %s: %w", cookiePath, err)
	}
	_, err = c.do("AUTHENTICATE " + hex.EncodeToString(cookie))
	return err
}

// do writes a command line and reads the multi-line reply, returning all
// data lines joined by \n. Errors when the final status line isn't 250.
func (c *Control) do(cmd string) (string, error) {
	if _, err := io.WriteString(c.conn, cmd+"\r\n"); err != nil {
		return "", err
	}
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return "", fmt.Errorf("short reply: %q", line)
		}
		code := line[:3]
		sep := line[3]
		body := line[4:]
		switch sep {
		case '-':
			lines = append(lines, body)
		case ' ':
			if code != "250" {
				return "", fmt.Errorf("tor control: %s %s", code, body)
			}
			if body != "" && body != "OK" {
				lines = append(lines, body)
			}
			return strings.Join(lines, "\n"), nil
		case '+':
			// Multi-line data block; read until "."
			lines = append(lines, body)
			for {
				dl, err := c.r.ReadString('\n')
				if err != nil {
					return "", err
				}
				dl = strings.TrimRight(dl, "\r\n")
				if dl == "." {
					break
				}
				lines = append(lines, dl)
			}
		default:
			return "", fmt.Errorf("unknown sep in %q", line)
		}
	}
}

// NewCircuit asks Tor to build new circuits for subsequent connections.
func (c *Control) NewCircuit() error {
	_, err := c.do("SIGNAL NEWNYM")
	return err
}

// SetConf updates a torrc-style option at runtime. Used to tighten
// ExitNodes into StrictNodes after bootstrap completes — writing
// StrictNodes 1 to torrc up front interacts poorly with bootstrap
// in some configurations, so we stage the strict pin in two phases.
func (c *Control) SetConf(key, value string) error {
	_, err := c.do("SETCONF " + key + "=" + value)
	return err
}

// CircuitStatus returns the parsed `circuit-status` info.
func (c *Control) CircuitStatus() (string, error) {
	return c.do("GETINFO circuit-status")
}

// GetConf reads the current value(s) for a torrc option. Used to
// verify that a SETCONF actually persisted the value Tor is honoring,
// not just returned 250 OK to the wire-level write.
func (c *Control) GetConf(key string) (string, error) {
	return c.do("GETCONF " + key)
}

// CloseCircuit closes a single circuit by ID (the integer Tor assigns
// in `circuit-status` output). NEWNYM only marks unused circuits dirty
// for new streams — actively-built circuits in the pool can still be
// reused for stream attachment unless explicitly closed. After a fresh
// SETCONF ExitNodes/StrictNodes, we want to drop EVERY pre-pin circuit
// so the next stream is forced through a circuit built with the new
// constraints.
func (c *Control) CloseCircuit(id string) error {
	_, err := c.do("CLOSECIRCUIT " + id)
	return err
}

// Relay is a single relay's identity in the current consensus.
type Relay struct {
	FingerprintHex string // 40-char uppercase hex
	IP             string // IPv4 dotted-quad
	IsExit         bool   // has the Exit consensus flag
}

// EnumerateConsensus returns every relay in the current consensus
// (GETINFO ns/all). Used to filter exit candidates by an external
// GeoIP DB before sending fingerprint-pinned ExitNodes — the
// canonical workaround for Tor's bundled GeoIP DB drifting from
// MaxMind/ipinfo.
//
// The response is large (often several MB on the live network).
// Caller should expect this to take a second or two.
func (c *Control) EnumerateConsensus() ([]Relay, error) {
	out, err := c.do("GETINFO ns/all")
	if err != nil {
		return nil, err
	}
	var relays []Relay
	var cur Relay
	have := false
	flush := func() {
		if have && cur.FingerprintHex != "" && cur.IP != "" {
			relays = append(relays, cur)
		}
		cur = Relay{}
		have = false
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'r':
			flush()
			// Format: r nickname identity-b64 descr-b64 date time IP ORPort DirPort
			fields := strings.Fields(line)
			if len(fields) < 8 {
				continue
			}
			fpHex, err := base64IdentityToHex(fields[2])
			if err != nil {
				continue
			}
			cur.FingerprintHex = fpHex
			cur.IP = fields[6]
			have = true
		case 's':
			// s Flag1 Flag2 ...
			if !have {
				continue
			}
			for _, f := range strings.Fields(line)[1:] {
				if f == "Exit" {
					cur.IsExit = true
				}
			}
		}
	}
	flush()
	return relays, nil
}

// base64IdentityToHex decodes a relay identity field from "r" lines —
// 20 bytes of SHA1 in base64 with no padding — into the 40-char
// uppercase hex form Tor's ExitNodes accepts as `$FP`.
func base64IdentityToHex(b64 string) (string, error) {
	// Tor's "r" lines strip "=" padding from base64. Add it back.
	missing := (4 - len(b64)%4) % 4
	padded := b64 + strings.Repeat("=", missing)
	raw, err := base64Std.DecodeString(padded)
	if err != nil {
		return "", err
	}
	if len(raw) != 20 {
		return "", fmt.Errorf("identity not 20 bytes (got %d)", len(raw))
	}
	return strings.ToUpper(hex.EncodeToString(raw)), nil
}

// AllCircuitIDs walks the GETINFO circuit-status reply and returns the
// integer ID of every circuit (any state). Caller can iterate +
// CloseCircuit each.
func (c *Control) AllCircuitIDs() ([]string, error) {
	out, err := c.CircuitStatus()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		// First field is the integer circuit ID.
		id := fields[0]
		if id == "" || id[0] < '0' || id[0] > '9' {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// StreamStatus returns the parsed `stream-status`.
func (c *Control) StreamStatus() (string, error) {
	return c.do("GETINFO stream-status")
}

// RelayIP returns the IP of a relay identified by its 40-hex
// fingerprint, by reading its consensus entry. Empty string on miss.
func (c *Control) RelayIP(fp string) (string, error) {
	out, err := c.do("GETINFO ns/id/" + fp)
	if err != nil {
		return "", err
	}
	// `r <nick> <id_hash> <descriptor_hash> <pub> <date> <time> <IP> <ORPort> <DirPort>`
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "r ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 7 {
			return fields[6], nil
		}
	}
	return "", nil
}

// Close closes the control connection.
func (c *Control) Close() error {
	return c.conn.Close()
}
