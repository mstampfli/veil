package profile

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// EndpointInfo describes a profile chain hop's known endpoint, derived
// purely from the on-disk config (no network). The IP is what we
// connect TO; whether IP-we-connect-to == IP-we-egress-from depends on
// the provider — in commercial-VPN setups they're the same, but we
// never assume; the caller treats this as a HINT only and verifies
// the actual exit at first launch.
type EndpointInfo struct {
	Kind     string // "wireguard" | "openvpn" | "socks5" | "http" | "tor"
	Host     string // raw host as written (IP literal or hostname)
	Port     int
	IsIP     bool   // true if Host parses as IP literal (no DNS needed)
	HostIP   net.IP // populated if IsIP
}

// ReadFirstHopEndpoint parses the first hop of a profile's chain and
// returns the endpoint we'd be connecting to. Returns ErrUnknown if
// the chain hop type doesn't have a fixed endpoint (e.g. Tor).
//
// This is OFFLINE — no DNS, no probe. Hostname endpoints are
// returned as-is with IsIP=false; the caller decides whether to
// resolve (and accept the leak that DNS implies) or wait until first
// launch.
func (p *Profile) ReadFirstHopEndpoint() (*EndpointInfo, error) {
	if len(p.Chain) == 0 {
		return nil, errors.New("profile has no chain")
	}
	b := p.Chain[0]
	switch b.Kind {
	case BackendSOCKS5, BackendHTTP:
		return makeEndpoint(string(b.Kind), b.Host, b.Port), nil
	case BackendWireGuard:
		return parseWGEndpoint(b.ConfigPath)
	case BackendOpenVPN:
		return parseOVPNEndpoint(b.ConfigPath)
	case BackendTor:
		return nil, ErrUnknown
	}
	return nil, fmt.Errorf("unsupported backend kind %q", b.Kind)
}

// ErrUnknown is returned when an endpoint can't be determined offline
// (e.g. Tor exit nodes are picked dynamically).
var ErrUnknown = errors.New("endpoint unknown until first launch")

func makeEndpoint(kind, host string, port int) *EndpointInfo {
	ei := &EndpointInfo{Kind: kind, Host: host, Port: port}
	if ip := net.ParseIP(host); ip != nil {
		ei.IsIP = true
		ei.HostIP = ip
	}
	return ei
}

// parseWGEndpoint reads a WireGuard config and returns the [Peer]
// section's Endpoint. Format:
//
//	[Peer]
//	Endpoint = 193.32.249.50:51820
//	Endpoint = de.mullvad.net:51820
func parseWGEndpoint(path string) (*EndpointInfo, error) {
	if path == "" {
		return nil, errors.New("wireguard config path empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "Endpoint = host:port" — case-insensitive on key.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !strings.EqualFold(key, "Endpoint") {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		host, port, err := splitHostPort(val)
		if err != nil {
			return nil, fmt.Errorf("wg endpoint %q: %w", val, err)
		}
		return makeEndpoint("wireguard", host, port), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("wireguard config has no [Peer] Endpoint")
}

// parseOVPNEndpoint reads an OpenVPN config and returns the first
// `remote host port` directive.
func parseOVPNEndpoint(path string) (*EndpointInfo, error) {
	if path == "" {
		return nil, errors.New("openvpn config path empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "remote ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		host := fields[1]
		port := 0
		fmt.Sscanf(fields[2], "%d", &port)
		if port == 0 {
			port = 1194
		}
		return makeEndpoint("openvpn", host, port), nil
	}
	return nil, errors.New("openvpn config has no `remote` directive")
}

func splitHostPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	if port <= 0 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return host, port, nil
}
