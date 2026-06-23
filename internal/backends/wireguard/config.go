package wireguard

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Config is a parsed wg-quick style .conf.
type Config struct {
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []string
	MTU        int

	Peers []Peer
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// ParseConfig parses a wg-quick style INI configuration.
// Only the fields Veil needs are extracted; unknown keys are ignored.
func ParseConfig(text string) (*Config, error) {
	cfg := &Config{}
	var section string
	var cur *Peer

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			if section == "peer" {
				cfg.Peers = append(cfg.Peers, Peer{})
				cur = &cfg.Peers[len(cfg.Peers)-1]
			}
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch section {
		case "interface":
			switch strings.ToLower(k) {
			case "privatekey":
				if _, err := base64.StdEncoding.DecodeString(v); err != nil {
					return nil, fmt.Errorf("invalid PrivateKey: %w", err)
				}
				cfg.PrivateKey = v
			case "address":
				for _, a := range strings.Split(v, ",") {
					p, err := netip.ParsePrefix(strings.TrimSpace(a))
					if err != nil {
						return nil, fmt.Errorf("invalid Address %q: %w", a, err)
					}
					cfg.Addresses = append(cfg.Addresses, p)
				}
			case "dns":
				for _, d := range strings.Split(v, ",") {
					cfg.DNS = append(cfg.DNS, strings.TrimSpace(d))
				}
			case "mtu":
				cfg.MTU, _ = strconv.Atoi(v)
			}
		case "peer":
			if cur == nil {
				continue
			}
			switch strings.ToLower(k) {
			case "publickey":
				cur.PublicKey = v
			case "presharedkey":
				cur.PresharedKey = v
			case "endpoint":
				if _, _, err := net.SplitHostPort(v); err != nil {
					return nil, fmt.Errorf("invalid Endpoint %q: %w", v, err)
				}
				cur.Endpoint = v
			case "allowedips":
				for _, a := range strings.Split(v, ",") {
					p, err := netip.ParsePrefix(strings.TrimSpace(a))
					if err != nil {
						return nil, fmt.Errorf("invalid AllowedIPs %q: %w", a, err)
					}
					cur.AllowedIPs = append(cur.AllowedIPs, p)
				}
			case "persistentkeepalive":
				cur.PersistentKeepalive, _ = strconv.Atoi(v)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("no [Peer] sections")
	}
	return cfg, nil
}

func splitKV(line string) (string, string, bool) {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:eq]), strings.TrimSpace(line[eq+1:]), true
}

// UAPIConfig renders the parsed config as a wireguard-go UAPI string for
// IpcSet. PrivateKey and PresharedKey are base64; UAPI wants hex.
func (c *Config) UAPIConfig() (string, error) {
	var sb strings.Builder
	priv, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&sb, "private_key=%x\n", priv)
	fmt.Fprintf(&sb, "replace_peers=true\n")
	for _, p := range c.Peers {
		pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&sb, "public_key=%x\n", pub)
		if p.PresharedKey != "" {
			psk, err := base64.StdEncoding.DecodeString(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("preshared key: %w", err)
			}
			fmt.Fprintf(&sb, "preshared_key=%x\n", psk)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&sb, "endpoint=%s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		fmt.Fprintf(&sb, "replace_allowed_ips=true\n")
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", a.String())
		}
	}
	return sb.String(), nil
}
