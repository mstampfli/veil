package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/mstampfli/veil/internal/backends"
)

// HTTPClientForSteering returns an http.Client routed through the steering's
// proxy (if any). When no proxy is set the client uses the OS default
// transport, which the engine is responsible for binding into the right
// namespace before this is called.
func HTTPClientForSteering(s *backends.Steering) (*http.Client, error) {
	t := &http.Transport{
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
	}
	if s != nil && s.ProxyURL != "" {
		u, err := url.Parse(s.ProxyURL)
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h":
			var auth *proxy.Auth
			if u.User != nil {
				p, _ := u.User.Password()
				auth = &proxy.Auth{User: u.User.Username(), Password: p}
			}
			d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
			if err != nil {
				return nil, err
			}
			ctxDialer, ok := d.(proxy.ContextDialer)
			if !ok {
				return nil, fmt.Errorf("socks5 dialer doesn't implement ContextDialer")
			}
			t.DialContext = ctxDialer.DialContext
		case "http", "https":
			t.Proxy = http.ProxyURL(u)
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
		}
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: t}, nil
}

// FetchExternalIP returns the public IP as seen via the given client.
// Uses a few hardcoded fallbacks; never falls back to plain DNS.
func FetchExternalIP(ctx context.Context, c *http.Client) (string, error) {
	endpoints := []string{
		"https://api.ipify.org?format=json",
		"https://ifconfig.co/json",
		"https://ipv4.icanhazip.com",
	}
	var lastErr error
	for _, ep := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "veil/1.0")
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		_ = resp.Body.Close()
		s := strings.TrimSpace(string(body[:n]))
		if strings.HasPrefix(s, "{") {
			var v struct{ IP string `json:"ip"` }
			if err := json.Unmarshal([]byte(s), &v); err == nil && v.IP != "" {
				return v.IP, nil
			}
		}
		if s != "" {
			return s, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no IP endpoint responded")
	}
	return "", lastErr
}
