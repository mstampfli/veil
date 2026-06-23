// Package dohproxy is a minimal DNS-to-DoH proxy. Accepts wire-format
// DNS queries on UDP and TCP, forwards each as an RFC 8484
// application/dns-message POST to an upstream DoH URL, returns the
// response on the same transport.
//
// Usage modes:
//
//   - Serve(ctx, udpListener, tcpListener, upstream): caller already
//     bound the listeners (e.g. inside the engine's netns). Run this
//     as a goroutine — it blocks until ctx is cancelled.
//
//   - Run(ctx, listenAddr, upstream, readyFile): self-contained
//     standalone mode (used by the `veil dohproxy` CLI subcommand).
//     Binds the listeners itself, then calls Serve.
//
// The engine prefers Serve because the userns child is already inside
// the profile's netns; spawning a subprocess via `ip netns exec` was
// fragile (stdio interactions with userns + ip-netns-exec produced
// hangs that I couldn't pin down).
package dohproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Serve runs the proxy using already-bound listeners. Returns when
// ctx is cancelled or both listeners error out. Closes both listeners
// on return; caller must not use them afterward.
func Serve(ctx context.Context, udp net.PacketConn, tcp net.Listener, upstreamURL string) error {
	// Generous timeout — when this proxy runs inside a Tor-bearing
	// netns, the upstream DoH HTTPS connection rides Tor + WG, and
	// uncached recursive lookups (random subdomains like whoer's
	// leak-test queries) regularly need 10-25s end-to-end. Tight
	// timeout would cause the MITM caller's lookup to fail, which
	// (under hard-fail policy) would tank the whole connection.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:    8,
			IdleConnTimeout: 90 * time.Second,
		},
	}
	// In-memory DNS cache. Browsers issue MANY duplicate lookups
	// (preconnect, parallel sub-resource loads, retry on connect
	// failures). Each duplicate without a cache = a full DoH-via-
	// Tor roundtrip (10-25s). Caching makes hot hostnames instant
	// and reduces upstream load N-fold per profile, which directly
	// fixes the multi-profile lag.
	cache := newDNSCache()

	go func() {
		<-ctx.Done()
		_ = udp.Close()
		_ = tcp.Close()
	}()

	go serveUDP(ctx, udp, client, upstreamURL, cache)
	go serveTCP(ctx, tcp, client, upstreamURL, cache)
	<-ctx.Done()
	return nil
}

// dnsCache: tiny TTL'd query/response cache shared between UDP+TCP
// serve loops. Key zeroes the 2-byte transaction ID so different
// IDs with the same logical question share an entry. TTL comes
// from the answer's smallest record TTL, capped at 5 min.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	resp    []byte
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func cacheKey(query []byte) string {
	if len(query) < 12 {
		return string(query)
	}
	clone := append([]byte(nil), query...)
	clone[0], clone[1] = 0, 0
	return string(clone)
}

func (c *dnsCache) get(query []byte) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	e, ok := c.entries[cacheKey(query)]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	resp := append([]byte(nil), e.resp...)
	if len(resp) >= 2 && len(query) >= 2 {
		resp[0], resp[1] = query[0], query[1] // splice in caller's TXID
	}
	return resp, true
}

func (c *dnsCache) put(query, resp []byte, ttl time.Duration) {
	if c == nil || len(resp) < 12 || ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[cacheKey(query)] = dnsCacheEntry{
		resp:    append([]byte(nil), resp...),
		expires: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

func extractMinTTL(resp []byte) time.Duration {
	if len(resp) < 12 {
		return 0
	}
	ancount := int(resp[6])<<8 | int(resp[7])
	if ancount == 0 {
		return 0
	}
	pos := 12
	pos = skipName(resp, pos)
	pos += 4 // QTYPE + QCLASS
	const maxCap = 5 * time.Minute
	var min time.Duration
	for i := 0; i < ancount && pos+10 <= len(resp); i++ {
		pos = skipName(resp, pos)
		if pos+10 > len(resp) {
			break
		}
		ttl := uint32(resp[pos+4])<<24 | uint32(resp[pos+5])<<16 |
			uint32(resp[pos+6])<<8 | uint32(resp[pos+7])
		rdlen := int(resp[pos+8])<<8 | int(resp[pos+9])
		t := time.Duration(ttl) * time.Second
		if t > maxCap {
			t = maxCap
		}
		if min == 0 || t < min {
			min = t
		}
		pos += 10 + rdlen
	}
	if min > 0 && min < 30*time.Second {
		min = 30 * time.Second
	}
	return min
}

func skipName(msg []byte, off int) int {
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1
		}
		if l&0xC0 == 0xC0 {
			return off + 2
		}
		off += l + 1
	}
	return off
}

// Run is the standalone CLI mode: binds listeners itself, optionally
// touches readyFile, then delegates to Serve.
func Run(ctx context.Context, listenAddr, upstreamURL, readyFile string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP %s: %w", listenAddr, err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listenAddr, err)
	}
	tcp, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("listen TCP %s: %w", listenAddr, err)
	}
	if readyFile != "" {
		if err := os.WriteFile(readyFile, nil, 0o644); err != nil {
			_ = udp.Close()
			_ = tcp.Close()
			return fmt.Errorf("write ready-file %s: %w", readyFile, err)
		}
	}
	return Serve(ctx, udp, tcp, upstreamURL)
}

func serveUDP(ctx context.Context, l net.PacketConn, client *http.Client, upstream string, cache *dnsCache) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := l.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		if cached, ok := cache.get(query); ok {
			_, _ = l.WriteTo(cached, addr)
			continue
		}
		go func(q []byte, peer net.Addr) {
			resp, err := forward(client, upstream, q)
			if err != nil {
				return
			}
			cache.put(q, resp, extractMinTTL(resp))
			_, _ = l.WriteTo(resp, peer)
		}(query, addr)
	}
}

func serveTCP(ctx context.Context, l net.Listener, client *http.Client, upstream string, cache *dnsCache) {
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleTCPConn(c, client, upstream, cache)
	}
}

func handleTCPConn(c net.Conn, client *http.Client, upstream string, cache *dnsCache) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	if length == 0 || length > 4096 {
		return
	}
	query := make([]byte, length)
	if _, err := io.ReadFull(c, query); err != nil {
		return
	}
	var resp []byte
	if cached, ok := cache.get(query); ok {
		resp = cached
	} else {
		var err error
		resp, err = forward(client, upstream, query)
		if err != nil {
			return
		}
		cache.put(query, resp, extractMinTTL(resp))
	}
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
	copy(out[2:], resp)
	_, _ = c.Write(out)
}

func forward(client *http.Client, upstream string, query []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", upstream, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ResolveDirect does a one-shot DoH lookup for `host` against the
// IP-literal DoH URL `upstream`, returning resolved IPv4 addresses.
// Used at chain bring-up time (BEFORE any netns / chain exists) to
// resolve hostnames in WireGuard / OpenVPN configs without touching
// the host's /etc/resolv.conf — which would otherwise leak the VPN
// endpoint hostname to the user's real ISP.
//
// Encrypted in transit (HTTPS to Mullvad's IP literal), so the ISP
// sees only "TLS to 194.242.2.2:443" — generic VPN-user pattern, not
// a specific lookup. Mullvad sees the query but doesn't know who
// you are beyond your real IP (this is pre-chain — the lookup
// happens before any tunnel is up). Trade-off: shifts the trust
// from "ISP sees plaintext DNS" to "Mullvad sees encrypted query
// from a real IP," which is the same trust posture as using Mullvad
// VPN itself.
func ResolveDirect(host, upstream string) ([]net.IP, error) {
	if upstream == "" {
		upstream = "https://194.242.2.2/dns-query"
	}
	query, err := buildDNSQuery(host)
	if err != nil {
		return nil, fmt.Errorf("build DNS query: %w", err)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	resp, err := forward(client, upstream, query)
	if err != nil {
		return nil, err
	}
	return parseDNSResponseIPv4(resp)
}

// buildDNSQuery encodes a wire-format DNS A-record query for host.
func buildDNSQuery(host string) ([]byte, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{q},
	}
	return msg.Pack()
}

// parseDNSResponseIPv4 walks the answer section, returning every
// A-record IPv4 the response contained.
func parseDNSResponseIPv4(wire []byte) ([]net.IP, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("skip questions: %w", err)
	}
	var out []net.IP
	for {
		hdr, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("answer header: %w", err)
		}
		if hdr.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return nil, fmt.Errorf("A resource: %w", err)
		}
		out = append(out, net.IP(a.A[:]))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no A record returned")
	}
	return out, nil
}
