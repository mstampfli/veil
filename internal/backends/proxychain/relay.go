// Package proxychain implements a small SOCKS5 server that forwards each
// accepted connection through a downstream proxy URL. It's used to make
// chains like "socks5_a → socks5_b" or "tor → socks5" work — Veil spawns
// a relay listener inside the namespace and the launched app's proxy
// points at the relay, which talks to socks5_b through socks5_a.
package proxychain

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// Relay is a SOCKS5 listener that chains every accepted connection to
// an upstream proxy.
type Relay struct {
	listener net.Listener
	upstream string
	dialer   proxy.ContextDialer

	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

// Start binds a new SOCKS5 listener on listenAddr (use ":0" for an
// ephemeral port) and forwards through upstreamURL. Returns the
// concrete listening address and the Relay.
//
// upstreamURL can be socks5://host:port[/...] or http(s)://host:port[/...].
func Start(listenAddr, upstreamURL string) (*Relay, string, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, "", err
	}
	dialer, err := BuildUpstreamDialer(u)
	if err != nil {
		return nil, "", err
	}
	return StartWithDialer(listenAddr, dialer, upstreamURL)
}

// StartWithDialer is like Start but forwards through a caller-supplied
// upstream dialer instead of one built from a single URL. This lets a
// caller compose a nested chain — e.g. "dial the final SOCKS5 server
// THROUGH the previous hop, then SOCKS5 to the target" — so a proxy that
// follows another proxy hop is actually traversed instead of bypassed.
// label is cosmetic (Status only).
func StartWithDialer(listenAddr string, dialer proxy.ContextDialer, label string) (*Relay, string, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, "", err
	}
	r := &Relay{listener: ln, upstream: label, dialer: dialer}
	go r.acceptLoop()
	return r, ln.Addr().String(), nil
}

// BuildUpstreamDialer returns a ContextDialer that reaches a target
// through the proxy described by u (socks5/socks5h or http/https).
// Exported so other backends can compose nested chains.
func BuildUpstreamDialer(u *url.URL) (proxy.ContextDialer, error) {
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 dialer not ContextDialer")
		}
		return cd, nil
	case "http", "https":
		return &httpConnectDialer{u: u}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", u.Scheme)
	}
}

func (r *Relay) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	err := r.listener.Close()
	r.wg.Wait()
	return err
}

func (r *Relay) acceptLoop() {
	for {
		c, err := r.listener.Accept()
		if err != nil {
			r.mu.Lock()
			done := r.closed
			r.mu.Unlock()
			if done {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		r.wg.Add(1)
		go r.handle(c)
	}
}

// handle implements the SOCKS5 server side of RFC 1928 enough to forward
// CONNECT requests to the upstream dialer.
func (r *Relay) handle(client net.Conn) {
	defer r.wg.Done()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nm := int(hdr[1])
	methods := make([]byte, nm)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// Reply: no auth (0x00).
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[1] != 0x01 { // CONNECT only
		_ = writeSocksReply(client, 0x07, "0.0.0.0", 0)
		return
	}
	host, err := readSocksAddr(client, req[3])
	if err != nil {
		_ = writeSocksReply(client, 0x01, "0.0.0.0", 0)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	// HARD FAIL on hostname-with-no-local-resolution. Passing hostname
	// to the upstream SOCKS5 dialer would let the upstream's exit
	// resolver do the DNS — leaking the queried domain to whatever
	// resolver the exit operator picked. Resolve locally first so
	// DNS goes through the netns's configured resolver chain
	// (which under dns_proxy is the in-netns DoH proxy).
	if net.ParseIP(host) == nil && !strings.HasSuffix(strings.ToLower(host), ".onion") {
		lctx, lcancel := context.WithTimeout(context.Background(), 30*time.Second)
		ips, lerr := net.DefaultResolver.LookupIP(lctx, "ip4", host)
		lcancel()
		if lerr != nil || len(ips) == 0 {
			_ = writeSocksReply(client, 0x04, "0.0.0.0", 0) // host unreachable
			return
		}
		host = ips[0].String()
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))

	// Reset deadline; long-lived sessions are fine.
	_ = client.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream, err := r.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = writeSocksReply(client, 0x05, "0.0.0.0", 0) // connection refused
		return
	}
	defer upstream.Close()
	_ = writeSocksReply(client, 0x00, "0.0.0.0", 0)

	go func() { _, _ = io.Copy(upstream, client) }()
	_, _ = io.Copy(client, upstream)
}

func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		host := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, host); err != nil {
			return "", err
		}
		return string(host), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

func writeSocksReply(w io.Writer, status byte, ip string, port int) error {
	_, err := w.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// httpConnectDialer dials via an HTTP CONNECT proxy.
type httpConnectDialer struct{ u *url.URL }

func (d *httpConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host := d.u.Host
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	auth := ""
	if d.u.User != nil {
		pw, _ := d.u.User.Password()
		auth = "Proxy-Authorization: Basic " + basic(d.u.User.Username(), pw) + "\r\n"
	}
	req := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n" + auth + "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	err = readConnectResponse(c)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// readConnectResponse consumes EXACTLY the HTTP CONNECT response headers
// (up to and including the CRLFCRLF terminator) and verifies a 2xx
// status. It reads one byte at a time on purpose: a buffered/large read
// would swallow any tunnel bytes the proxy pipelines after the response
// (corrupting the very first payload), and a single fixed read can pass a
// prefix check on a split response while leaving stray header bytes in
// the stream. Reading to the terminator leaves all tunnel data in the
// socket for the relay's io.Copy. Header size is capped to avoid an
// unbounded read from a hostile/broken proxy.
func readConnectResponse(c net.Conn) error {
	var resp []byte
	one := make([]byte, 1)
	for len(resp) < 8192 {
		if _, err := io.ReadFull(c, one); err != nil {
			return err
		}
		resp = append(resp, one[0])
		if bytes.HasSuffix(resp, []byte("\r\n\r\n")) {
			status := string(resp)
			if !strings.HasPrefix(status, "HTTP/1.1 200") && !strings.HasPrefix(status, "HTTP/1.0 200") {
				return fmt.Errorf("CONNECT failed: %q", strings.SplitN(status, "\r\n", 2)[0])
			}
			return nil
		}
	}
	return fmt.Errorf("CONNECT response headers exceeded 8192 bytes without terminator")
}

func basic(user, pass string) string {
	return base64Std(user + ":" + pass)
}

// base64Std is a tiny wrapper that avoids pulling in encoding/base64 as
// a top-level import — keeps the import list local.
func base64Std(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	for i := 0; i < len(s); i += 3 {
		c := uint32(s[i]) << 16
		n := 1
		if i+1 < len(s) {
			c |= uint32(s[i+1]) << 8
			n = 2
		}
		if i+2 < len(s) {
			c |= uint32(s[i+2])
			n = 3
		}
		out = append(out,
			alpha[(c>>18)&0x3f],
			alpha[(c>>12)&0x3f])
		if n >= 2 {
			out = append(out, alpha[(c>>6)&0x3f])
		} else {
			out = append(out, '=')
		}
		if n >= 3 {
			out = append(out, alpha[c&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}
