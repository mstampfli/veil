package engine

// Minimal RFC 6455 WebSocket client for in-process CDP usage. No
// dependency on gorilla/websocket or nhooyr.io. Scope is intentionally
// narrow:
//   - localhost-only (no TLS handshake)
//   - text frames only (CDP uses JSON over text)
//   - single-threaded read/write (CDP requests are sequential)
//   - no extension negotiation, no compression
//
// This is enough to drive Chrome DevTools Protocol over the browser's
// local /devtools endpoints. Anything more sophisticated (subprotocol
// negotiation, fragmented frames, ping/pong) would belong in a real
// websocket library — but for our use case, that's complexity we
// don't need.

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const wsAcceptMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsConn is a tiny WebSocket connection. Use dialWS to construct.
type wsConn struct {
	c   net.Conn
	r   *bufio.Reader
	buf []byte // scratch frame buffer for masked-frame writes
}

// dialWS performs the HTTP/1.1 -> WebSocket Upgrade handshake to the
// given ws:// URL and returns a connected wsConn. addrOverride lets
// the caller supply the dialed TCP target (e.g. when the URL contains
// a hostname we can't resolve from this netns); pass "" to use the
// URL's host directly.
func dialWS(rawURL string, addrOverride string, timeout time.Duration) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("only ws:// is supported (got %q)", u.Scheme)
	}
	addr := addrOverride
	if addr == "" {
		addr = u.Host
		if !strings.Contains(addr, ":") {
			addr = addr + ":80"
		}
	}
	d := &net.Dialer{Timeout: timeout}
	tc, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	// Sec-WebSocket-Key: 16 random bytes, base64.
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		tc.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	host := u.Host
	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Version: 13",
		// CDP requires this for Chromium 111+ to allow non-default origin.
		"Origin: http://" + host,
		"", "",
	}, "\r\n")
	_ = tc.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := tc.Write([]byte(req)); err != nil {
		tc.Close()
		return nil, fmt.Errorf("write upgrade: %w", err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		tc.Close()
		return nil, fmt.Errorf("ws upgrade: HTTP %d", resp.StatusCode)
	}
	_ = tc.SetReadDeadline(time.Time{})
	_ = tc.SetWriteDeadline(time.Time{})
	return &wsConn{c: tc, r: br}, nil
}

// writeText sends the bytes as a single masked text frame. CDP
// messages always fit in one frame for our payloads (sub-MiB).
func (w *wsConn) writeText(payload []byte) error {
	// FIN + opcode 0x1 (text)
	header := []byte{0x81}
	pl := len(payload)
	switch {
	case pl < 126:
		header = append(header, 0x80|byte(pl)) // mask bit set
	case pl <= 0xFFFF:
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[2:], uint16(pl))
	default:
		header = append(header, 0x80|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[2:], uint64(pl))
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	header = append(header, mask...)
	w.buf = append(w.buf[:0], header...)
	w.buf = append(w.buf, payload...)
	masked := w.buf[len(header):]
	for i := range masked {
		masked[i] ^= mask[i%4]
	}
	_, err := w.c.Write(w.buf)
	return err
}

// readText reads a single text frame's payload. Continuation,
// fragmented and binary frames return an error — CDP doesn't use them.
// Server-to-client frames are unmasked per RFC 6455.
func (w *wsConn) readText() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(w.r, hdr); err != nil {
		return nil, err
	}
	fin := hdr[0]&0x80 != 0
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	plen := int64(hdr[1] & 0x7F)
	switch plen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(w.r, ext); err != nil {
			return nil, err
		}
		plen = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(w.r, ext); err != nil {
			return nil, err
		}
		plen = int64(binary.BigEndian.Uint64(ext))
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(w.r, maskKey[:]); err != nil {
			return nil, err
		}
	}
	if plen > 1<<24 { // 16 MiB sanity cap
		return nil, fmt.Errorf("ws frame too large: %d bytes", plen)
	}
	payload := make([]byte, plen)
	if _, err := io.ReadFull(w.r, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	if !fin {
		return nil, errors.New("ws fragmented frames not supported")
	}
	switch opcode {
	case 0x1: // text
		return payload, nil
	case 0x8: // close
		return nil, io.EOF
	case 0x9: // ping → reply with pong, then re-read for next frame
		_ = w.writePong(payload)
		return w.readText()
	case 0xA: // pong → ignore, re-read
		return w.readText()
	default:
		return nil, fmt.Errorf("unsupported ws opcode 0x%x", opcode)
	}
}

func (w *wsConn) writePong(payload []byte) error {
	// Single-frame pong with mask. Same shape as writeText but opcode 0xA.
	header := []byte{0x8A}
	pl := len(payload)
	switch {
	case pl < 126:
		header = append(header, 0x80|byte(pl))
	case pl <= 0xFFFF:
		header = append(header, 0x80|126, 0, 0)
		binary.BigEndian.PutUint16(header[2:], uint16(pl))
	default:
		return errors.New("pong too large")
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	header = append(header, mask...)
	out := append([]byte(nil), header...)
	out = append(out, payload...)
	masked := out[len(header):]
	for i := range masked {
		masked[i] ^= mask[i%4]
	}
	_, err := w.c.Write(out)
	return err
}

func (w *wsConn) Close() error {
	// Best-effort close frame, then close TCP.
	_, _ = w.c.Write([]byte{0x88, 0x80, 0, 0, 0, 0})
	return w.c.Close()
}
