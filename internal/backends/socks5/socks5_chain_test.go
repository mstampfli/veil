package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// mockSocks5 is a minimal no-auth SOCKS5 CONNECT server that dials the
// requested address and splices. Each accepted CONNECT bumps *hits, so a
// test can assert the hop was actually traversed.
func mockSocks5(t *testing.T, hits *int32) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveMock(c, hits)
		}
	}()
	return ln
}

func serveMock(c net.Conn, hits *int32) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hdr[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		hb := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, hb); err != nil {
			return
		}
		host = string(hb)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	atomic.AddInt32(hits, 1)
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte{0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

// TestDialThroughPrev_TraversesBothHops proves the chained dialer routes
// app -> PREV -> THIS -> target. The pre-fix code forwarded through prev
// only and dropped the second hop, so bHits would have stayed 0.
func TestDialThroughPrev_TraversesBothHops(t *testing.T) {
	var aHits, bHits int32
	tgt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	go func() {
		c, err := tgt.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("HELLO"))
		_ = c.Close()
	}()

	a := mockSocks5(t, &aHits) // prev hop
	defer a.Close()
	b := mockSocks5(t, &bHits) // this hop (must be the exit)
	defer b.Close()

	d, err := dialThroughPrev("socks5://"+a.Addr().String(), b.Addr().String(), "", "")
	if err != nil {
		t.Fatalf("dialThroughPrev: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", tgt.Addr().String())
	if err != nil {
		t.Fatalf("dial target through chain: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "HELLO" {
		t.Fatalf("payload through chain wrong: %q err=%v", buf, err)
	}
	if atomic.LoadInt32(&aHits) == 0 {
		t.Error("PREV hop was not traversed")
	}
	if atomic.LoadInt32(&bHits) == 0 {
		t.Error("THIS hop (the exit) was not traversed — the bug this fix closes")
	}
}
