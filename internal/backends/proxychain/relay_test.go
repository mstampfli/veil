package proxychain

import (
	"io"
	"net"
	"testing"
)

// TestReadConnectResponse_PreservesTunnelData: a proxy that pipelines
// tunnel bytes right after the CONNECT response must NOT lose them — the
// old single-Read code read them into a throwaway buffer and dropped them.
func TestReadConnectResponse_PreservesTunnelData(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	go func() {
		_, _ = srv.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nTUNNELHELLO"))
	}()
	if err := readConnectResponse(cli); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	buf := make([]byte, len("TUNNELHELLO"))
	if _, err := io.ReadFull(cli, buf); err != nil {
		t.Fatalf("reading tunnel data: %v", err)
	}
	if string(buf) != "TUNNELHELLO" {
		t.Errorf("tunnel data lost/corrupted: got %q want TUNNELHELLO", buf)
	}
}

// TestReadConnectResponse_SplitResponse: the response terminator arriving
// in two writes must still be framed correctly (the old prefix check could
// pass on a partial header, leaving stray bytes in the stream).
func TestReadConnectResponse_SplitResponse(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	go func() {
		_, _ = srv.Write([]byte("HTTP/1.1 200 OK\r\n"))
		_, _ = srv.Write([]byte("\r\n"))
		_, _ = srv.Write([]byte("DATA"))
	}()
	if err := readConnectResponse(cli); err != nil {
		t.Fatalf("unexpected error on split response: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(cli, buf); err != nil || string(buf) != "DATA" {
		t.Errorf("tunnel data after split header wrong: %q err=%v", buf, err)
	}
}

func TestReadConnectResponse_NonOK(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	go func() {
		_, _ = srv.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	}()
	if err := readConnectResponse(cli); err == nil {
		t.Error("expected error on non-2xx CONNECT, got nil")
	}
}
