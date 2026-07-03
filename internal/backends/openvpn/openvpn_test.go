package openvpn

import (
	"strings"
	"testing"
	"time"
)

// runReadOutput drives readOutput against a canned openvpn log and returns
// what (if anything) it signaled. readOutput runs to EOF on the string
// reader, so exactly one of ready/failed is produced per the new contract.
func runReadOutput(t *testing.T, log string) (gotReady bool, name string, gotFailed bool, ferr error) {
	t.Helper()
	b := &Backend{}
	ready := make(chan ovpnReady, 1)
	failed := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		b.readOutput(strings.NewReader(log), ready, failed)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("readOutput did not return")
	}
	select {
	case r := <-ready:
		gotReady = true
		name = r.tun
	default:
	}
	select {
	case ferr = <-failed:
		gotFailed = true
	default:
	}
	return
}

// TestReadOutput_DeviceOpenIsNotReady: the "TUN/TAP device opened" line
// must NOT make Start return ready — the tunnel is not up yet. Before the
// fix this signaled ready prematurely, launching the app mid-handshake.
func TestReadOutput_DeviceOpenIsNotReady(t *testing.T) {
	log := strings.Join([]string{
		"TLS: Initial packet from [AF_INET]1.2.3.4:1194",
		"VERIFY OK: depth=0",
		"TUN/TAP device tun0 opened",
		"do_ifconfig, tt->did_ifconfig_ipv6_setup=0",
		// no "Initialization Sequence Completed" -> openvpn died handshaking
	}, "\n")
	gotReady, _, gotFailed, ferr := runReadOutput(t, log)
	if gotReady {
		t.Fatal("readOutput signaled ready on TUN-device-open alone (premature ready bug)")
	}
	if !gotFailed {
		t.Fatal("readOutput should report failure when openvpn exits before init completes")
	}
	if ferr == nil || !strings.Contains(ferr.Error(), "before initialization completed") {
		t.Fatalf("unexpected failure error: %v", ferr)
	}
}

// TestReadOutput_InitCompletedSignalsReady: ready fires only on the
// canonical completion marker, carrying the TUN name captured earlier.
func TestReadOutput_InitCompletedSignalsReady(t *testing.T) {
	log := strings.Join([]string{
		"TUN/TAP device tun7 opened",
		"GID set to nogroup",
		"Initialization Sequence Completed",
		"some later chatter that must be drained",
	}, "\n")
	gotReady, name, gotFailed, ferr := runReadOutput(t, log)
	if !gotReady {
		t.Fatal("readOutput did not signal ready after Initialization Sequence Completed")
	}
	if name != "tun7" {
		t.Errorf("ready carried wrong TUN name: got %q want tun7", name)
	}
	if gotFailed {
		t.Errorf("readOutput also signaled failure after a successful init: %v", ferr)
	}
}

// TestReadOutput_AuthFailed: an AUTH_FAILED line must surface as an error,
// never as ready.
func TestReadOutput_AuthFailed(t *testing.T) {
	log := strings.Join([]string{
		"TUN/TAP device tun0 opened",
		"AUTH: Received control message: AUTH_FAILED",
	}, "\n")
	gotReady, _, gotFailed, ferr := runReadOutput(t, log)
	if gotReady {
		t.Fatal("readOutput signaled ready despite AUTH_FAILED")
	}
	if !gotFailed || ferr == nil || !strings.Contains(ferr.Error(), "AUTH_FAILED") {
		t.Fatalf("expected AUTH_FAILED error, got ready=%v err=%v", gotReady, ferr)
	}
}
