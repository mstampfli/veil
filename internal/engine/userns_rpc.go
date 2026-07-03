package engine

// User-ns engine RPC protocol.
//
// One Veil profile session = one user-ns child process. The parent
// (unprivileged veil-gui / veil binary) holds an open Unix socket
// to each child and uses it to invoke Engine methods inside the
// namespace. The child side runs an in-process linuxEngine and
// dispatches each request to it.
//
// Wire format: one JSON object per line. Synchronous request/reply.
// One outstanding call at a time per child — sessions are
// single-threaded from the GUI's perspective anyway. Any method
// that doesn't fit (background watchdogs, async health probes) is
// already structured around explicit calls so this is fine.

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mstampfli/veil/internal/profile"
)

// rpcRequest / rpcResponse are the on-the-wire frames.
type rpcRequest struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Method names — used on both sides. Keep these as constants so a
// typo in either parent or child fails fast at compile time.
const (
	mUp               = "Up"
	mLaunch           = "Launch"
	mDown             = "Down"
	mExternalIP       = "ExternalIP"
	mExternalIPInfo   = "ExternalIPInfo"
	mTrafficStats     = "TrafficStats"
	mProbeLeaks       = "ProbeLeaks"
	mBrowserProbeIP   = "BrowserProbeIP"
	mTorNewCircuit    = "TorNewCircuit"
	mTorControlInfo   = "TorControlInfo"
	mTorCircuitStatus = "TorCircuitStatus"
	mTorRelayIP       = "TorRelayIP"

	// Lifecycle: parent tells child to set up its net-ns before Up
	// (peer device name, addresses, default route to host).
	mConfigureNetwork = "ConfigureNetwork"

	// Lifecycle: parent asks child to exit cleanly. Child runs any
	// final cleanup the linuxEngine didn't already do, then exits.
	mShutdown = "Shutdown"
)

// configureNetworkParams is sent over mConfigureNetwork BEFORE Up.
// The bridge has already moved the peer veth into the child's
// net-ns; the child just needs to address it and add the default
// route. We do this from the child rather than the bridge because
// these operations need to happen INSIDE the child's net-ns, where
// the bridge can't easily reach without yet another netns dance.
type configureNetworkParams struct {
	PeerDevice  string `json:"peer_device"`
	NSAddress   string `json:"ns_address"`   // e.g. "10.250.13.2/30"
	HostGateway string `json:"host_gateway"` // e.g. "10.250.13.1"
	// Pasta is true on the zero-capability path: the uplink interface
	// (PeerDevice, "veil0") is configured by pasta asynchronously, so the
	// child only waits for it to come up rather than addressing it itself.
	Pasta bool `json:"pasta,omitempty"`
}

// upParams carries the full profile to the child for its
// linuxEngine.Up call.
type upParams struct {
	Profile *profile.Profile `json:"profile"`
}

// launchResult / downParams etc. are kept thin — the child re-derives
// everything it needs from its own state.

// readFrame reads one JSON-line frame from r. Used by both sides.
func readFrame(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// writeFrame writes one JSON-line frame to w followed by a newline.
func writeFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

// rpcError formats an rpcResponse with a stringified error.
func rpcError(id uint64, err error) rpcResponse {
	return rpcResponse{ID: id, Error: err.Error()}
}

// rpcOK builds an rpcResponse with the given JSON-encodable result.
func rpcOK(id uint64, v any) rpcResponse {
	if v == nil {
		return rpcResponse{ID: id, Result: json.RawMessage("null")}
	}
	data, err := json.Marshal(v)
	if err != nil {
		return rpcError(id, fmt.Errorf("marshal result: %w", err))
	}
	return rpcResponse{ID: id, Result: data}
}
