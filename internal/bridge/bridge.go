// Package bridge is the client-side wrapper around the cmd/veil-bridge
// helper binary.
//
// In the user-ns engine model, the engine itself runs inside an
// unprivileged user namespace and so cannot create a veth pair where
// one end attaches to the host's network device — that requires
// CAP_NET_ADMIN on the host. cmd/veil-bridge holds that capability
// via `setcap cap_net_admin+ep` and does only that one thing. This
// package is what calls into it.
//
// Caller scope:
//   - The Veil GUI/CLI parent process (user uid, no caps) is the
//     ONLY caller of this package. It exec's veil-bridge — which
//     gets its file caps applied at kernel exec time, since the
//     parent is on the host (not inside a user-ns).
//   - The engine child running inside a user-ns CANNOT exec
//     veil-bridge with effective caps; it must instead send requests
//     up to its parent over IPC, and the parent uses this package.
//
// We invoke `veil-bridge` once per operation (no daemon). Each call
// is short-lived and produces one JSON line on stdout for success.

package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrHelperMissing is returned when the veil-bridge binary cannot be
// located on PATH or at the configured override. Surface it to the
// user as "install veil package or run `setup --install-helpers`".
var ErrHelperMissing = errors.New("veil-bridge: helper binary not found")

// ErrHelperNoCaps is returned when veil-bridge runs but reports it
// lacks CAP_NET_ADMIN (via the `doctor` subcommand). Surface as
// "run: sudo setcap cap_net_admin+ep <path>".
var ErrHelperNoCaps = errors.New("veil-bridge: helper present but missing CAP_NET_ADMIN")

// HelperPathEnv overrides automatic discovery of the binary; useful
// for development where veil-bridge isn't on PATH.
const HelperPathEnv = "VEIL_BRIDGE"

// bridgeSearchPaths are the fixed install locations checked after
// $VEIL_BRIDGE and PATH. A package var (not an inline literal) so tests
// can override it to stay hermetic regardless of what is installed on the
// build machine.
var bridgeSearchPaths = []string{
	"/usr/local/libexec/veil-bridge",
	"/usr/libexec/veil-bridge",
}

// Locate finds the veil-bridge binary. Search order:
//  1. $VEIL_BRIDGE
//  2. PATH
//  3. /usr/local/libexec/veil-bridge
//  4. /usr/libexec/veil-bridge
//  5. ./veil-bridge alongside the main binary
func Locate() (string, error) {
	if p := os.Getenv(HelperPathEnv); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("veil-bridge"); err == nil {
		return p, nil
	}
	for _, p := range bridgeSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		alt := filepath.Join(filepath.Dir(exe), "veil-bridge")
		if _, err := os.Stat(alt); err == nil {
			return alt, nil
		}
	}
	return "", ErrHelperMissing
}

// DoctorReport mirrors what `veil-bridge doctor` prints.
type DoctorReport struct {
	Binary   string   `json:"binary"`
	EUID     int      `json:"euid"`
	HasCaps  bool     `json:"has_caps"`
	VeilDevs []string `json:"veil_devs"`
}

// Doctor runs the helper's self-test and returns its report. Returns
// ErrHelperMissing or ErrHelperNoCaps with a wrapped underlying error
// when the helper is unusable.
func Doctor() (*DoctorReport, error) {
	path, err := Locate()
	if err != nil {
		return nil, err
	}
	out, err := runHelper(path, []string{"doctor"})
	if err != nil && !strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		return nil, err
	}
	var rep DoctorReport
	if jerr := json.Unmarshal(out, &rep); jerr != nil {
		return nil, fmt.Errorf("doctor: parse: %w (raw: %q)", jerr, string(out))
	}
	if !rep.HasCaps {
		return &rep, fmt.Errorf("%w: %s", ErrHelperNoCaps, rep.Binary)
	}
	return &rep, nil
}

// CreateVethSpec is a single create-veth request.
type CreateVethSpec struct {
	Profile  string
	HostCIDR string // e.g. "10.13.0.1/30"
	NSCIDR   string // e.g. "10.13.0.2/30"
	NSPID    int    // pid whose /proc/<pid>/ns/net to attach the peer to
}

// CreateVethResult is the bridge's reply.
type CreateVethResult struct {
	Profile     string `json:"profile"`
	HostDev     string `json:"host_dev"`
	PeerDev     string `json:"peer_dev"`
	HostAddress string `json:"host_address"`
	NSPID       int    `json:"ns_pid"`
}

// CreateVeth invokes veil-bridge create-veth. Caller is responsible
// for picking a unique profile name (the bridge derives device names
// deterministically from it).
func CreateVeth(spec CreateVethSpec) (*CreateVethResult, error) {
	path, err := Locate()
	if err != nil {
		return nil, err
	}
	args := []string{
		"create-veth",
		"--profile", spec.Profile,
		"--host-cidr", spec.HostCIDR,
		"--ns-cidr", spec.NSCIDR,
		"--ns-pid", strconv.Itoa(spec.NSPID),
	}
	out, err := runHelper(path, args)
	if err != nil {
		return nil, err
	}
	var r CreateVethResult
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("create-veth: parse: %w", err)
	}
	return &r, nil
}

// RemoveVeth tears down the host-side veth. Idempotent.
func RemoveVeth(profile string) error {
	path, err := Locate()
	if err != nil {
		return err
	}
	_, err = runHelper(path, []string{"remove-veth", "--profile", profile})
	return err
}

// AddNAT installs the FORWARD ACCEPT pair + POSTROUTING MASQUERADE
// for the given private subnet egressing via iface.
func AddNAT(subnetCIDR, iface string) error {
	path, err := Locate()
	if err != nil {
		return err
	}
	_, err = runHelper(path, []string{
		"add-nat",
		"--subnet", subnetCIDR,
		"--iface", iface,
	})
	return err
}

// RemoveNAT removes what AddNAT added. Idempotent.
func RemoveNAT(subnetCIDR, iface string) error {
	path, err := Locate()
	if err != nil {
		return err
	}
	_, err = runHelper(path, []string{
		"remove-nat",
		"--subnet", subnetCIDR,
		"--iface", iface,
	})
	return err
}

// runHelper executes the helper, captures stdout (success payload)
// and stderr (which the helper prints JSON errors to on failure),
// and returns stdout bytes. Distinguishes "binary not found" /
// "exec failed" / "helper exited with error" so the caller can give
// a clear remediation message.
func runHelper(path string, args []string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, parseHelperError(err, stderr.Bytes(), args)
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

// parseHelperError tries to extract the JSON error message the helper
// prints to stderr; falls back to the raw stderr when not JSON.
func parseHelperError(runErr error, stderr []byte, args []string) error {
	stderr = bytes.TrimSpace(stderr)
	if len(stderr) > 0 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(stderr, &e) == nil && e.Error != "" {
			return fmt.Errorf("veil-bridge %s: %s", args[0], e.Error)
		}
		return fmt.Errorf("veil-bridge %s: %s (run err: %w)", args[0], string(stderr), runErr)
	}
	return fmt.Errorf("veil-bridge %s: %w", args[0], runErr)
}
