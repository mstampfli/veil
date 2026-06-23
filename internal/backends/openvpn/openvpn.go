// Package openvpn implements an OpenVPN backend by shelling out to the
// openvpn binary. The binary must be installed on the host.
package openvpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/profile"
)

type Backend struct {
	configPath string
	tmpFile    string

	mu        sync.Mutex
	cmd       *exec.Cmd
	tunName   string
	localAddr string // tunnel address to (re)assign after the netns move, CIDR
	gateway   string // ptp peer to route through, "" for subnet topology
	stopped   chan struct{}

	logMu  sync.Mutex // guards logBuf (written by readOutput, read by Start)
	logBuf strings.Builder
}

func init() {
	backends.Register(profile.BackendOpenVPN, func(b profile.Backend) (backends.Backend, error) {
		path := b.ConfigPath
		var tmp string
		// If a pool of paths is supplied, pick one uniformly at random.
		if len(b.ConfigPaths) > 0 {
			path = b.ConfigPaths[ovpnRand(len(b.ConfigPaths))]
		}
		if path == "" {
			if b.ConfigData == "" {
				return nil, fmt.Errorf("openvpn: config required (set config_path or config_paths)")
			}
			f, err := os.CreateTemp("", "veil-ovpn-*.ovpn")
			if err != nil {
				return nil, err
			}
			if _, err := f.WriteString(b.ConfigData); err != nil {
				f.Close()
				os.Remove(f.Name())
				return nil, err
			}
			f.Close()
			path = f.Name()
			tmp = path
		}
		return &Backend{configPath: path, tmpFile: tmp}, nil
	})
}

func ovpnRand(n int) int {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	return int(v % uint64(n))
}

func (b *Backend) Kind() profile.BackendKind { return profile.BackendOpenVPN }

func (b *Backend) Start(ctx context.Context, _ *backends.Steering) (*backends.Steering, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd != nil {
		return b.steering(), nil
	}
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		return nil, fmt.Errorf("openvpn binary not found in PATH (install openvpn)")
	}

	dir := filepath.Dir(b.configPath)
	cmd := exec.Command(bin,
		"--config", b.configPath,
		"--script-security", "2",
		"--pull-filter", "ignore", "redirect-gateway",
		"--route-noexec",
	)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("openvpn start: %w", err)
	}

	b.cmd = cmd
	b.stopped = make(chan struct{})
	ready := make(chan ovpnReady, 1)
	failed := make(chan error, 1)

	go b.readOutput(stdout, ready, failed)
	go func() {
		_ = cmd.Wait()
		close(b.stopped)
	}()

	select {
	case r := <-ready:
		b.tunName = r.tun
		b.localAddr = r.localAddr
		b.gateway = r.gateway
		return b.steering(), nil
	case err := <-failed:
		_ = cmd.Process.Kill()
		return nil, err
	case <-time.After(45 * time.Second):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("openvpn timed out connecting:\n%s", b.snapshotLog())
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return nil, ctx.Err()
	}
}

// ovpnReady carries the connection facts captured from openvpn's output by
// the time it reports "Initialization Sequence Completed".
type ovpnReady struct {
	tun       string
	localAddr string // CIDR to (re)assign to the TUN, e.g. "10.9.0.2/32"
	gateway   string // ptp peer to route through, "" for subnet topology
}

var (
	ovpnPtpRe    = regexp.MustCompile(`net_addr_ptp_v4_add:\s+([0-9.]+)\s+peer\s+([0-9.]+)\s+dev`)
	ovpnSubnetRe = regexp.MustCompile(`net_addr_v4_add:\s+([0-9.]+/[0-9]+)\s+dev`)
)

// parseOvpnAddr extracts the tunnel's local address (as CIDR) and, for a
// point-to-point link, the peer/gateway from one line of openvpn output.
// Covers openvpn 2.6's net_addr_* netlink messages for both ptp (net30) and
// subnet topologies — emitted whether the address is local (--ifconfig /
// static key) or server-pushed. ok=false when the line carries no address.
//
// This is essential because the engine moves the TUN into the profile netns,
// which FLUSHES its addresses; without re-reporting them here the engine has
// nothing to re-assign and the tunnel comes up with no IP (no egress).
func parseOvpnAddr(line string) (localCIDR, gateway string, ok bool) {
	if m := ovpnPtpRe.FindStringSubmatch(line); m != nil {
		return m[1] + "/32", m[2], true
	}
	if m := ovpnSubnetRe.FindStringSubmatch(line); m != nil {
		return m[1], "", true
	}
	return "", "", false
}

func (b *Backend) readOutput(r io.Reader, ready chan<- ovpnReady, failed chan<- error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1<<14), 1<<20)
	var tunName, localAddr, gateway string
	signaled := false
	for scanner.Scan() {
		if signaled {
			// Past readiness: keep draining stdout so a full pipe can never
			// block openvpn, but stop storing lines. logBuf is only read by
			// Start's pre-ready failure paths (snapshotLog), so continuing to
			// append for the whole life of the connection would grow without
			// bound with nothing ever reading it — a slow memory leak on long
			// sessions (replay/renegotiation chatter adds up).
			continue
		}
		line := scanner.Text()
		b.appendLog(line)

		// Capture the tunnel address openvpn assigns (or is pushed) so the
		// engine can re-apply it after moving the TUN into the netns.
		if lc, gw, ok := parseOvpnAddr(line); ok {
			localAddr = lc
			if gw != "" {
				gateway = gw
			}
		}

		// Capture the TUN device name, but do NOT treat device creation as
		// readiness. openvpn opens the TUN early in the connection, before
		// the TLS handshake finishes and the data path is up. Signaling
		// ready here would make Start return while the tunnel is still dead,
		// and the engine moves the TUN into the netns and launches the app
		// immediately (engine_linux.go moveTUNToNS), so the app's first
		// connections would be blackholed until the handshake completes.
		if i := strings.Index(line, "TUN/TAP device "); i >= 0 {
			rest := strings.TrimPrefix(line[i:], "TUN/TAP device ")
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				tunName = fields[0]
			}
			continue
		}
		// The tunnel is usable only once openvpn reports the initialization
		// sequence complete — the canonical readiness marker. Signal once,
		// then keep scanning to drain stdout (a full pipe would block
		// openvpn).
		if !signaled && strings.Contains(line, "Initialization Sequence Completed") {
			select {
			case ready <- ovpnReady{tun: tunName, localAddr: localAddr, gateway: gateway}:
			default:
			}
			signaled = true
			continue
		}
		if strings.Contains(line, "AUTH_FAILED") {
			select {
			case failed <- errors.New("openvpn AUTH_FAILED"):
			default:
			}
			return
		}
	}
	// stdout closed (openvpn exited) before we ever saw the completion
	// marker: report failure so Start returns immediately instead of
	// blocking until the 45s timeout.
	if !signaled {
		select {
		case failed <- fmt.Errorf("openvpn exited before initialization completed:\n%s", b.snapshotLog()):
		default:
		}
	}
}

func (b *Backend) appendLog(line string) {
	b.logMu.Lock()
	b.logBuf.WriteString(line)
	b.logBuf.WriteByte('\n')
	b.logMu.Unlock()
}

func (b *Backend) snapshotLog() string {
	b.logMu.Lock()
	defer b.logMu.Unlock()
	return b.logBuf.String()
}

func (b *Backend) steering() *backends.Steering {
	s := &backends.Steering{
		TUNDevice: b.tunName,
		Subnet:    "0.0.0.0/0",
	}
	// Re-assign the tunnel address inside the netns: the engine's move of the
	// TUN flushes its addresses, so without this the interface has no IP and
	// nothing egresses. We deliberately leave Gateway empty so the engine
	// installs a gateway-less "default dev <tun>" route (same as WireGuard):
	// the TUN address is a /32, so the ptp peer is not on-link and a
	// "default via <peer>" route would fail with "network is unreachable".
	// For a point-to-point TUN the device route is what actually works.
	if b.localAddr != "" {
		s.Addresses = []string{b.localAddr}
	}
	return s
}

func (b *Backend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd == nil || b.cmd.Process == nil {
		return nil
	}
	_ = b.cmd.Process.Signal(os.Interrupt)
	select {
	case <-b.stopped:
	case <-time.After(3 * time.Second):
		_ = b.cmd.Process.Kill()
	}
	b.cmd = nil
	if b.tmpFile != "" {
		_ = os.Remove(b.tmpFile)
	}
	return nil
}

func (b *Backend) Status() string {
	if b.cmd == nil {
		return "openvpn stopped"
	}
	return fmt.Sprintf("openvpn up on %s", b.tunName)
}

// TUNName returns the TUN device name for stats lookup.
func (b *Backend) TUNName() string { return b.tunName }

// Endpoints parses `remote <host> <port>` lines out of the .ovpn
// config so the GUI can geo-locate the server.
func (b *Backend) Endpoints() []string {
	data, err := os.ReadFile(b.configPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "remote ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			out = append(out, fields[1]+":"+fields[2])
		} else if len(fields) == 2 {
			out = append(out, fields[1])
		}
	}
	return out
}
