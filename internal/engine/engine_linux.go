//go:build linux

package engine

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mstampfli/veil/internal/audit"
	"github.com/mstampfli/veil/internal/inputjitter"
	"github.com/mstampfli/veil/internal/tcpfp"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/backends/tlsmitm"
	"github.com/mstampfli/veil/internal/backends/tor"
	"github.com/mstampfli/veil/internal/chain"
	"github.com/mstampfli/veil/internal/dohproxy"
	"github.com/mstampfli/veil/internal/launcher"
	personaextension "github.com/mstampfli/veil/internal/launcher/persona-extension"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/persona"
	"github.com/mstampfli/veil/internal/profile"
)

// active returns the Linux engine.
func active() Engine { return &linuxEngine{} }

type linuxEngine struct {
	mu       sync.Mutex
	subnets  map[string]netip.Prefix // profile -> /30 used
	nextLast byte                    // last octet seed

	// pastaHostLoopback is the address at which the HOST's loopback is
	// reachable from inside the profile netns when running under the pasta
	// uplink (pasta maps host 127.0.0.1 to its gateway, a different subnet
	// than the inner profile veth). Empty on the bridge/legacy path. Set
	// once by the user-ns child from ConfigureNetwork before Up; read in Up
	// to annotate the backend context. Single child / single profile /
	// sequential RPCs, so no extra locking needed.
	pastaHostLoopback string
}

type linuxState struct {
	netns        netns.NsHandle
	netnsName    string
	veth, peer   string
	hostIP       netip.Addr
	nsIP         netip.Addr
	subnet       netip.Prefix
	pids         []int
	resolvFile   string
	tunDevices   []string  // TUN/Wintun devices attached to this session
	hostRules    [][]string // iptables rules added on the host (for rollback)
	wanIface     string    // the WAN interface used for MASQUERADE
	jitter       inputjitter.Jitter // keyboard jitter daemon (nil if off)
	mouseJitter  inputjitter.Jitter // mouse jitter daemon (nil if off)
	cdpPort      int                // Chromium-family --remote-debugging-port; 0 if not a Chromium preset or not yet started
	cdpWSURL     string             // browser-level WebSocket URL parsed from stderr ("DevTools listening on ws://...")
	cdpReady     chan struct{}      // closed when cdpWSURL is populated
	marionettePort int              // Firefox --marionette port; 0 if not a Firefox preset
	personaProbe *personaProbeServer // listens for the extension's load-confirmation POST
	cleanupExtra []func() error
	dnsProxyCancel context.CancelFunc // cancels the in-process DoH proxy goroutine when dns_proxy is on (nil otherwise)
	dnsProxyPort   int                // port the in-netns DoH proxy bound to
}

const (
	veilSubnetBase = "10.200." // 10.200.X.0/30 per profile
	wanRouteMark   = "veil"
)

func (e *linuxEngine) Up(ctx context.Context, p *profile.Profile) (sess *Session, retErr error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("veil engine on Linux needs root (try sudo)")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := gateLicense(p); err != nil {
		return nil, err
	}
	// Default DataDir — needs to happen BEFORE the strict-tier tls_mitm
	// CA install (which writes the per-profile CA into <DataDir>) that
	// runs further down in this function. Two cases need an on-disk
	// home: (a) browser presets store their browser profile there, and
	// (b) ANY chain with a tls_mitm hop needs it for the CA root, even
	// for a non-browser app (e.g. curl) — otherwise EnsureInstalled-
	// ForProfile fails with "dataDir required" and the launch aborts.
	// Pick a HOME-rooted path (we are the user regardless of the euid
	// value inside a user-ns).
	if p.DataDir == "" && (launcher.IsBrowserPreset(p.App.Preset) || chainHasTLSMITM(p.Chain)) {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			if u, err := osuser.Current(); err == nil {
				homeDir = u.HomeDir
			}
		}
		if homeDir != "" {
			leaf := p.App.Preset
			if leaf == "" {
				leaf = "app"
			}
			p.DataDir = filepath.Join(homeDir, ".local", "share", "veil", "data", p.Name, leaf)
			// Browser presets bake the DataDir into their --user-data-dir
			// / --profile args, so rebuild them. Non-browser apps don't
			// reference DataDir in their args — leave those untouched.
			if launcher.IsBrowserPreset(p.App.Preset) {
				p.App.Args = nil
				if err := launcher.Resolve(p); err != nil {
					return nil, fmt.Errorf("re-resolve preset after DataDir default: %w", err)
				}
			}
		}
	}

	// Auto-derive TCP stack persona from the loaded browser persona's
	// OS when the user didn't explicitly pick one. Eliminates a class
	// of inconsistency where the JS layer claims Windows but the TCP
	// stack still looks like Linux.
	if p.TCPPersona == "" && (p.Persona != "" || p.ForgePersona) {
		if derived := deriveTCPFromPersona(p); derived != "" {
			p.TCPPersona = derived
			logger.L().Info("tcp persona auto-derived from browser persona",
				"profile", p.Name, "tcp_persona", derived)
		}
	}
	// Override the auto-inserted tls_mitm hop's fingerprint from the
	// persona's User-Agent. profile.pickTLSFingerprint can't see the
	// loaded persona (import cycle) so it picks from App.Preset only.
	// Without this override, an iPhone-Safari persona running in Brave
	// would TLS-handshake as Chrome while JS/headers claim Safari.
	if p.Persona != "" || p.ForgePersona {
		if fp := deriveTLSFingerprintFromPersona(p); fp != "" {
			for i := range p.Chain {
				h := &p.Chain[i]
				if h.Kind == profile.BackendTLSMITM && h.TLSFingerprint != fp {
					logger.L().Info("tls_mitm fingerprint overridden from persona UA",
						"profile", p.Name,
						"old", h.TLSFingerprint, "new", fp)
					h.TLSFingerprint = fp
				}
			}
		}
	}
	// Auto-derive TCP persona for AntiFingerprint mode based on what
	// the BROWSER will claim at the JS layer. The goal is coherence
	// AND not leaking host-specific kernel tuning (window sizes,
	// option ordering, custom sysctl knobs that might fingerprint
	// the user's specific Linux install).
	//
	//   * Firefox / Thunderbird with privacy.resistFingerprinting=true
	//     rewrites navigator.{userAgent,platform,oscpu,appVersion} all
	//     to Windows-shape. So we set TCP=windows to match. End-to-end
	//     coherent Windows claim.
	//
	//   * Chromium-family (Brave, Chromium, Edge) WITHOUT our fork has
	//     no way to override navigator.platform — it always reveals
	//     "Linux x86_64" on a Linux host. We set TCP=linux to NORMALIZE
	//     to a vanilla Linux 6.x signature: removes host-specific
	//     kernel quirks AND adds per-profile TSOffset so each profile's
	//     timestamp counter is independent (breaks cross-profile
	//     correlation via shared monotonic clock inheritance).
	//
	//     This gives "every Veil-AntiFingerprint user looks like the
	//     same vanilla Linux box" — shared cohort = anonymous in it,
	//     while still being coherent with navigator.platform=Linux.
	if p.TCPPersona == "" && p.AntiFingerprint.IsOn() {
		switch p.App.Preset {
		case "firefox", "thunderbird":
			p.TCPPersona = "windows"
			logger.L().Info("tcp persona auto-set for anti_fingerprint+firefox cohort",
				"profile", p.Name, "tcp_persona", "windows",
				"reason", "Firefox RFP claims Windows at JS layer; matching L4")
		default:
			// Chromium-family / other: normalize to vanilla Linux at
			// L4. NOT same as "no rewrite" — the rewrite removes any
			// host-kernel-tuning quirks that could fingerprint this
			// specific machine, and adds per-profile timestamp offset
			// for cross-profile decorrelation.
			p.TCPPersona = "linux"
			logger.L().Info("tcp persona normalized for anti_fingerprint+chromium cohort",
				"profile", p.Name, "tcp_persona", "linux",
				"reason", "matches navigator.platform=Linux; strips host kernel tuning; per-profile TS offset breaks correlation")
		}
	}
	// Apply chain randomizer (mandatory/optional + reroll on each launch).
	if p.RandomizeChain {
		original := p.Chain
		p.Chain = chain.Randomize(original)
		logger.L().Info("chain randomized",
			"profile", p.Name,
			"from", len(original), "to", len(p.Chain))
	}

	logger.L().Info("engine.Up", "profile", p.Name, "chain_len", len(p.Chain))

	// If the chain includes tls_mitm (auto-inserted when
	// AntiFingerprint=true, or manually added by the user), make sure
	// the Veil CA is installed in the system trust store + user NSS
	// DB BEFORE the browser starts. Otherwise the substituted certs
	// from tlsmitm fail validation and every page errors. Idempotent:
	// repeat launches re-run the install but it's a no-op when
	// already installed.
	caInstalled := false
	for _, b := range p.Chain {
		if b.Kind != profile.BackendTLSMITM {
			continue
		}
		// HARD FAIL. If the CA install can't be done, every TLS
		// connection through tls_mitm will fail validation in the
		// browser → user thinks anti_fingerprint:strict is in
		// effect but actually nothing loads. Refuse to launch.
		if !caInstalled {
			if err := tlsmitm.EnsureInstalledForProfile(p.DataDir); err != nil {
				return nil, fmt.Errorf("tls_mitm: per-profile CA install failed (anti_fingerprint:strict cannot be enforced): %w", err)
			}
			caInstalled = true
		}
		// HARD FAIL, pre-egress. Prove the uTLS rewrite actually emits a
		// browser-shaped ClientHello (not Go's stdlib fingerprint) BEFORE
		// any app traffic flows. Without this, a broken/inactive uTLS
		// path would silently leak a detectable non-browser fingerprint
		// while the user believes anti-fingerprinting is enforced.
		if err := tlsmitm.SelfCheck(b.TLSFingerprint); err != nil {
			return nil, fmt.Errorf("tls_mitm: %w", err)
		}
	}

	st := &linuxState{netnsName: "veil-" + p.Name}
	sess = &Session{Profile: p, State: st}

	// Defensive: clean any leftover state for this profile name from
	// a previous crashed run before we start.
	cleanupOrphan(st.netnsName)

	// Single deferred teardown — runs on ANY error (or panic) before
	// success. Without this, a half-built netns from a failed Up gets
	// left around and the next attempt sometimes builds on top, with
	// inconsistent error messages ("no default route", "device busy",
	// etc.) depending on which step the prior attempt got stuck at.
	// Now: error in Up = full rollback, deterministic state for the
	// next attempt.
	subnetAllocated := false
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("engine.Up panic: %v", r)
		}
		if retErr == nil {
			return
		}
		logger.L().Warn("engine.Up failed; rolling back partial state",
			"profile", p.Name, "err", retErr)
		// IMPORTANT: sess here is the named return value. On
		// `return nil, err` paths the caller's nil clobbers our
		// local pointer before this defer runs, so we MUST
		// nil-check before dereferencing or the rollback itself
		// panics. (Symptom: "child panic in Up: nil pointer
		// dereference" hides the real Up failure.)
		if sess != nil {
			// Stop any backends that were started, in reverse order.
			for i := len(sess.Backends) - 1; i >= 0; i-- {
				done := make(chan struct{}, 1)
				b := sess.Backends[i]
				go func() {
					_ = b.Stop()
					done <- struct{}{}
				}()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					logger.L().Warn("rollback: backend stop timed out", "kind", b.Kind())
				}
			}
			sess.Backends = nil
		}
		_ = e.cleanup(st)
		if subnetAllocated {
			e.freeSubnet(p.Name)
		}
		sess = nil
	}()

	subnet, err := e.allocSubnet(p.Name)
	if err != nil {
		return nil, err
	}
	subnetAllocated = true
	st.subnet = subnet
	addrs := subnetAddrs(subnet)
	st.hostIP = addrs[0]
	st.nsIP = addrs[1]

	if err := e.createNamespace(st); err != nil {
		return nil, err
	}
	if err := e.createVethPair(st); err != nil {
		return nil, err
	}
	if err := e.configureForwarding(st); err != nil {
		return nil, err
	}
	if err := e.writeResolvConf(st, p.DNS); err != nil {
		return nil, err
	}
	// Per-namespace ephemeral port range carving so two profiles don't
	// share the kernel's global ephemeral pool. Each profile allocates
	// from a disjoint slice of [10000, 60000].
	// HARD FAIL: per-namespace ephemeral port range. Without this,
	// two profiles share the kernel's global ephemeral pool and an
	// observer can correlate sessions by source-port distribution.
	if err := installPortRange(st); err != nil {
		return nil, fmt.Errorf("port range carving failed (cross-profile correlation by source-port would be possible): %w", err)
	}

	// HARD FAIL: pre-flight check /dev/net/tun. Backends like
	// wireguard-go open it; failing late produces an opaque "create
	// tun: permission denied". Detect it here with a remediation
	// message naming the exact fix.
	if needsTun := chainNeedsTUN(p); needsTun {
		if err := preflightTUN(); err != nil {
			return nil, err
		}
	}
	// Match TCP congestion control to the persona (modern OSes all use
	// cubic, so this is mostly already correct, but explicit is safer).
	if p.TCPPersona != "" {
		_ = exec.Command("ip", "netns", "exec", st.netnsName,
			"sysctl", "-w", "net.ipv4.tcp_congestion_control=cubic").Run()
	}

	// Resolve the persona NOW, before the chain comes up, and drop
	// the WebExtension files (including persona.json) into the
	// profile data dir. tls_mitm reads <DataDir>/veil-persona-extension/
	// persona.json at Backend.Start so it can rewrite Sec-Ch-Ua-* on
	// the wire. If we leave persona resolution for Launch (after chain
	// bring-up), tls_mitm starts with the PREVIOUS launch's stale
	// persona.json — UA on the wire stays Linux/Chrome even when the
	// user re-rolled to a Windows/Firefox persona, etc.
	//
	// The Launch path resolves the persona AGAIN and writes
	// user.js / Chromium args / extension files. Idempotent — the
	// second write produces identical bytes. The double work is
	// trivial vs. the staleness bug it prevents.
	if p.Persona != "" || p.ForgePersona {
		writePersonaExtensionEarly(p)
	}

	// Bring up backends in order. Each backend that returns a TUN device
	// must be moved into the namespace and routed.
	//
	// On any failure mid-chain we stop every backend that's already up,
	// in reverse order, before tearing the namespace down — otherwise a
	// failed Tor-after-WG launch would leak a wireguard-go process.
	bctx := backends.WithNamespace(ctx, st.netnsName)
	bctx = backends.WithHostGateway(bctx, st.hostIP.String())
	if e.pastaHostLoopback != "" {
		// Pasta uplink: host loopback lives at pasta's gateway, not the
		// inner veth gateway. Backends that rewrite "localhost" use this.
		bctx = backends.WithHostLoopback(bctx, e.pastaHostLoopback)
	}
	bctx = backends.WithProfileDataDir(bctx, p.DataDir)
	var prev *backends.Steering
	for _, b := range p.Chain {
		impl, err := backends.New(b)
		if err != nil {
			return nil, err
		}
		s, err := impl.Start(bctx, prev)
		if err != nil {
			_ = impl.Stop()
			return nil, fmt.Errorf("backend %s: %w", b.Kind, err)
		}
		// Track it before any subsequent step that could fail, so the
		// deferred rollback can Stop it.
		sess.Backends = append(sess.Backends, impl)
		if s.TUNDevice != "" {
			if err := e.moveTUNToNS(st, s); err != nil {
				return nil, fmt.Errorf("attach %s: %w", s.TUNDevice, err)
			}
			st.tunDevices = append(st.tunDevices, s.TUNDevice)
		}
		// If a backend supplies new DNS servers (e.g. transparent Tor
		// pointing /etc/resolv.conf at 127.0.0.1), refresh the per-ns
		// resolv.conf. HARD FAIL: a stale resolv.conf points the
		// launched app at the wrong resolver — best case slow lookups,
		// worst case DNS leak via the previous (now-tunneled-through)
		// resolver.
		if len(s.DNS) > 0 {
			if err := e.writeResolvConf(st, s.DNS); err != nil {
				return nil, fmt.Errorf("update resolv.conf for backend DNS %v failed (DNS would leak via stale resolver): %w", s.DNS, err)
			}
		}
		prev = s
	}
	sess.Final = prev

	// Tor country pin (phase 2). Bootstrap is done across every
	// chain hop, so the Tor control port is now live INSIDE the
	// netns. We can't dial it from this goroutine without
	// runInNetns — which is exactly why putting SETCONF in
	// Backend.Start (where it ran from the engine's loopback) was
	// silently failing. Apply ExitNodes + StrictNodes here, then
	// NEWNYM to drop any pre-pin circuits.
	//
	// HARD FAIL when a country was requested but the pin couldn't be
	// applied. Continuing would leave Tor exiting to a random country
	// despite the user explicitly asking for a country lock — the
	// exact silent-leak failure mode this whole gate exists to
	// prevent. No country requested = no error path here.
	if err := e.applyTorCountryPin(sess, st); err != nil {
		return nil, fmt.Errorf("tor country pin: %w (refusing to launch with unconstrained exit country)", err)
	}

	// Optional in-netns DoH proxy. Catches every UDP/53 and TCP/53
	// in the namespace — browser primary, OCSP, captive portal,
	// cert validation, anything — and forwards as DoH to the
	// configured upstream. Without this, side queries leak through
	// Tor's DNSPort to the exit relay's upstream resolver (whatever
	// the operator picked). With it, every DNS query in the netns
	// gets DoH-encrypted to the same provider.
	if p.DNSProxy {
		if err := e.installDNSProxy(sess, st); err != nil {
			return nil, fmt.Errorf("dns_proxy: %w", err)
		}
	}

	// DNS probe — confirms the per-namespace resolver actually
	// answers. HARD FAIL on failure: as the original comment said,
	// "launched apps would silently fall back to host resolver =
	// leak". That's not a "proceed with warning" situation; that's
	// the leak we explicitly built the netns to prevent.
	if err := e.verifyDNS(st); err != nil {
		return nil, fmt.Errorf("DNS probe failed: %w (configured resolver unreachable; launched apps would fall back to host resolver and leak)", err)
	}

	if p.KillSwitch {
		if err := e.installKillSwitch(st); err != nil {
			return nil, fmt.Errorf("kill switch: %w", err)
		}
	}

	// Drop UDP/443 (QUIC) outbound from the netns, regardless of
	// kill_switch. Reasoning:
	//   - We don't have a QUIC MITM yet, so HTTP/3 would bypass our
	//     tls_mitm + H1/H2 mediator entirely → site sees real TLS +
	//     real Sec-Ch-Ua-* and persona is broken.
	//   - --disable-quic in the browser is one signal but rejecting
	//     UDP/443 at network level is the more authentic pattern: real
	//     users on QUIC-blocking networks (corporate wifi, restrictive
	//     ISPs) see exactly this — the browser tries QUIC once, gets
	//     ICMP-unreachable, marks the network as QUIC-broken, never
	//     retries on this network. Persona-coherent.
	if err := e.dropQUICOutbound(st); err != nil {
		return nil, fmt.Errorf("drop UDP/443: %w", err)
	}

	// Behavioral jitter: intercept keyboard events with random timing
	// offsets to defeat keystroke-dynamics fingerprinting. HARD FAIL
	// if requested but unavailable — silently launching without
	// jitter would leave the user thinking they're protected when
	// the keystroke timing fingerprint is fully exposed.
	if p.BehavioralJitter {
		j, err := inputjitter.Start(inputjitter.DefaultOptions())
		if err != nil {
			return nil, fmt.Errorf("behavioral_jitter requested but failed to start (cannot enforce keystroke-dynamics defense): %w (run: sudo veil setup --install-helpers, then re-login so the veil group is active for /dev/uinput access)", err)
		}
		st.jitter = j
		logger.L().Info("behavioral jitter armed",
			"profile", p.Name,
			"note", "ALL host keyboard input is jittered while this profile runs")
	}

	// Mouse jitter: ±1 px on a fraction of position deltas + small
	// timing jitter. Same fail-hard policy.
	if p.MouseJitter {
		opts := inputjitter.DefaultOptions()
		// Small per-event timing jitter (0-3ms), applied ONLY when the
		// stream is caught up — the mouse loop skips the delay whenever
		// another event is already queued, so fast movement (up to
		// ~1000Hz) never backlogs and the cursor stays responsive. The
		// +/-1px position noise (the real curvature defense) always
		// applies. Net: a touch of timing jitter on slow moves, no lag
		// under load.
		opts.MinDelay = 0
		opts.MaxDelay = 3 * time.Millisecond
		mj, err := inputjitter.StartMouse(opts)
		if err != nil {
			return nil, fmt.Errorf("mouse_jitter requested but failed to start (cannot enforce mouse-curvature/timing defense): %w (run: sudo veil setup --install-helpers, then re-login so the veil group is active for /dev/uinput access)", err)
		}
		st.mouseJitter = mj
		logger.L().Info("mouse jitter armed",
			"profile", p.Name,
			"note", "ALL host mouse input is jittered while this profile runs")
	}

	// TCP stack normalization (TTL + MSS via iptables, options + WS via
	// NFQUEUE userspace rewriter) so passive OS fingerprinting sees the
	// persona we want, not Linux.
	if p.TCPPersona != "" {
		chosen := p.TCPPersona
		if chosen == "random" {
			chosen = randomTCPPersona()
			logger.L().Info("tcp persona: random pick", "profile", p.Name, "chosen", chosen)
		}
		// HARD FAIL: if the user picked a TCP persona but we can't
		// install the iptables MSS clamp + NFQUEUE rewrite, the
		// browser leaks the host's real TCP stack fingerprint.
		// That's exactly the leak anti_fingerprint is supposed to
		// close.
		if err := installTCPPersona(st.netnsName, chosen); err != nil {
			return nil, fmt.Errorf("tcp_persona=%q requested but iptables persona setup failed (TCP fingerprint would leak): %w", chosen, err)
		}
		logger.L().Info("tcp persona iptables applied", "ns", st.netnsName, "persona", chosen)
		if err := installTCPRewriter(st, chosen); err != nil {
			return nil, fmt.Errorf("tcp_persona=%q requested but NFQUEUE rewriter setup failed (TCP option order / window scale would leak): %w", chosen, err)
		}
	}
	return sess, nil
}

// hasUnshareTime reports whether the host's `unshare` binary supports
// the --time flag (Linux 5.6+, util-linux 2.36+).
func hasUnshareTime() bool {
	out, err := exec.Command("unshare", "--help").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "--time")
}

// randomTimeOffset returns a random number of seconds in the range
// [-31536000, 31536000] (±1 year) so per-profile clock offsets fall
// within plausible "this device booted some time in the last year".
func randomTimeOffset() int64 {
	var b [8]byte
	_, _ = cryptorand.Read(b[:])
	v := int64(0)
	for i := 0; i < 8; i++ {
		v = v<<8 | int64(b[i])
	}
	if v < 0 {
		v = -v
	}
	return v % (365 * 24 * 60 * 60)
}

// randomTCPPersona picks one of the supported OS personas using
// crypto/rand so observers can't predict which Veil profiles will pick
// which OS in advance.
func randomTCPPersona() string {
	options := []string{"windows", "macos", "linux", "ios", "android"}
	var b [1]byte
	_, _ = cryptorand.Read(b[:])
	return options[int(b[0])%len(options)]
}

// installTCPRewriter sets up an NFQUEUE iptables rule that punts every
// outbound TCP SYN to userspace, then starts a per-namespace listener
// that rewrites the option set + window scale + timestamp presence to
// match the persona.
func installTCPRewriter(st *linuxState, persona string) error {
	pp := tcpfp.Builtin(persona)
	if pp == nil {
		return fmt.Errorf("no rewriter persona for %q", persona)
	}
	// Per-profile random TS offset: kills cross-profile correlation via
	// shared kernel timestamp clock.
	var offsetBytes [4]byte
	if _, err := cryptorand.Read(offsetBytes[:]); err == nil {
		pp.TSOffset = uint32(offsetBytes[0])<<24 | uint32(offsetBytes[1])<<16 |
			uint32(offsetBytes[2])<<8 | uint32(offsetBytes[3])
	}
	// Use a per-session queue number derived from the netns name hash.
	queueNum := uint16(0)
	for _, c := range st.netnsName {
		queueNum = queueNum*131 + uint16(c)
	}
	queueNum = (queueNum % 0xFE00) + 0x100 // stay in 256..65279

	// NOTE: this NFQUEUE hook lives in filter OUTPUT and is appended, so
	// a backend kill switch that terminally ACCEPTs first (WireGuard's
	// "-o <wgif> -j ACCEPT", tor's loopback ACCEPT) shadows it and the
	// SYN rewrite never fires in those chains (verified: queue TOTAL=0).
	// Moving it to mangle OUTPUT so it fires DOES rewrite the SYN but
	// breaks connectivity in the non-root path (the reinjected packet is
	// dropped, likely a checksum-offload / tunnel-MTU interaction), so
	// for now we keep the safe no-op placement: TTL + MSS still come
	// from the iptables mangle in installTCPPersona, and installTCPRewriter
	// warns below when the deeper rewrite isn't active. Full option-order
	// rewrite in the user-ns path needs more work (see warn).
	rule := []string{"-w", "5", "-A", "OUTPUT",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNum)),
		"--queue-bypass",
	}
	args := append([]string{"netns", "exec", st.netnsName, "iptables"}, rule...)
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("nfqueue iptables: %s: %w", string(out), err)
	}
	listener, err := tcpfp.Start(st.netnsName, queueNum, pp)
	if err != nil {
		// Roll back the iptables rule on failure.
		_ = exec.Command("ip", "netns", "exec", st.netnsName, "iptables",
			"-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNum)),
			"--queue-bypass").Run()
		return err
	}
	st.cleanupExtra = append(st.cleanupExtra, func() error {
		_ = listener.Stop()
		_ = exec.Command("ip", "netns", "exec", st.netnsName, "iptables",
			"-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queueNum)),
			"--queue-bypass").Run()
		return nil
	})
	// Verify the NFQUEUE actually bound inside the netns. go-nfqueue
	// performs the queue bind asynchronously after Start() returns, and
	// in an unprivileged user-ns that bind can silently fail (binding an
	// nfnetlink_queue still requires CAP_NET_ADMIN in the INIT user-ns
	// on most kernels, not just the netns owner). When it doesn't bind,
	// the OUTPUT "--queue-bypass" rule passes SYNs UNMODIFIED, so the
	// TCP option-order / window-scale / timestamp rewrite would silently
	// not apply. Warn loudly rather than claim success. TTL + MSS still
	// come from the iptables mangle (installTCPPersona), so partial L4
	// normalization remains in effect either way.
	if !nfqueueBound(st.netnsName, queueNum) {
		logger.L().Warn("tcp rewriter: NFQUEUE did not bind in the netns; "+
			"TCP option-order/window-scale/timestamp will NOT be rewritten "+
			"(TTL + MSS still applied). Likely an unprivileged user-ns "+
			"nfnetlink limitation; run as root for full TCP-stack persona.",
			"ns", st.netnsName, "persona", persona, "queue", queueNum)
	} else {
		logger.L().Info("tcp rewriter armed",
			"ns", st.netnsName, "persona", persona,
			"window_scale", pp.WindowScale, "queue", queueNum)
	}
	return nil
}

// nfqueueBound reports whether an nfnetlink_queue with the given queue
// number is bound by a listener inside the namespace. The first column
// of /proc/net/netfilter/nfnetlink_queue is the queue number; a row
// only exists once a process has bound (NFQNL_CFG_CMD_BIND) the queue.
func nfqueueBound(nsName string, queueNum uint16) bool {
	out, err := exec.Command("ip", "netns", "exec", nsName, "cat",
		"/proc/net/netfilter/nfnetlink_queue").Output()
	if err != nil {
		return false
	}
	want := strconv.Itoa(int(queueNum))
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) > 0 && f[0] == want {
			return true
		}
	}
	return false
}

// installPortRange picks a per-namespace ephemeral source-port range
// from a disjoint pool of slices in [10000, 60000]. Each profile name
// hashes to a unique slice so two simultaneous profiles never overlap
// on source-port allocation, removing one cross-profile correlation
// signal.
func installPortRange(st *linuxState) error {
	const lo, hi = 10000, 60000
	const sliceSize = 1024
	maxSlices := (hi - lo) / sliceSize // 48
	h := uint32(0)
	for _, c := range st.netnsName {
		h = h*131 + uint32(c)
	}
	idx := int(h) % maxSlices
	start := lo + idx*sliceSize
	end := start + sliceSize - 1
	args := []string{"netns", "exec", st.netnsName, "sysctl", "-w",
		fmt.Sprintf("net.ipv4.ip_local_port_range=%d %d", start, end)}
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("port range %d-%d: %s: %w", start, end, string(out), err)
	}
	logger.L().Info("port range carved", "ns", st.netnsName, "range", fmt.Sprintf("%d-%d", start, end))
	return nil
}

// installTCPPersona and deriveTCPFromPersona (the per-OS TCP/IP-stack
// fingerprint shaping — a Pro anti-detect capability) live in
// tcp_persona_linux_pro.go (//go:build linux && pro) with a no-op stub in
// tcp_persona_linux_stub.go for the free edition, so the technique is not
// present in the public open-core repo.

func (e *linuxEngine) allocSubnet(name string) (netip.Prefix, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.subnets == nil {
		e.subnets = map[string]netip.Prefix{}
	}
	if p, ok := e.subnets[name]; ok {
		return p, nil
	}
	// Seed search from a deterministic per-name hash so the same profile
	// tends to get the same /30 across runs (predictable for debugging).
	h := byte(0)
	for _, c := range name {
		h = byte(int(h)*131+int(c)) & 0xff
	}
	hostUsed := scanHostSubnets()
	for tries := 0; tries < 256; tries++ {
		oct3 := (h + byte(tries)) & 0xff
		p, _ := netip.ParsePrefix(fmt.Sprintf("%s%d.0/30", veilSubnetBase, oct3))
		// Skip if another active Veil session in this engine already has it.
		taken := false
		for _, used := range e.subnets {
			if used == p {
				taken = true
				break
			}
		}
		// Skip if the host already has an interface in this /30 (leftover
		// veth from a different process or a real local network).
		if !taken && hostUsed[p] {
			taken = true
		}
		if !taken {
			e.subnets[name] = p
			return p, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no free /30 in %s0.0/16 — too many active sessions or stale interfaces", veilSubnetBase)
}

// freeSubnet releases a /30 from the engine's allocation map.
func (e *linuxEngine) freeSubnet(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.subnets, name)
}

// scanHostSubnets looks at every IP currently configured on the host and
// returns the set of /30s overlapping any of them, so we don't try to
// reuse one that's already live.
func scanHostSubnets() map[netip.Prefix]bool {
	out := map[netip.Prefix]bool{}
	links, err := netlink.LinkList()
	if err != nil {
		return out
	}
	for _, l := range links {
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IPNet == nil {
				continue
			}
			ipv4src := a.IPNet.IP.To4()
			if ipv4src == nil {
				continue
			}
			// Defensive copy: To4() may alias netlink's internal buffer,
			// and we're about to mask the last octet to the /30 boundary.
			ipv4 := append(net.IP(nil), ipv4src...)
			ipv4[3] &^= 0x03
			p, err := netip.ParsePrefix(fmt.Sprintf("%s/30", ipv4.String()))
			if err == nil {
				out[p] = true
			}
		}
	}
	return out
}

func subnetAddrs(p netip.Prefix) [2]netip.Addr {
	a := p.Addr().As4()
	a[3] = 1
	host := netip.AddrFrom4(a)
	a[3] = 2
	ns := netip.AddrFrom4(a)
	return [2]netip.Addr{host, ns}
}

func (e *linuxEngine) createNamespace(st *linuxState) error {
	// If a namespace from a prior crashed run is still around, drop it
	// so we get a clean state.
	_ = exec.Command("ip", "netns", "del", st.netnsName).Run()
	// `ip netns add` ensures /var/run/netns/<name> exists so other tools see it.
	if out, err := exec.Command("ip", "netns", "add", st.netnsName).CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add: %s: %w", string(out), err)
	}
	h, err := netns.GetFromName(st.netnsName)
	if err != nil {
		return fmt.Errorf("getfromname: %w", err)
	}
	st.netns = h
	st.cleanupExtra = append(st.cleanupExtra, func() error {
		return exec.Command("ip", "netns", "del", st.netnsName).Run()
	})
	return nil
}

func (e *linuxEngine) createVethPair(st *linuxState) error {
	hash := uint32(0)
	for _, c := range st.netnsName {
		hash = hash*131 + uint32(c)
	}
	st.veth = fmt.Sprintf("veil%x0", hash%0xffff)
	st.peer = fmt.Sprintf("veil%x1", hash%0xffff)

	// If a previous run leaked a veth with this name (Down() crashed,
	// kernel kept the host-side device, etc.), drop it before adding.
	// The name is deterministic from the profile, so a stale device
	// otherwise turns every relaunch into "veth add: file exists".
	// Same fail-soft pattern as createNamespace's `ip netns del`.
	if existing, err := netlink.LinkByName(st.veth); err == nil {
		_ = netlink.LinkDel(existing)
	}
	if existing, err := netlink.LinkByName(st.peer); err == nil {
		_ = netlink.LinkDel(existing)
	}

	la := netlink.NewLinkAttrs()
	la.Name = st.veth
	veth := &netlink.Veth{LinkAttrs: la, PeerName: st.peer}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("veth add: %w", err)
	}
	st.cleanupExtra = append(st.cleanupExtra, func() error {
		l, err := netlink.LinkByName(st.veth)
		if err == nil {
			_ = netlink.LinkDel(l)
		}
		return nil
	})

	hostLink, err := netlink.LinkByName(st.veth)
	if err != nil {
		return err
	}
	peerLink, err := netlink.LinkByName(st.peer)
	if err != nil {
		return err
	}

	// Host-side address.
	hostNet := &net.IPNet{IP: net.IP(st.hostIP.AsSlice()), Mask: net.CIDRMask(30, 32)}
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: hostNet}); err != nil {
		return fmt.Errorf("host addr: %w", err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return err
	}

	// Move peer into the namespace.
	if err := netlink.LinkSetNsFd(peerLink, int(st.netns)); err != nil {
		return fmt.Errorf("move peer to ns: %w", err)
	}

	// Configure the peer end inside the namespace.
	return runInNetns(st.netns, func() error {
		l, err := netlink.LinkByName(st.peer)
		if err != nil {
			return err
		}
		nsNet := &net.IPNet{IP: net.IP(st.nsIP.AsSlice()), Mask: net.CIDRMask(30, 32)}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: nsNet}); err != nil {
			return fmt.Errorf("ns addr: %w", err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		// loopback up too
		if lo, err := netlink.LinkByName("lo"); err == nil {
			_ = netlink.LinkSetUp(lo)
		}
		// default route via host side
		gw := net.IP(st.hostIP.AsSlice())
		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        gw,
			Dst:       nil,
		})
	})
}

func (e *linuxEngine) configureForwarding(st *linuxState) error {
	// Enable IP forwarding. Per-netns sysctl on modern kernels — we
	// have CAP_NET_ADMIN inside our net-ns so this should always
	// succeed. HARD FAIL: without forwarding the netns is isolated
	// at the IP layer and traffic never reaches the wire — the user
	// would see a hung browser, not a recognizable "veil broken"
	// state. Surface it explicitly.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		return fmt.Errorf("enable ip_forward (CAP_NET_ADMIN required in this net-ns): %w", err)
	}
	// Verify the write took.
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err != nil || strings.TrimSpace(string(b)) != "1" {
		return fmt.Errorf("ip_forward did not enable (read back: %q, err: %v) — netns will not route", string(b), err)
	}

	subnetCIDR := st.subnet.String()
	wan, err := defaultWANInterface()
	if err != nil {
		return err
	}
	st.wanIface = wan

	// Each rule recorded so the cleanup phase can DELETE precisely what
	// it ADDED. -I FORWARD 1 keeps Veil's rules above Docker's.
	rules := [][]string{
		{"-w", "5", "-I", "FORWARD", "1", "-s", subnetCIDR, "-j", "ACCEPT"},
		{"-w", "5", "-I", "FORWARD", "1", "-d", subnetCIDR, "-j", "ACCEPT"},
		{"-w", "5", "-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "-o", wan, "-j", "MASQUERADE"},
	}
	for _, r := range rules {
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %s: %w", r, string(out), err)
		}
		st.hostRules = append(st.hostRules, append([]string(nil), r...))
		logger.L().Debug("iptables added", "rule", r)
	}
	return nil
}

// removeHostRules deletes every rule recorded in st.hostRules. Each
// recorded rule is an *insert/append* form; the matching delete form is
// produced by swapping -I/-A for -D and dropping the position number.
func removeHostRules(st *linuxState) {
	for _, r := range st.hostRules {
		del := toDeleteForm(r)
		if out, err := exec.Command("iptables", del...).CombinedOutput(); err != nil {
			logger.L().Warn("iptables delete failed", "rule", del, "err", err, "out", string(out))
		} else {
			logger.L().Debug("iptables removed", "rule", del)
		}
	}
}

// toDeleteForm rewrites an iptables ADD form to its DELETE form: copy r,
// replace -I/-A with -D, and drop the integer position that follows -I.
func toDeleteForm(r []string) []string {
	out := make([]string, 0, len(r))
	for i := 0; i < len(r); i++ {
		t := r[i]
		switch t {
		case "-I":
			out = append(out, "-D")
			if i+1 < len(r) {
				out = append(out, r[i+1])
				i++
			}
			// Drop next token if it's a numeric position.
			if i+1 < len(r) {
				if _, err := strconv.Atoi(r[i+1]); err == nil {
					i++
				}
			}
		case "-A":
			out = append(out, "-D")
		default:
			out = append(out, t)
		}
	}
	return out
}

func (e *linuxEngine) writeResolvConf(st *linuxState, dns []string) error {
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "9.9.9.9"}
	}
	dir := filepath.Join("/etc/netns", st.netnsName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "resolv.conf")
	var content string
	for _, ns := range dns {
		content += "nameserver " + ns + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	st.resolvFile = path
	st.cleanupExtra = append(st.cleanupExtra, func() error {
		_ = os.Remove(path)
		_ = os.Remove(dir)
		return nil
	})
	return nil
}

func (e *linuxEngine) moveTUNToNS(st *linuxState, s *backends.Steering) error {
	// Try the engine's current netns first. Legacy/root path: backend
	// creates the TUN here and we move it across.
	if link, err := netlink.LinkByName(s.TUNDevice); err == nil {
		if err := netlink.LinkSetNsFd(link, int(st.netns)); err != nil {
			return err
		}
	} else {
		// Not in our netns. Two legitimate reasons:
		//   1. Nested backend (e.g., second-hop wireguard) creates its
		//      TUN INSIDE the profile netns directly. Nothing to move.
		//   2. Userns engine path where the helper's "engine netns" and
		//      "profile netns" are the same — also nothing to move.
		// Probe the target netns; if the device is there, skip move and
		// continue to IP/route setup. If it's nowhere, surface the
		// original "Link not found" so callers can rollback.
		var foundInTarget bool
		probeErr := runInNetns(st.netns, func() error {
			if _, lerr := netlink.LinkByName(s.TUNDevice); lerr == nil {
				foundInTarget = true
			}
			return nil
		})
		if probeErr != nil {
			return fmt.Errorf("LinkByName %s: %w (also failed to probe target netns: %v)", s.TUNDevice, err, probeErr)
		}
		if !foundInTarget {
			return err
		}
	}
	return runInNetns(st.netns, func() error {
		l, err := netlink.LinkByName(s.TUNDevice)
		if err != nil {
			return err
		}
		// Pin /32 routes (e.g., this nested tunnel's peer endpoint) via
		// the PREVIOUS TUN device, BEFORE we replace the default route.
		// Without this, the inner WG would try to route its UDP packets
		// to its own peer through itself, which loops.
		if len(s.PinnedRoutes) > 0 && len(st.tunDevices) > 0 {
			prevTun := st.tunDevices[len(st.tunDevices)-1]
			pl, err := netlink.LinkByName(prevTun)
			if err == nil {
				for _, r := range s.PinnedRoutes {
					_, dst, perr := net.ParseCIDR(r)
					if perr != nil {
						continue
					}
					if perr := netlink.RouteReplace(&netlink.Route{
						LinkIndex: pl.Attrs().Index,
						Dst:       dst,
						Scope:     netlink.SCOPE_LINK,
					}); perr != nil {
						// HARD FAIL: a missing pinned route on a
						// multi-hop chain means the next hop's
						// upstream-IP traffic could egress via the
						// wrong tunnel (or no tunnel) and leak.
						return fmt.Errorf("pinned route %s via %s failed (multi-hop tunnel pinning broken; upstream would leak): %w", r, prevTun, perr)
					} else {
						logger.L().Info("pinned route", "dst", r, "via", prevTun)
					}
				}
			}
		}
		// Assign tunnel IPs to the TUN inside the namespace BEFORE bring-up.
		for _, a := range s.Addresses {
			ip, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				return fmt.Errorf("address %q: %w", a, err)
			}
			ipnet.IP = ip
			if err := netlink.AddrReplace(l, &netlink.Addr{IPNet: ipnet}); err != nil {
				return fmt.Errorf("addr %s on %s: %w", a, s.TUNDevice, err)
			}
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		// Default route via the TUN device. RouteReplace because the
		// namespace already has a default route either from the veth or
		// a previous tunnel hop.
		var gw net.IP
		if s.Gateway != "" {
			gw = net.ParseIP(s.Gateway)
		}
		_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
		return netlink.RouteReplace(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        gw,
			Dst:       defaultDst,
			Scope:     netlink.SCOPE_LINK,
		})
	})
}

// dropQUICOutbound installs an iptables REJECT for UDP/443 in the
// netns OUTPUT chain. Sits ABOVE the kill switch's policy DROP so it
// returns ICMP-unreachable (which the browser interprets as "network
// blocks QUIC, fall back to TCP") rather than a silent drop (which
// can stall the browser for handshake-timeout seconds).
func (e *linuxEngine) dropQUICOutbound(st *linuxState) error {
	if !runuserHasIptables() {
		return fmt.Errorf("iptables not in PATH — cannot install UDP/443 reject (would let QUIC bypass MITM)")
	}
	return runInNetns(st.netns, func() error {
		// -I OUTPUT 1: insert at top so this fires before the kill
		// switch's tunnel-only ACCEPT and before policy DROP.
		// REJECT with icmp-port-unreachable is what real "QUIC-blocked
		// network" middleboxes return; the browser parses this and
		// switches the per-network bit "this network is QUIC-broken".
		args := []string{
			"-w", "5",
			"-I", "OUTPUT", "1",
			"-p", "udp", "--dport", "443",
			"-j", "REJECT", "--reject-with", "icmp-port-unreachable",
		}
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables UDP/443 reject: %s: %w", string(out), err)
		}
		return nil
	})
}

// installKillSwitch installs fail-closed firewall rules in the namespace.
//
// Egress is permitted only via:
//   - loopback (local proxy / tor / curl-self-checks)
//   - any TUN/Wintun device attached to this session (active tunnels)
//   - the veth peer ONLY when there's no tunnel in the chain (proxy-only)
//     — in that case the proxy/tor traffic leaves via the host, which is
//     the only egress path the user actually has.
//
// Existing connections (ESTABLISHED, RELATED) get an ACCEPT so a tunnel
// blip doesn't tear connections that the kernel still considers up.
//
// All rules use `-w 5` so they don't race other iptables commands.
func (e *linuxEngine) installKillSwitch(st *linuxState) error {
	if !runuserHasIptables() {
		// HARD FAIL. The user opted into kill_switch=true (we
		// only call this when they did). Letting the namespace
		// run unfiltered means the user thinks they're protected
		// but a tunnel drop leaks the host's real IP.
		return fmt.Errorf("kill_switch requested but iptables not found in PATH — refusing to launch unfiltered (install iptables: apt install iptables; PATH inside namespace=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin)")
	}
	logger.L().Info("installing kill switch", "ns", st.netnsName, "tuns", st.tunDevices)
	if err := e.installKillSwitchRules(st); err != nil {
		return err
	}
	// Active verification: read back the rules and confirm policies are
	// DROP. If install silently fragmented (e.g. some rules but not the
	// policies), this catches it. Belt-and-suspenders against a "fail
	// closed" guarantee that didn't actually close.
	if err := e.verifyKillSwitch(st); err != nil {
		audit.Log(audit.Event{
			Type: audit.EventKillSwitchVerifyFail, Severity: audit.SeverityError,
			Detail: map[string]any{"ns": st.netnsName, "err": err.Error()},
		})
		audit.Crash("kill switch verification failed", st.netnsName, "",
			map[string]any{"err": err.Error()})
		return fmt.Errorf("kill switch verify: %w", err)
	}
	audit.Log(audit.Event{
		Type: audit.EventKillSwitchInstalled, Severity: audit.SeverityInfo,
		Detail: map[string]any{"ns": st.netnsName},
	})
	return nil
}

// installKillSwitchRules is the original install logic — moved to a
// helper so installKillSwitch can wrap it in verify+audit.
func (e *linuxEngine) installKillSwitchRules(st *linuxState) error {
	return runInNetns(st.netns, func() error {
		cmds := [][]string{
			{"-w", "5", "-P", "OUTPUT", "DROP"},
			{"-w", "5", "-P", "INPUT", "DROP"},
			{"-w", "5", "-P", "FORWARD", "DROP"},
			{"-w", "5", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"},
			{"-w", "5", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
			{"-w", "5", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
			{"-w", "5", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		}
		// Allow traffic out (and reply traffic in) each tunnel device.
		for _, d := range st.tunDevices {
			cmds = append(cmds,
				[]string{"-w", "5", "-A", "OUTPUT", "-o", d, "-j", "ACCEPT"},
				[]string{"-w", "5", "-A", "INPUT", "-i", d, "-j", "ACCEPT"},
			)
		}
		// Without a tunnel, the veth peer is the only egress (proxy-only chain).
		if len(st.tunDevices) == 0 {
			cmds = append(cmds,
				[]string{"-w", "5", "-A", "OUTPUT", "-o", st.peer, "-j", "ACCEPT"},
				[]string{"-w", "5", "-A", "INPUT", "-i", st.peer, "-j", "ACCEPT"},
			)
		}
		// Block multicast/broadcast on egress.
		cmds = append(cmds,
			[]string{"-w", "5", "-A", "OUTPUT", "-m", "addrtype", "--dst-type", "MULTICAST", "-j", "DROP"},
			[]string{"-w", "5", "-A", "OUTPUT", "-m", "addrtype", "--dst-type", "BROADCAST", "-j", "DROP"},
		)

		for _, c := range cmds {
			if out, err := exec.Command("iptables", c...).CombinedOutput(); err != nil {
				return fmt.Errorf("kill switch %v: %s: %w", c, string(out), err)
			}
		}
		return nil
	})
}

// verifyDNS runs a probe DNS query inside the namespace and returns
// nil iff the configured resolver answers within the timeout. Logs
// the result to the audit log either way.
//
// This is not a true leak test (which would require sniffing the host
// iface for stray DNS packets); it's a connectivity probe that
// confirms /etc/resolv.conf is being honored by the resolver path the
// kernel will hand to launched apps. Many "DNS leaks" in practice are
// actually "configured resolver unreachable, app falls back to host
// resolver" — which this catches.
func (e *linuxEngine) verifyDNS(st *linuxState) error {
	// Query a guaranteed-NXDOMAIN name. We just want to know the
	// resolver responds; the answer doesn't matter.
	name := "veil-probe.invalid"
	out, err := exec.Command(
		"ip", "netns", "exec", st.netnsName,
		"getent", "hosts", name,
	).CombinedOutput()
	// getent returns 2 for NOTFOUND (NXDOMAIN) — that's actually a
	// SUCCESSFUL resolver query, just with negative answer. We pass.
	// Returns 0 if name resolves (shouldn't for .invalid TLD but harmless).
	// Returns >2 or hangs if resolver is unreachable.
	if err != nil {
		// Check if it's just NXDOMAIN (exit 2) — that's fine.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 2 {
			audit.Log(audit.Event{
				Type: audit.EventDNSLeakProbePass, Severity: audit.SeverityInfo,
				Detail: map[string]any{"ns": st.netnsName, "result": "nxdomain"},
			})
			return nil
		}
		audit.Log(audit.Event{
			Type: audit.EventDNSLeakProbeFail, Severity: audit.SeverityError,
			Detail: map[string]any{
				"ns": st.netnsName, "err": err.Error(), "out": string(out),
			},
		})
		return fmt.Errorf("dns probe inside netns failed: %w (output: %s)", err, string(out))
	}
	audit.Log(audit.Event{
		Type: audit.EventDNSLeakProbePass, Severity: audit.SeverityInfo,
		Detail: map[string]any{"ns": st.netnsName, "result": "resolved"},
	})
	return nil
}

// verifyKillSwitch reads back the netns iptables rules and confirms:
//   - INPUT, OUTPUT, FORWARD chain policies are DROP
//   - At least one ACCEPT rule exists for the tunnel/peer device
//
// Returns error if rules don't match expectations — caller refuses to
// launch the user app in that case ("fail closed" verified, not assumed).
func (e *linuxEngine) verifyKillSwitch(st *linuxState) error {
	out, err := exec.Command("ip", "netns", "exec", st.netnsName, "iptables", "-S").CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -S: %w (out=%s)", err, string(out))
	}
	rules := string(out)
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		marker := "-P " + chain + " DROP"
		if !strings.Contains(rules, marker) {
			return fmt.Errorf("policy not DROP on %s chain (rules: %s)", chain, rules)
		}
	}
	// At least one egress ACCEPT rule (tunnel or peer) must exist.
	hasEgress := false
	for _, d := range append(st.tunDevices, st.peer) {
		if strings.Contains(rules, "-A OUTPUT -o "+d+" -j ACCEPT") {
			hasEgress = true
			break
		}
	}
	if !hasEgress {
		return fmt.Errorf("no egress ACCEPT rule found — namespace is fully sealed and unusable")
	}
	return nil
}

func runuserHasIptables() bool {
	_, err := exec.LookPath("iptables")
	return err == nil
}

// VerifyKillSwitch lists OUTPUT/INPUT chain policies and rule counts in a
// namespace. Used by veil doctor & selftest.
func VerifyKillSwitch(nsName string) (string, error) {
	out, err := exec.Command("ip", "netns", "exec", nsName, "iptables", "-S").CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func (e *linuxEngine) Launch(s *Session) (int, error) {
	st := s.State.(*linuxState)
	binary := s.Profile.App.Binary
	args := append([]string(nil), s.Profile.App.Args...)
	if s.Profile.App.Preset != "" && binary == "" {
		return 0, fmt.Errorf("preset %q: binary not resolved", s.Profile.App.Preset)
	}
	if binary == "" {
		return 0, fmt.Errorf("no app to launch")
	}

	target, err := resolveLaunchUser()
	if err != nil {
		return 0, err
	}

	// For browser presets without an explicit DataDir, default to a
	// per-profile dir under the *target user's* home so they have full
	// access regardless of pkexec/sudo's HOME shenanigans. Refresh the
	// preset args so --profile/--user-data-dir get the new path.
	if launcher.IsBrowserPreset(s.Profile.App.Preset) && s.Profile.DataDir == "" && target != nil {
		s.Profile.DataDir = filepath.Join(target.HomeDir, ".local", "share", "veil", "data", s.Profile.Name, s.Profile.App.Preset)
		// Clear any stale launcher-generated args so they get rebuilt.
		s.Profile.App.Args = nil
		if err := launcher.Resolve(s.Profile); err != nil {
			return 0, err
		}
		// Refresh local copies after Resolve.
		binary = s.Profile.App.Binary
		args = append([]string(nil), s.Profile.App.Args...)
	}

	// Ensure the per-profile data dir exists, owned by the target user
	// from the very top of any new path components down to the leaf.
	// Pre-existing root-owned components (from earlier crashed runs) are
	// chowned back to the user.
	if s.Profile.DataDir != "" {
		if target != nil {
			if err := ensureDirAsUser(s.Profile.DataDir, target); err != nil {
				return 0, fmt.Errorf("data dir %s: %w", s.Profile.DataDir, err)
			}
		} else {
			if err := os.MkdirAll(s.Profile.DataDir, 0o700); err != nil {
				return 0, fmt.Errorf("mkdir data dir: %w", err)
			}
		}
	}

	// Auto-fingerprint: if requested and TZ/Lang aren't user-set, derive
	// them from the session's exit country (looked up via ipinfo).
	if s.Profile.Env.AutoFromExit && (s.Profile.Env.TZ == "" || s.Profile.Env.Lang == "") {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if info, err := e.ExternalIPInfo(ctx, s); err == nil && info.Country != "" {
			tz, lang := launcher.CountryDefaults(info.Country)
			if s.Profile.Env.TZ == "" {
				s.Profile.Env.TZ = tz
			}
			if s.Profile.Env.Lang == "" {
				s.Profile.Env.Lang = lang
			}
			logger.L().Info("fingerprint auto-derived", "country", info.Country, "tz", tz, "lang", lang)
		}
		cancel()
	}

	// Configure the browser before it starts. For Firefox/Thunderbird
	// this writes user.js into DataDir; for Chromium/Brave it appends
	// --proxy-server. Either way the browser has no opportunity to
	// disregard the proxy — its own config is what we put there.
	proxyURL := ""
	if s.Final != nil {
		proxyURL = s.Final.ProxyURL
	}
	// Persona: load + apply at the same time as proxy config so the
	// launched browser sees both in its single startup-time config read.
	//
	// Anti-detect mode (ForgePersona): if the profile has ForgePersona
	// set, we resolve the persona name deterministically from the
	// profile name and forge a realistic, unique identity if it doesn't
	// already exist in the store. Same profile → same forged persona
	// forever; different profiles → different real-looking identities.
	personaName := s.Profile.Persona
	if s.Profile.ForgePersona {
		if personaName == "" {
			personaName = s.Profile.Name
		}
		// Build forge options from profile-saved constraints. Re-roll
		// seed lets the user rotate the forged persona without
		// renaming the profile (incrementing forge_seed yields a
		// different identity from the same name).
		opts := persona.ForgeOptions{
			FormFactor: s.Profile.ForgeFormFactor,
			OS:         s.Profile.ForgeOS,
			Browser:    s.Profile.ForgeBrowser,
			Country:    s.Profile.ForgeCountry,
			Seed:       s.Profile.ForgeSeed,
		}
		// Validate up front so a bad profile yaml fails launch with a
		// clear message instead of producing a misshapen persona.
		if err := opts.Validate(); err != nil {
			return 0, fmt.Errorf("forge_persona constraints: %w", err)
		}
		// Always re-forge with the current options instead of trusting
		// a possibly-stale stored copy. The store is only consulted as
		// a fallback for the no-options case (where same-name yields
		// same identity forever, the legacy contract).
		hasConstraints := opts.FormFactor != "" || opts.OS != "" ||
			opts.Browser != "" || opts.Country != "" || opts.Seed != ""
		if store, err := persona.DefaultStore(); err == nil {
			if hasConstraints {
				if forged, ferr := persona.ForgeWithError(personaName, opts); ferr == nil {
					_ = store.Save(forged)
					logger.L().Info("forged persona (constrained)",
						"name", forged.Name, "ua", forged.UserAgent,
						"platform", forged.Platform,
						"form_factor", opts.FormFactor, "os", opts.OS,
						"browser", opts.Browser, "country", opts.Country,
						"seed", opts.Seed)
					audit.LogPersonaForged(s.Profile.Name, forged.Name)
				}
			} else if _, err := store.Load(personaName); err != nil {
				if forged, ferr := store.ForgeAndStore(personaName); ferr == nil {
					logger.L().Info("forged persona", "name", forged.Name,
						"ua", forged.UserAgent, "platform", forged.Platform)
					audit.LogPersonaForged(s.Profile.Name, forged.Name)
				}
			}
		}
	}
	pc, fullPersona := loadPersonaFull(personaName)

	// Derive Env.TZ / Env.Lang from the persona's stated identity when
	// the user hasn't pinned them explicitly. Whoer-style leak tests
	// flag "system time != IP country TZ" and "browser language !=
	// IP country language" — both are real fingerprint-correlation
	// vectors. The persona already names a Country / Timezone /
	// Locale, so we have ground truth without needing an ipinfo
	// probe. User-set Env.TZ / Env.Lang always win (explicit beats
	// derived).
	if fullPersona != nil {
		if s.Profile.Env.TZ == "" {
			if fullPersona.Timezone != "" {
				s.Profile.Env.TZ = fullPersona.Timezone
			} else if fullPersona.Country != "" {
				if tz, _ := launcher.CountryDefaults(fullPersona.Country); tz != "" {
					s.Profile.Env.TZ = tz
				}
			}
		}
		if s.Profile.Env.Lang == "" {
			if fullPersona.Locale != "" {
				s.Profile.Env.Lang = fullPersona.Locale
			} else if fullPersona.Country != "" {
				if _, lang := launcher.CountryDefaults(fullPersona.Country); lang != "" {
					s.Profile.Env.Lang = lang
				}
			}
		}
		logger.L().Info("env derived from persona",
			"tz", s.Profile.Env.TZ, "lang", s.Profile.Env.Lang,
			"persona_country", fullPersona.Country)
	}

	if err := launcher.ApplyProxyPersonaAndFull(s.Profile, proxyURL, pc, fullPersona); err != nil {
		logger.L().Warn("apply proxy/persona config", "err", err)
	} else if proxyURL != "" {
		logger.L().Info("browser configured",
			"preset", s.Profile.App.Preset,
			"proxy", proxyURL,
			"persona", s.Profile.Persona)
	}

	// Schedule guard: refuse to launch outside the configured window
	// (in persona timezone). Empty window = no guard.
	if w := s.Profile.ScheduleWindow; w != "" {
		ptz := s.Profile.Env.TZ
		if ptz == "" && fullPersona != nil {
			ptz = fullPersona.Timezone
		}
		if err := CheckScheduleWindow(w, ptz); err != nil {
			return 0, fmt.Errorf("schedule guard: %w", err)
		}
	}

	// Locked endpoint: enforce that the actual exit matches the
	// profile's expected identity (country/ASN/IP). Verification mode
	// follows the local-first design: zero external queries by default;
	// opt-in probe-once for multi-hop edge cases.
	if s.Profile.LockedEndpoint {
		if err := e.verifyLockedEndpoint(s, personaName, fullPersona); err != nil {
			return 0, err
		}
	}
	// Persona's TZ/locale also feed into env overrides — give them
	// precedence over auto-from-exit (which already ran above).
	if pc != nil {
		if pc.AcceptLanguage != "" && s.Profile.Env.Lang == "" {
			// AcceptLanguage isn't a libc locale; only set Lang if persona
			// supplied a real locale via persona.Locale. Done below.
		}
	}
	// Re-chown the data dir after writing user.js (we wrote it as root).
	if s.Profile.DataDir != "" && target != nil {
		_ = chownRecursive(s.Profile.DataDir, target.uid, target.gid)
	}
	// Refresh local arg copy in case ApplyProxyConfig mutated p.App.Args.
	args = append([]string(nil), s.Profile.App.Args...)

	// Chromium-family browsers: enable a localhost-only DevTools debug
	// port so Veil can drive ipinfo.io / drift checks via the running
	// browser instead of issuing its own HTTPS request. The browser
	// makes the actual request — exit observers see browser-shaped
	// traffic, not a Veil-shaped tell. The port binds to 127.0.0.1
	// inside the netns; nothing reaches it from outside the namespace.
	// Start the persona probe server BEFORE the browser launches.
	// The extension's background script will POST to it as soon as
	// it loads; we wait on that probe below before letting the
	// launch path return success. Without the probe, Veil refuses
	// to expose the browser to the network.
	//
	// Started in-netns so the extension's localhost POST hits this
	// listener (and not whatever's bound on the host's loopback at
	// the same port).
	if s.Profile.DataDir != "" {
		needPersona := s.Profile.Persona != "" || s.Profile.ForgePersona ||
			s.Profile.AntiFingerprint.IsOn()
		if needPersona {
			if err := setupPersonaProbe(st, s.Profile.DataDir); err != nil {
				return 0, fmt.Errorf("persona probe setup: %w", err)
			}
			// REAL network gate: until the probe verifies, the browser
			// MUST NOT be able to reach the MITM proxy (which is its
			// only path to the open internet). Without this, the
			// browser has working network during the verification
			// window and a fast-clicking user could browse before the
			// probe deadline fires.
			//
			// The probe server itself is on a different localhost
			// port and is exempt by --proxy-bypass-list, so the
			// probe page loads while external HTTPS is hard-blocked.
			if s.Final != nil && s.Final.ProxyURL != "" {
				if err := blockBrowserEgress(st, s.Final.ProxyURL); err != nil {
					return 0, fmt.Errorf("install pre-probe egress block: %w", err)
				}
			}
		}
	}

	if launcher.IsChromiumPreset(s.Profile.App.Preset) {
		// Use --remote-debugging-port=0 + parse stderr for the
		// "DevTools listening on ws://..." line. This is the same
		// pattern Puppeteer / Playwright / ChromeDriver use because
		// it's the only race-free way:
		//   - We don't know what's free in the netns until Chromium
		//     itself binds. Pre-picking ports collides with Tor /
		//     tls_mitm and Chromium silently fails (no fallback in
		//     Chromium source — Brave drops the DevTools server
		//     entirely on EADDRINUSE).
		//   - --remote-debugging-port=0 → Chromium asks the kernel
		//     for any free port in ITS netns, binds successfully,
		//     prints "DevTools listening on ws://127.0.0.1:N/..."
		//     to stderr. We capture stderr, regex-match the line,
		//     extract the WS URL, and skip /json/version entirely.
		//   - --remote-allow-origins=* — we don't know the port at
		//     launch time so can't whitelist a specific origin. * is
		//     fine because Chromium is bound on 127.0.0.1 only.
		st.cdpReady = make(chan struct{})
		args = append(args,
			"--remote-debugging-port=0",
			"--remote-debugging-address=127.0.0.1",
			"--remote-allow-origins=*",
		)
		logger.L().Info("chromium debug port enabled (port=0, will discover via stderr)",
			"profile", s.Profile.Name, "ns", st.netnsName)
	}

	// Firefox: enable Marionette protocol for the same purpose as CDP
	// on Chromium. Firefox's --marionette-port CLI flag is IGNORED
	// (verified in stderr: Firefox always reports "Listening on port
	// 2828" regardless of the flag). The actual port comes from the
	// `marionette.port` user.js preference — which writeFirefoxUserJS
	// sets per-profile. We just enable Marionette here; the port is
	// already in user.js by this point.
	//
	// Default port 2828 collides when multiple Firefox profiles run
	// concurrently, so each profile's user.js sets a per-profile
	// random port and we read st.marionettePort from there.
	if s.Profile.App.Preset == "firefox" || s.Profile.App.Preset == "thunderbird" {
		port, err := pickEphemeralPortInNetns(st.netns)
		if err != nil {
			return 0, fmt.Errorf("pick marionette port in netns: %w", err)
		}
		st.marionettePort = port
		// Append marionette.port to the user.js launcher already wrote.
		// CLI flag --marionette-port is IGNORED by Firefox; only the
		// user.js pref controls the actual bind port.
		userJS := filepath.Join(s.Profile.DataDir, "user.js")
		extra := fmt.Sprintf("\nuser_pref(\"marionette.port\", %d);\n", port)
		if f, ferr := os.OpenFile(userJS, os.O_APPEND|os.O_WRONLY, 0o644); ferr == nil {
			_, _ = f.WriteString(extra)
			f.Close()
		}
		// -remote-allow-system-access is REQUIRED for Marionette to
		// switch to chrome scope (privileged context). Our IP probe
		// uses chrome-scope XHR to fetch ipinfo.io WITHOUT opening a
		// visible tab. Without this flag, SetContext(chrome) fails
		// with "System access is required" and the probe falls back
		// to navigating a real tab.
		args = append(args, "--marionette", "-remote-allow-system-access")
		logger.L().Info("firefox marionette enabled", "profile", s.Profile.Name, "port", port)
	}

	// Build env for the launched process. Start from the current env so
	// DISPLAY/WAYLAND_DISPLAY/etc come along (the GUI launcher injected
	// them via pkexec). Override HOME/USER for the target user so apps
	// that read $HOME (Firefox profile dir, Chromium config) point at the
	// right place when we drop privileges.
	env := os.Environ()
	if target != nil {
		env = setEnv(env, "HOME", target.HomeDir)
		env = setEnv(env, "USER", target.Username)
		env = setEnv(env, "LOGNAME", target.Username)
	}
	// Strict-tier (anti_fingerprint:strict) installs a per-profile
	// CA into <DataDir>/.pki/nssdb. Chromium-family browsers read
	// the NSS database from $HOME/.pki/nssdb — that path is
	// hardcoded in libnss, no Chromium flag overrides it. Without
	// HOME pointing at DataDir, Chromium never sees Veil's CA, every
	// TLS connection fails validation, and the browser appears to
	// have no internet. Override HOME for Chromium-family launches
	// when a CA is in play. (Firefox stores certs in the profile
	// dir directly, so this isn't needed for Firefox.)
	chainHasMITM := false
	for _, b := range s.Profile.Chain {
		if b.Kind == profile.BackendTLSMITM {
			chainHasMITM = true
			break
		}
	}
	if chainHasMITM && launcher.IsBrowserPreset(s.Profile.App.Preset) && s.Profile.DataDir != "" {
		switch strings.ToLower(s.Profile.App.Preset) {
		case "chromium", "brave", "veil-browser":
			env = setEnv(env, "HOME", s.Profile.DataDir)
			logger.L().Info("strict-tier: HOME overridden so Chromium reads per-profile NSS DB",
				"profile", s.Profile.Name, "home", s.Profile.DataDir)
		}
	}
	for k, v := range envOverridesEnv(s.Profile) {
		env = append(env, k+"="+v)
	}
	if s.Final != nil && s.Final.ProxyURL != "" {
		// Cross-platform proxy hint for apps that respect env vars.
		env = append(env,
			"HTTP_PROXY="+s.Final.ProxyURL,
			"HTTPS_PROXY="+s.Final.ProxyURL,
			"ALL_PROXY="+s.Final.ProxyURL,
			"http_proxy="+s.Final.ProxyURL,
			"https_proxy="+s.Final.ProxyURL,
			"all_proxy="+s.Final.ProxyURL,
		)
	}

	// Compose `ip netns exec <ns> unshare --time --monotonic=N
	// --boottime=N [runuser -u <user> --] <binary> <args>`.
	//
	// unshare --time gives the launched app its own time namespace with
	// per-profile monotonic + boottime offsets so JS performance.now()
	// and clock-drift signals can't be correlated across profiles
	// running on the same host (kernel 5.6+ required).
	tsOffset := randomTimeOffset()
	bootOffset := randomTimeOffset()
	cmdArgs := []string{"netns", "exec", st.netnsName}
	if hasUnshareTime() {
		cmdArgs = append(cmdArgs, "unshare", "--time",
			fmt.Sprintf("--monotonic=%d", tsOffset),
			fmt.Sprintf("--boottime=%d", bootOffset))
	}
	if target != nil {
		// -m/--preserve-environment keeps DISPLAY/XAUTHORITY/etc;
		// without it runuser resets PATH/HOME/USER and the GUI breaks.
		cmdArgs = append(cmdArgs, "/usr/sbin/runuser", "-u", target.Username, "-m", "--")
	}
	cmdArgs = append(cmdArgs, binary)
	cmdArgs = append(cmdArgs, args...)
	// We DON'T pass a probe URL anymore — verification is done
	// via CDP/Marionette pulling persona from the running browser
	// instead of the browser POSTing to us. Browser starts on its
	// default page (about:blank for Firefox via user.js;
	// chrome://newtab for Chromium with our --no-first-run +
	// no-network flags is harmless).

	// CPU throttle: create a cgroup v2 sub-cgroup with cpu.max set so
	// the launched app sees a uniform low CPU speed via JS benchmarks.
	// HARD FAIL if requested but unavailable — without this the
	// browser exposes the host's real CPU performance to JS-based
	// timing benchmarks, defeating the cohort-blending intent.
	cgroupPath := ""
	if s.Profile.CPUThrottle != "" {
		path, err := setupCPUCgroup(s.Profile.Name, s.Profile.CPUThrottle)
		if err != nil {
			return 0, fmt.Errorf("cpu_throttle=%q requested but cgroup setup failed (CPU performance fingerprint cannot be normalized): %w", s.Profile.CPUThrottle, err)
		}
		if path == "" {
			return 0, fmt.Errorf("cpu_throttle=%q requested but no writable cgroup v2 root found (need systemd v240+ user delegation, or a writable /sys/fs/cgroup); CPU performance fingerprint would leak", s.Profile.CPUThrottle)
		}
		cgroupPath = path
		logger.L().Info("cpu throttle armed", "path", path, "limit", s.Profile.CPUThrottle)
	}

	// Defensively clean up browser singleton-lock files left over from
	// a previous run that was SIGKILL'd before it could remove them.
	// Without this, the second launch of the same profile sees an old
	// SingletonLock (Chromium) or `lock` symlink (Firefox) and refuses
	// to start. Mirrors the veth/netns defensive cleanup pattern.
	if s.Profile.DataDir != "" && launcher.IsBrowserPreset(s.Profile.App.Preset) {
		for _, name := range []string{
			"SingletonLock", "SingletonCookie", "SingletonSocket",
			"Default/SingletonLock", "Default/SingletonCookie", "Default/SingletonSocket",
			"lock", ".parentlock",
		} {
			_ = os.Remove(filepath.Join(s.Profile.DataDir, name))
		}
	}

	cmd := exec.Command("ip", cmdArgs...)
	cmd.Env = env
	// Make the child its own process group leader so we can SIGKILL
	// the entire group (browser main + renderer/GPU/utility children)
	// in one shot on Stop. Without this, Chromium-spawned subprocesses
	// get reparented to PID 1 and keep running — holding the data_dir
	// SingletonLock open and blocking the next launch.
	//
	// Pdeathsig=SIGKILL: when the engine dies (crash, OOM-kill, force
	// kill), the kernel ships SIGKILL to the browser. Without it, a
	// crashed engine could leave the browser running and accessing
	// the netns until the netns ref-count drops to zero. The kill
	// switch (iptables in the netns) STILL prevents leaks during
	// that window, but killing the browser fast closes the gap from
	// "kill switch active until netns dies" to "browser gone, no
	// possible egress."
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	// Capture child stdout/stderr to a per-profile log so we can see why
	// a launched app died (Firefox often fails silently otherwise).
	logPath := "/tmp/veil-app-" + s.Profile.Name + ".log"
	logF, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	// devToolsURLWatcher scans stderr for the "DevTools listening on
	// ws://..." line that Chromium prints right after binding. It tees
	// every byte to logF (so the log still has full output) and
	// extracts the WS URL when it sees the marker line. See
	// cdp_stderr_watcher.go.
	dtWatcher := newDevToolsURLWatcher(st)
	if ferr == nil {
		cmd.Stdout = logF
		cmd.Stderr = io.MultiWriter(logF, dtWatcher)
		if target != nil {
			_ = logF.Chown(target.uid, target.gid)
		}
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = io.MultiWriter(os.Stderr, dtWatcher)
	}
	if err := cmd.Start(); err != nil {
		if logF != nil {
			logF.Close()
		}
		return 0, fmt.Errorf("%w (see %s)", err, logPath)
	}
	pid := cmd.Process.Pid
	st.pids = append(st.pids, pid)

	// Place the launched process into the cgroup so its CPU usage gets
	// throttled. Done after Start so the PID exists.
	if cgroupPath != "" {
		_ = os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
			[]byte(strconv.Itoa(pid)), 0o644)
	}

	// Firefox persona extension: stock Firefox refuses unsigned
	// extensions. Veil installs it as a temporary add-on via
	// Marionette. CRITICAL: this MUST be synchronous AND hard-fail.
	// If the extension never installs, the persona is silently NOT
	// applied — a leak the user would not detect (browser still
	// works, fingerprint just isn't shaped). We refuse to leave
	// Launch with the browser running but no persona override
	// installed.
	//
	// Network is already gated at iptables level: launch happens
	// inside the netns where the only egress is the chain. Even
	// during the few seconds Firefox boots before we install the
	// addon, traffic still goes out persona-shaped at L4/L7 (tls_
	// mitm, TCP rewriter); only the JS-level overrides aren't
	// applied yet. To protect against THAT brief window, the
	// Firefox user.js sets browser.startup.page=0 (about:blank) so
	// Firefox doesn't auto-open a homepage.
	//
	// personaVerified is set true ONLY when a real verification confirms
	// the persona actually applied — the Firefox Marionette addon install
	// just below, or the Chromium CDP check further down. The egress
	// unblock gates on it so a browser whose verification never ran fails
	// closed instead of being exposed unverified.
	personaVerified := false
	if st.marionettePort != 0 && s.Profile.DataDir != "" {
		needPersona := s.Profile.Persona != "" || s.Profile.ForgePersona ||
			s.Profile.AntiFingerprint.IsOn()
		if needPersona {
			extDir := filepath.Join(s.Profile.DataDir, "veil-persona-extension")
			if _, err := os.Stat(extDir); err != nil {
				_ = syscall.Kill(-pid, syscall.SIGTERM)
				_ = cmd.Process.Kill()
				return 0, fmt.Errorf("firefox persona extension dir missing at %s — refusing to launch with no persona override (would silently leak)", extDir)
			}
			deadline := time.Now().Add(30 * time.Second)
			var installErr error
			_ = runInNetns(st.netns, func() error {
				installErr = installFirefoxAddon(st.marionettePort, extDir, deadline)
				return nil
			})
			if installErr != nil {
				logger.L().Warn("firefox persona install failed; killing browser to prevent silent leak",
					"err", installErr, "profile", s.Profile.Name)
				_ = syscall.Kill(-pid, syscall.SIGTERM)
				_ = cmd.Process.Kill()
				return 0, fmt.Errorf("firefox persona extension install failed (refusing to run with no persona override — would silently leak): %w", installErr)
			}
			logger.L().Info("firefox persona extension installed",
				"profile", s.Profile.Name, "path", extDir)
			personaVerified = true
		}
	}

	go func() {
		_ = cmd.Wait()
		if logF != nil {
			logF.Close()
		}
		if cgroupPath != "" {
			_ = os.Remove(cgroupPath)
		}
	}()

	// Wait for the persona extension to phone home with its loaded
	// persona blob. CRITICAL gate: if the extension didn't load (or
	// loaded with mismatched persona), Veil REFUSES to leave the
	// browser running. Without this gate a half-broken extension
	// would leave the browser fingerprinting as the host system.
	//
	// The browser is already launched with about:blank as start
	// page (Firefox via user.js, Chromium has no auto-load) so it
	// hasn't made any external HTTPS request yet.
	// Persona verification via CDP (Chromium-family). Marionette path
	// for Firefox already verified at Addon:Install above.
	if st.personaProbe != nil && launcher.IsChromiumPreset(s.Profile.App.Preset) {
		// Wait for the CDP WebSocket URL to be discovered from
		// stderr, with a deadline.
		select {
		case <-st.cdpReady:
		case <-time.After(20 * time.Second):
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			_ = cmd.Process.Kill()
			return 0, fmt.Errorf("persona verify: CDP didn't come up within 20s — browser failed to bind --remote-debugging-port. log: /tmp/veil-app-%s.log", s.Profile.Name)
		}
		expectedJSON, _ := os.ReadFile(filepath.Join(s.Profile.DataDir, "veil-persona-extension", "persona.json"))
		var verr error
		if err := runInNetns(st.netns, func() error {
			verr = verifyPersonaViaCDP(context.Background(), st.cdpPort, st.cdpWSURL, expectedJSON, 20*time.Second)
			return nil
		}); err != nil {
			verr = err
		}
		if verr != nil {
			logger.L().Warn("persona verify failed; killing browser to prevent silent leak",
				"profile", s.Profile.Name, "err", verr)
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			_ = cmd.Process.Kill()
			return 0, fmt.Errorf("persona extension verification failed (refusing to expose browser to network): %w", verr)
		}
		// Verified → unblock browser egress so the user can browse.
		if s.Final != nil && s.Final.ProxyURL != "" {
			if uerr := unblockBrowserEgress(st, s.Final.ProxyURL); uerr != nil {
				logger.L().Warn("failed to remove pre-probe egress block",
					"profile", s.Profile.Name, "err", uerr)
			}
		}
		logger.L().Info("persona verified via CDP — extension loaded with correct persona",
			"profile", s.Profile.Name)
	} else if st.personaProbe != nil {
		// Reached for non-Chromium personas. A persona browser MUST have
		// been verified by the Firefox Marionette addon install above; if
		// it wasn't (e.g. Marionette never came up, so marionettePort was
		// 0 and the addon gate was skipped), there is NO proof the persona
		// applied — fail closed instead of unblocking an unverified
		// browser. Non-browser apps have no browser-JS persona to leak, so
		// they unblock (their L4/L7 shaping is enforced separately).
		if egressUnblockDecision(launcher.IsBrowserPreset(s.Profile.App.Preset), personaVerified) {
			logger.L().Warn("persona required but no verification ran; killing browser to prevent silent leak",
				"profile", s.Profile.Name, "marionette_port", st.marionettePort)
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			_ = cmd.Process.Kill()
			return 0, fmt.Errorf("persona required but neither Chromium CDP nor Firefox Marionette verification ran (marionette_port=%d) — refusing to unblock egress (fail closed)", st.marionettePort)
		}
		if s.Final != nil && s.Final.ProxyURL != "" {
			if uerr := unblockBrowserEgress(st, s.Final.ProxyURL); uerr != nil {
				logger.L().Warn("failed to remove pre-probe egress block",
					"profile", s.Profile.Name, "err", uerr)
			}
		}
		if personaVerified {
			logger.L().Info("persona verified via Marionette Addon:Install",
				"profile", s.Profile.Name)
		} else {
			logger.L().Info("non-browser persona profile — L4/L7 shaping enforced; egress unblocked",
				"profile", s.Profile.Name)
		}
	}
	return pid, nil
}

// setupCPUCgroup creates a cgroup v2 entry and writes cpu.max
// according to the user's throttle string.
//
// Format accepted:
//
//	"30%"             -> 30% of one core
//	"50000/100000"    -> 50ms quota per 100ms period (raw cpu.max)
//
// The cgroup root is determined dynamically: when running as actual
// host root, we use /sys/fs/cgroup directly. When running inside a
// user-ns where /sys/fs/cgroup is owned by host-uid-0 (unmapped), we
// fall back to the user's delegated subtree at
// /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/
// — systemd v240+ delegates this to the user.
//
// Returns ("", nil) (NOT an error) when no writable cgroup is
// available so CPU throttle degrades gracefully to "no throttle"
// instead of failing the whole launch.
func setupCPUCgroup(profileName, throttle string) (string, error) {
	root := findWritableCgroupRoot()
	if root == "" {
		logger.L().Warn("cgroup v2 root not writable; cpu_throttle will be a no-op",
			"profile", profileName)
		return "", nil
	}
	path := filepath.Join(root, "veil-"+profileName)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", err
	}
	// Enable the cpu controller in the parent (best-effort: systemd
	// usually has it on; if not, we'll fail to set cpu.max).
	_ = os.WriteFile(filepath.Join(root, "cgroup.subtree_control"),
		[]byte("+cpu"), 0o644)

	cpuMax := parseCPUThrottle(throttle)
	if err := os.WriteFile(filepath.Join(path, "cpu.max"),
		[]byte(cpuMax), 0o644); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("cpu.max: %w", err)
	}
	return path, nil
}

// findWritableCgroupRoot returns the cgroup v2 directory we have
// write access to, or "" when none is reachable. Order:
//  1. /sys/fs/cgroup if writable (real-root case).
//  2. /proc/self/cgroup → user-delegated subtree (rootless / user-ns).
func findWritableCgroupRoot() string {
	const sysRoot = "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(sysRoot, "cgroup.controllers")); err != nil {
		return ""
	}
	// Quick writability probe: try to create+remove a temp dir.
	probe := filepath.Join(sysRoot, ".veil-probe")
	if err := os.Mkdir(probe, 0o700); err == nil {
		_ = os.Remove(probe)
		return sysRoot
	}
	// Fallback: read our own cgroup membership and use that as the
	// delegated subtree. Format of /proc/self/cgroup line for v2:
	//   0::/user.slice/user-1000.slice/user@1000.service/...
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimPrefix(line, "0::")
			rel = strings.TrimSpace(rel)
			candidate := filepath.Join(sysRoot, rel)
			probe := filepath.Join(candidate, ".veil-probe")
			if err := os.Mkdir(probe, 0o700); err == nil {
				_ = os.Remove(probe)
				return candidate
			}
			break
		}
	}
	return ""
}

// parseCPUThrottle returns a cpu.max-formatted string ("<quota> <period>").
// "30%" → "30000 100000". A raw "<n>/<m>" passthrough is also accepted.
func parseCPUThrottle(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "max 100000"
	}
	if i := strings.Index(s, "/"); i > 0 {
		// raw form
		return strings.Replace(s, "/", " ", 1)
	}
	if strings.HasSuffix(s, "%") {
		pctStr := strings.TrimSuffix(s, "%")
		pct, err := strconv.Atoi(pctStr)
		if err != nil || pct <= 0 {
			return "max 100000"
		}
		// 100% of one core = 100000/100000 (1:1).
		quota := pct * 1000
		return fmt.Sprintf("%d 100000", quota)
	}
	return "max 100000"
}

// TorRelayIP looks up the relay IP for a Tor fingerprint via the
// session's Tor control port. Stays inside the netns; no external
// queries — Tor's local consensus already has every relay's IP.
func (e *linuxEngine) TorRelayIP(s *Session, fingerprint string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return "", fmt.Errorf("no Tor backend")
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return "", fmt.Errorf("no Tor control port")
	}
	st, _ := s.State.(*linuxState)
	if st == nil {
		return "", fmt.Errorf("invalid state")
	}
	var ip string
	err := runInNetns(st.netns, func() error {
		ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
		if err != nil {
			return err
		}
		defer ctrl.Close()
		got, err := ctrl.RelayIP(fingerprint)
		if err == nil {
			ip = got
		}
		return err
	})
	return ip, err
}

// installDNSProxy spawns cloudflared inside the session's netns,
// configured to listen on a free local port and forward queries as
// DoH to the configured upstream (DNSProxyUpstream, falling back to
// DNSMatchEndpoint, falling back to Mullvad). After cloudflared is
// up, the session's transparent-DNS REDIRECT rules get rewritten to
// point at cloudflared's port instead of Tor's DNSPort — every
// UDP/53 and TCP/53 in the netns funnels through cloudflared, gets
// DoH-wrapped, and exits the chain as HTTPS to the DoH provider.
//
// HARD FAIL when cloudflared isn't installed or fails to bind.
// Without the proxy actually running, the iptables redirect would
// black-hole every DNS query in the netns; that breaks the chain
// completely. The user opted into DNSProxy explicitly, so refuse
// the launch with a clear "install cloudflared" error rather than
// degrade silently.
func (e *linuxEngine) installDNSProxy(sess *Session, st *linuxState) error {
	// Run the DoH proxy as a goroutine inside the engine process
	// itself. The engine (in userns mode) ALREADY runs inside the
	// session's netns — no need to fork via `ip netns exec`. That
	// path was failing for reasons I couldn't pin down (stdio
	// disappearing under userns + ip-netns-exec interaction); doing
	// it in-process eliminates all of that surface area.
	upstream := strings.TrimSpace(sess.Profile.DNSProxyUpstream)
	if upstream == "" {
		upstream = strings.TrimSpace(sess.Profile.DNSMatchEndpoint)
	}
	if upstream == "" {
		upstream = "https://194.242.2.2/dns-query" // Mullvad default
	}
	port, err := pickEphemeralPortInNetns(st.netns)
	if err != nil {
		return fmt.Errorf("pick port for dns proxy: %w", err)
	}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// Bind the listeners synchronously here — they live in the
	// netns the engine itself is in. Hand the bound listeners to
	// dohproxy.Serve which only does the request handling.
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("dns_proxy resolve UDP %s: %w", listenAddr, err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("dns_proxy bind UDP %s: %w", listenAddr, err)
	}
	tcp, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("dns_proxy bind TCP %s: %w", listenAddr, err)
	}

	dohCtx, dohCancel := context.WithCancel(context.Background())
	go func() {
		_ = dohproxy.Serve(dohCtx, udp, tcp, upstream)
	}()
	st.dnsProxyCancel = dohCancel
	st.dnsProxyPort = port

	// Redirect every UDP/53 and TCP/53 in the netns to our local DoH
	// proxy. We INSERT at position 1 of both chains so our rule wins
	// over the OUTPUT-chain REDIRECT the Tor backend installed at
	// chain bring-up (which sends UDP/53 to Tor's DNSPort). The
	// OUTPUT chain is the critical one for transparent mode —
	// browser DNS queries are locally-originated in the netns, so
	// they hit OUTPUT, not PREROUTING. PREROUTING is here too as a
	// belt-and-suspenders for any externally-routed DNS that
	// somehow reaches the netns.
	//
	// HARD FAIL on either insert: a half-installed redirect would
	// silently let DNS fall through to Tor's DNSPort + exit
	// relay's upstream resolver (the leak the user enabled
	// dns_proxy to prevent in the first place).
	for _, chain := range []string{"OUTPUT", "PREROUTING"} {
		for _, proto := range []string{"udp", "tcp"} {
			args := []string{
				"netns", "exec", st.netnsName,
				"iptables", "-w", "5", "-t", "nat",
				"-I", chain, "1",
				"-p", proto, "--dport", "53",
				"-j", "REDIRECT", "--to-ports", strconv.Itoa(port),
			}
			if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
				dohCancel()
				return fmt.Errorf("install dns_proxy %s %s/53 redirect: %s: %w",
					chain, proto, strings.TrimSpace(string(out)), err)
			}
		}
	}
	logger.L().Info("dns_proxy installed (in-process DoH proxy)",
		"profile", sess.Profile.Name,
		"port", port,
		"upstream", upstream,
		"ns", st.netnsName)
	// Diagnostic: dump the netns nat OUTPUT chain to confirm our
	// REDIRECT rule is at position 1 (above Tor's). Without this we
	// can only guess from the dnsleaktest output whether the rule
	// is actually catching DNS.
	if out, err := exec.Command("ip", "netns", "exec", st.netnsName,
		"iptables", "-w", "5", "-t", "nat", "-L", "OUTPUT", "-n", "--line-numbers").CombinedOutput(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			logger.L().Info("dns_proxy nat OUTPUT", "line", line)
		}
	}
	return nil
}

// TorCircuitStatus dials the Tor control port from inside the
// session's netns and returns the raw GETINFO circuit-status reply.
func (e *linuxEngine) TorCircuitStatus(s *Session) (string, error) {
	if s == nil {
		return "", fmt.Errorf("TorCircuitStatus: nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return "", fmt.Errorf("TorCircuitStatus: profile %q has no Tor hop", s.Profile.Name)
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return "", fmt.Errorf("TorCircuitStatus: control port unavailable")
	}
	st, _ := s.State.(*linuxState)
	if st == nil {
		return "", fmt.Errorf("TorCircuitStatus: invalid state")
	}
	var out string
	err := runInNetns(st.netns, func() error {
		ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
		if err != nil {
			return fmt.Errorf("dial tor control: %w", err)
		}
		defer ctrl.Close()
		reply, err := ctrl.CircuitStatus()
		if err != nil {
			return err
		}
		out = reply
		return nil
	})
	return out, err
}

// TorNewCircuit signals SIGNAL NEWNYM to the session's Tor backend.
// Walks s.Backends for the *tor.Backend, dials its control port from
// inside the session's netns, sends NEWNYM. No-op when chain has no
// Tor hop (returns descriptive error so GUI can disable the button).
func (e *linuxEngine) TorNewCircuit(s *Session) error {
	if s == nil {
		return fmt.Errorf("TorNewCircuit: nil session")
	}
	var tb *tor.Backend
	for _, b := range s.Backends {
		if t, ok := b.(*tor.Backend); ok {
			tb = t
			break
		}
	}
	if tb == nil {
		return fmt.Errorf("TorNewCircuit: profile %q has no Tor hop", s.Profile.Name)
	}
	port, cookie := tb.ControlInfo()
	if port == 0 {
		return fmt.Errorf("TorNewCircuit: control port unavailable")
	}
	st, _ := s.State.(*linuxState)
	if st == nil {
		return fmt.Errorf("TorNewCircuit: invalid session state")
	}
	return runInNetns(st.netns, func() error {
		ctrl, err := tor.Dial(fmt.Sprintf("127.0.0.1:%d", port), cookie)
		if err != nil {
			return fmt.Errorf("dial tor control: %w", err)
		}
		defer ctrl.Close()
		return ctrl.NewCircuit()
	})
}

// writePersonaExtensionEarly forges/loads the profile's persona and
// drops persona.json + the extension scripts into <DataDir>/veil-
// persona-extension/ BEFORE the chain bootstraps. Otherwise tls_mitm
// (started during chain bring-up) loads the previous launch's stale
// persona.json and rewrites Sec-Ch-Ua-* on the wire to whatever
// persona was active LAST time the profile launched.
//
// Best-effort: any failure here just leaves the prior launch's files
// in place, which is the same behavior we used to have before this
// pre-pass existed. Launch-path ApplyProxyPersonaAndFull writes the
// files again later with identical content.
func writePersonaExtensionEarly(p *profile.Profile) {
	if p.DataDir == "" || !launcher.IsBrowserPreset(p.App.Preset) {
		return
	}
	personaName := p.Persona
	if p.ForgePersona && personaName == "" {
		personaName = p.Name
	}
	if personaName == "" {
		return
	}
	if p.ForgePersona {
		opts := persona.ForgeOptions{
			FormFactor: p.ForgeFormFactor,
			OS:         p.ForgeOS,
			Browser:    p.ForgeBrowser,
			Country:    p.ForgeCountry,
			Seed:       p.ForgeSeed,
		}
		if forged, err := persona.ForgeWithError(personaName, opts); err == nil {
			if store, err := persona.DefaultStore(); err == nil {
				_ = store.Save(forged)
			}
		}
	}
	_, full := loadPersonaFull(personaName)
	if full == nil {
		return
	}
	family := "chromium"
	switch strings.ToLower(p.App.Preset) {
	case "firefox", "thunderbird":
		family = "firefox"
	}
	if _, err := personaextension.WriteAndPersonaWithFlagsForBrowser(p.DataDir, family, full, nil); err != nil {
		logger.L().Warn("early persona extension write failed; tls_mitm may load stale persona.json",
			"profile", p.Name, "err", err)
		return
	}
	logger.L().Info("persona extension written pre-chain",
		"profile", p.Name, "persona", personaName, "country", full.Country)
}

// probeTimeout chooses a per-fetch deadline based on the chain
// shape. Tor (especially through low-exit countries) is meaningfully
// slower than direct fetches; 15s used to time out routinely on
// Brazilian / rare-country pins where the exit relay is up but
// loaded. Multi-hop chains compound the latency.
func probeTimeout(s *Session) time.Duration {
	if s != nil && s.Profile != nil {
		if s.Profile.ChainEndsInTor() || s.Profile.ChainIsMultihop() {
			return 60 * time.Second
		}
	}
	return 20 * time.Second
}

// BrowserProbeIP drives the running browser to fetch target via its
// remote-control protocol (CDP for Chromium-family, Marionette for
// Firefox). The browser makes the actual HTTPS request — exit
// observers see browser-shaped traffic. CDP/Marionette traffic stays
// on 127.0.0.1 inside the netns, never reaches the network.
//
// Returns an error when:
//   - the profile isn't running
//   - the launched app is neither Chromium-family nor Firefox
//   - the protocol connection / navigation / evaluation fails
//
// Callers (typically ExternalIPInfo) parse the returned body as JSON.
//
// Renamed receiver-method body kept below for the historical CDP path;
// to navigate to ipinfo.io and reads the page body back. The actual
// network request is made BY the browser — exit observers see a
// vanilla browser visit, not a Veil-initiated probe. CDP traffic
// stays on 127.0.0.1 inside the netns and never reaches the network.
//
// Returns an error if:
//   - the profile isn't running
//   - the launched app isn't a Chromium-family browser (no debug port)
//   - CDP connection / navigation / evaluation fails
//
// Callers (typically ExternalIPInfo) parse the returned body as JSON.
func (e *linuxEngine) BrowserProbeIP(ctx context.Context, s *Session, target string) (string, error) {
	st, ok := s.State.(*linuxState)
	if !ok {
		return "", fmt.Errorf("BrowserProbeIP: invalid session state")
	}
	// Fast-fail when the launched browser process is dead. Without
	// this, a clicked IP/Drift button waits the full 30s cdpProbe
	// deadline retrying connection-refused before erroring — feels
	// like the GUI hung. We have st.pids so just check.
	if !anyPidAlive(st.pids) {
		return "", fmt.Errorf("browser process has exited — relaunch the profile to use IP/drift/health probes")
	}
	// Choose protocol by what's enabled at the launch:
	//   * Chromium-family: cdpPort set, use CDP
	//   * Firefox: marionettePort set, use Marionette
	//   * neither: caller should fall back to local/error path
	if st.cdpReady != nil {
		// Wait for Chromium to print "DevTools listening on ws://..."
		// to stderr. Our devToolsURLWatcher captures it and closes
		// st.cdpReady. This is the canonical synchronization pattern
		// (Puppeteer/Playwright/ChromeDriver). Bound by ctx so the
		// caller's deadline still fires.
		select {
		case <-st.cdpReady:
			// got the URL
		case <-ctx.Done():
			return "", fmt.Errorf("cdp: timed out waiting for browser DevTools URL on stderr (browser may have failed to bind --remote-debugging-port; check %s)",
				"/tmp/veil-app-"+s.Profile.Name+".log")
		case <-time.After(20 * time.Second):
			return "", fmt.Errorf("cdp: 20s waiting for browser DevTools URL on stderr — Chromium probably failed to bind. log at /tmp/veil-app-%s.log",
				s.Profile.Name)
		}
		var body string
		err := runInNetns(st.netns, func() error {
			out, err := cdpProbeWithWS(ctx, st.cdpPort, st.cdpWSURL, target, probeTimeout(s))
			if err != nil {
				return err
			}
			body = out
			return nil
		})
		if err != nil {
			diag := nsListenDiag(st.netnsName, st.cdpPort)
			return "", fmt.Errorf("%w\n  netns diagnostic: %s\n  ws url: %s", err, diag, st.cdpWSURL)
		}
		return body, nil
	}
	if st.cdpPort != 0 {
		// Legacy path (kept for any code path that still pre-allocates
		// a port without setting cdpReady). Should be unused now.
		var body string
		err := runInNetns(st.netns, func() error {
			out, err := cdpProbe(ctx, st.cdpPort, target, probeTimeout(s))
			if err != nil {
				return err
			}
			body = out
			return nil
		})
		if err != nil {
			diag := nsListenDiag(st.netnsName, st.cdpPort)
			return "", fmt.Errorf("%w\n  netns diagnostic: %s", err, diag)
		}
		return body, nil
	}
	if st.marionettePort != 0 {
		var body string
		err := runInNetns(st.netns, func() error {
			out, err := firefoxProbe(ctx, st.marionettePort, target, probeTimeout(s))
			if err != nil {
				return err
			}
			body = out
			return nil
		})
		return body, err
	}
	return "", fmt.Errorf("BrowserProbeIP: profile %q has no remote-control port (preset is %q — only Chromium-family and Firefox are supported)", s.Profile.Name, s.Profile.App.Preset)
}

// loadPersona looks up the named persona and returns the launcher's
// view of it. Returns nil if the name is empty or the persona doesn't
// load — in that case the engine just doesn't apply persona overrides.
func loadPersona(name string) *launcher.PersonaConfig {
	pc, _ := loadPersonaFull(name)
	return pc
}

// loadPersonaFull returns both the launcher PersonaConfig (used for
// Firefox prefs / Chromium flags) and the full persona.Persona (used
// when launching a Chromium fork that consumes --veil-persona JSON).
func loadPersonaFull(name string) (*launcher.PersonaConfig, *persona.Persona) {
	if name == "" {
		return nil, nil
	}
	store, err := persona.DefaultStore()
	if err != nil {
		logger.L().Warn("persona store", "err", err)
		return nil, nil
	}
	p, err := store.Load(name)
	if err != nil {
		logger.L().Warn("persona load", "name", name, "err", err)
		return nil, nil
	}
	pc := &launcher.PersonaConfig{
		UserAgent:           p.UserAgent,
		AcceptLanguage:      p.AcceptLanguage,
		Platform:            p.Platform,
		ScreenWidth:         p.ScreenWidth,
		ScreenHeight:        p.ScreenHeight,
		DevicePixelRatio:    p.DevicePixelRatio,
		HardwareConcurrency: p.HardwareConcurrency,
	}
	return pc, p
}

// deriveTCPFromPersona (maps a persona's OS to a tcp_persona) is a Pro
// anti-detect helper; it lives in tcp_persona_linux_pro.go with a free
// stub in tcp_persona_linux_stub.go so the technique stays out of the
// public open-core repo.

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// anyPidAlive reports whether any of the given pids are still
// running. Used to fast-fail browser-dependent probes (IP, drift,
// health) when the browser has exited — without this the cdpProbe
// retries connection-refused for 30s before erroring, making the
// GUI feel hung.
func anyPidAlive(pids []int) bool {
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		// signal 0 = "is this process alive?". Returns nil if yes,
		// ESRCH if dead. Permission errors mean alive but ours.
		if err := syscall.Kill(pid, 0); err == nil {
			return true
		}
	}
	return false
}

// egressUnblockDecision decides the post-launch egress gate for a persona
// profile. It returns failClosed=true when a browser required a persona
// but no verification (Chromium CDP / Firefox Marionette) confirmed it —
// the caller must then kill the browser and abort rather than unblock an
// unverified browser. For a verified browser, or a non-browser app where
// the browser-JS persona doesn't apply, it returns false (unblock is
// safe; L4/L7 shaping is enforced independently).
func egressUnblockDecision(isBrowserPreset, personaVerified bool) (failClosed bool) {
	return isBrowserPreset && !personaVerified
}

// blockBrowserEgress installs an iptables rule in the profile netns
// that drops TCP packets destined for the MITM proxy port. The
// browser's --proxy-server points at that port, so blocking it
// effectively blocks ALL the browser's external HTTP/HTTPS — the
// proxy is the only path out for non-loopback traffic.
//
// Probe-page loopback (different port, exempt from proxy via
// --proxy-bypass-list) still works, so the probe completes and we
// can unblock once verified.
//
// Inserted at top of OUTPUT chain so it fires before any ACCEPT
// rule. Removed by unblockBrowserEgress on success.
func blockBrowserEgress(st *linuxState, proxyURL string) error {
	port, err := proxyPortFromURL(proxyURL)
	if err != nil {
		return err
	}
	return runInNetns(st.netns, func() error {
		args := []string{
			"-w", "5",
			"-I", "OUTPUT", "1",
			"-p", "tcp", "--dport", strconv.Itoa(port),
			"-j", "REJECT", "--reject-with", "tcp-reset",
		}
		out, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("install egress block: %s: %w", string(out), err)
		}
		logger.L().Info("pre-probe egress block installed",
			"ns", st.netnsName, "blocked_dport", port)
		return nil
	})
}

// unblockBrowserEgress removes the pre-probe egress block.
func unblockBrowserEgress(st *linuxState, proxyURL string) error {
	port, err := proxyPortFromURL(proxyURL)
	if err != nil {
		return err
	}
	return runInNetns(st.netns, func() error {
		args := []string{
			"-w", "5",
			"-D", "OUTPUT",
			"-p", "tcp", "--dport", strconv.Itoa(port),
			"-j", "REJECT", "--reject-with", "tcp-reset",
		}
		out, err := exec.Command("iptables", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("remove egress block: %s: %w", string(out), err)
		}
		logger.L().Info("pre-probe egress block removed",
			"ns", st.netnsName, "unblocked_dport", port)
		return nil
	})
}

// proxyPortFromURL extracts the port from "http://127.0.0.1:N" /
// "socks5://...:N" style proxy URLs.
func proxyPortFromURL(proxyURL string) (int, error) {
	// Trim scheme.
	s := proxyURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path/query.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	colon := strings.LastIndex(s, ":")
	if colon < 0 {
		return 0, fmt.Errorf("no port in proxy URL %q", proxyURL)
	}
	p, err := strconv.Atoi(s[colon+1:])
	if err != nil || p <= 0 {
		return 0, fmt.Errorf("bad port in proxy URL %q: %w", proxyURL, err)
	}
	return p, nil
}

// setupPersonaProbe starts a probe HTTP server inside the profile
// netns + injects the probe URL + token into the existing persona
// JSON file (and the persona-data.js the extension reads). Returns
// nil + a probe handle stored on st; caller must Wait on it after
// launching the browser.
func setupPersonaProbe(st *linuxState, dataDir string) error {
	personaPath := filepath.Join(dataDir, "veil-persona-extension", "persona.json")
	dataJSPath := filepath.Join(dataDir, "veil-persona-extension", "persona-data.js")
	raw, err := os.ReadFile(personaPath)
	if err != nil {
		return fmt.Errorf("read persona.json: %w", err)
	}
	srv, err := newPersonaProbeServer(raw)
	if err != nil {
		return err
	}
	if err := runInNetns(st.netns, func() error {
		_, e := srv.Start()
		return e
	}); err != nil {
		return fmt.Errorf("start probe in netns: %w", err)
	}
	// Inject probe URL + token into persona.json + persona-data.js.
	var blob map[string]any
	if err := json.Unmarshal(raw, &blob); err != nil {
		_ = srv.Close()
		return fmt.Errorf("parse persona.json: %w", err)
	}
	blob["_veil_probe_url"] = srv.URL()
	blob["_veil_probe_token"] = srv.Token()
	patched, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		_ = srv.Close()
		return err
	}
	if err := os.WriteFile(personaPath, patched, 0o644); err != nil {
		_ = srv.Close()
		return fmt.Errorf("write patched persona.json: %w", err)
	}
	dataJS := []byte("// Auto-generated by Veil — do not edit by hand.\n" +
		"window.__veil_persona_data = " + string(patched) + ";\n")
	if err := os.WriteFile(dataJSPath, dataJS, 0o644); err != nil {
		_ = srv.Close()
		return fmt.Errorf("write patched persona-data.js: %w", err)
	}
	st.personaProbe = srv
	st.cleanupExtra = append(st.cleanupExtra, func() error { return srv.Close() })
	logger.L().Info("persona probe armed", "url", srv.URL())
	return nil
}

// pickEphemeralPortInNetns picks a free TCP port BY BINDING INSIDE
// the given netns. Returns the port number and closes the listener
// — kernel preserves the recently-released port for a brief window
// so the actual user (Brave's --remote-debugging-port) gets it.
//
// CRITICAL: must use this instead of pickEphemeralPort when the
// caller will hand the port to a process that runs INSIDE the netns.
// Each netns has its own port allocation table; a port we get from
// the parent's netns may already be bound by another in-netns
// service (Tor's transparent port, tls_mitm, etc.).
func pickEphemeralPortInNetns(ns netns.NsHandle) (int, error) {
	var port int
	err := runInNetns(ns, func() error {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		port = l.Addr().(*net.TCPAddr).Port
		return l.Close()
	})
	if err != nil {
		return 0, err
	}
	return port, nil
}

// readDevToolsActivePort reads <dataDir>/DevToolsActivePort which
// Chromium writes once its DevTools HTTP server has actually bound a
// port. Format: line 1 = port number, line 2 = browser GUID (which
// is the WebSocket path /devtools/browser/<guid>). Returns 0 + ""
// if the file is missing or unreadable — caller should keep using
// st.cdpPort (the port we asked for).
//
// We need this because Chromium DOES NOT write the requested port
// when it ends up binding a different one (e.g., requested port was
// in use). Without checking the file, we'd dial the requested port
// forever and time out while Chromium is alive on a different one.
func readDevToolsActivePort(dataDir string) (port int, browserPath string) {
	if dataDir == "" {
		return 0, ""
	}
	// Chromium-family browsers all write the file in the user-data-dir
	// root or in the default profile subdir. Try both.
	for _, sub := range []string{"DevToolsActivePort", "Default/DevToolsActivePort"} {
		raw, err := os.ReadFile(filepath.Join(dataDir, sub))
		if err != nil {
			continue
		}
		lines := strings.SplitN(strings.TrimSpace(string(raw)), "\n", 2)
		if len(lines) == 0 {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSpace(lines[0]))
		if err != nil || p <= 0 {
			continue
		}
		bp := ""
		if len(lines) > 1 {
			bp = strings.TrimSpace(lines[1])
		}
		return p, bp
	}
	return 0, ""
}

// nsListenDiag runs `ip netns exec NS ss -lnt` and returns a short
// summary of what's listening in the netns. Used in error messages
// so failures like "browser debug port refused" come with evidence
// of whether the port (and other expected ports like Tor SOCKS) is
// actually bound — distinguishing "browser failed to bind" from
// "we're dialing the wrong netns" from "port shifted".
func nsListenDiag(nsName string, expectPort int) string {
	out, err := exec.Command("ip", "netns", "exec", nsName, "ss", "-lnt").Output()
	if err != nil {
		return fmt.Sprintf("ss failed: %v", err)
	}
	lines := strings.Split(string(out), "\n")
	var listening []string
	saw := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "State") {
			continue
		}
		// Format: State Recv-Q Send-Q Local-Address:Port ...
		fs := strings.Fields(l)
		if len(fs) < 4 {
			continue
		}
		addr := fs[3]
		listening = append(listening, addr)
		if strings.HasSuffix(addr, fmt.Sprintf(":%d", expectPort)) {
			saw = true
		}
	}
	if saw {
		return fmt.Sprintf("port %d IS listening in netns; got refused anyway — check firewall / NFQUEUE rule. listeners: %s", expectPort, strings.Join(listening, ", "))
	}
	return fmt.Sprintf("port %d NOT listening in netns (browser bound elsewhere or hasn't bound yet). listeners: %s", expectPort, strings.Join(listening, ", "))
}

// deriveTLSFingerprintFromPersona returns the uTLS template name that
// matches the persona's claimed browser. Used by Up() to override the
// chain's tls_mitm hop fingerprint, which was initially picked from
// App.Preset alone (no persona-awareness at profile-validation time
// due to import-cycle constraints — see profile.pickTLSFingerprint).
//
// Without this, running e.g. an iPhone-Safari persona inside Brave
// would TLS-handshake as Chrome while the JS layer + headers claim
// Safari iOS — which is itself a fingerprint signal.
func deriveTLSFingerprintFromPersona(p *profile.Profile) string {
	var pers *persona.Persona
	if p.Persona != "" {
		_, pers = loadPersonaFull(p.Persona)
	} else if p.ForgePersona {
		pers = persona.ForgeWith(p.Name, persona.ForgeOptions{
			FormFactor: p.ForgeFormFactor,
			OS:         p.ForgeOS,
			Browser:    p.ForgeBrowser,
			Country:    p.ForgeCountry,
			Seed:       p.ForgeSeed,
		})
	}
	if pers == nil {
		return ""
	}
	ua := pers.UserAgent
	switch {
	case contains(ua, "Firefox/"):
		return "firefox"
	case contains(ua, "Edg/"):
		return "edge"
	case contains(ua, "iPhone"), contains(ua, "iPad"):
		return "ios"
	case contains(ua, "Macintosh") && contains(ua, "Safari/") && !contains(ua, "Chrome/"):
		return "safari"
	case contains(ua, "Chrome/"):
		return "chrome"
	}
	// ClientHints fallback when UA is generic.
	if pers.ClientHints != nil {
		switch pers.ClientHints.Platform {
		case "iOS":
			return "ios"
		case "macOS":
			return "safari"
		}
	}
	return ""
}

// chownRecursive sets ownership of path and everything under it.
func chownRecursive(path string, uid, gid int) error {
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

// ensureDirAsUser makes path exist with every directory from the user's
// home down to the leaf owned by target with mode 0700 (leaf) / 0755
// (parents). Any existing root-owned components inside the user's home
// are chowned back to target.
func ensureDirAsUser(path string, target *targetUser) error {
	if !filepath.IsAbs(path) {
		var err error
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}
	}
	clean := filepath.Clean(path)
	if !pathHasPrefix(clean, target.HomeDir) {
		// Outside user's home; just MkdirAll + chown the whole tree.
		if err := os.MkdirAll(clean, 0o755); err != nil {
			return err
		}
		return chownRecursive(clean, target.uid, target.gid)
	}
	// Within user's home — create each missing component with 0o755
	// and chown to user. Already-existing components owned by root
	// (likely from a prior crashed run) are repaired.
	rel, err := filepath.Rel(target.HomeDir, clean)
	if err != nil {
		return err
	}
	cur := target.HomeDir
	parts := splitPath(rel)
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		mode := os.FileMode(0o755)
		if i == len(parts)-1 {
			mode = 0o700
		}
		if fi, err := os.Stat(cur); os.IsNotExist(err) {
			if err := os.Mkdir(cur, mode); err != nil && !os.IsExist(err) {
				return err
			}
			if err := os.Chown(cur, target.uid, target.gid); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != target.uid {
			// Pre-existing dir owned by someone else (likely root from
			// a previous failed launch) — fix it.
			if err := os.Chown(cur, target.uid, target.gid); err != nil {
				return err
			}
		}
	}
	return nil
}

func pathHasPrefix(path, prefix string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(prefix) {
		return false
	}
	prefix = filepath.Clean(prefix)
	if path == prefix {
		return true
	}
	return len(path) > len(prefix) &&
		path[:len(prefix)] == prefix &&
		path[len(prefix)] == filepath.Separator
}

func splitPath(p string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(p); i++ {
		if p[i] == filepath.Separator {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(p[i])
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// targetUser describes the unprivileged user we drop to before exec'ing
// the launched app.
type targetUser struct {
	Username string
	HomeDir  string
	uid, gid int
}

// resolveLaunchUser picks the unprivileged user to launch the app as,
// based on how veil was started (sudo / pkexec / plain root). Returns
// nil when veil is running as a normal user already.
func resolveLaunchUser() (*targetUser, error) {
	if os.Geteuid() != 0 {
		return nil, nil // we're not root; launch as ourselves
	}
	// User-ns engine path: euid=0 is "root in the namespace" but we
	// were started by an unprivileged user (mapping host uid 1000 → 0).
	// We don't need to drop privileges because we ARE the user from
	// the host's perspective — just running with namespace-fake-root.
	// Trying to chown to the host uid would also fail with EINVAL
	// because that uid isn't mapped inside our user-ns.
	if inUnprivilegedUserNS() {
		return nil, nil
	}
	candidates := []string{
		os.Getenv("SUDO_USER"),
		lookupByUID(os.Getenv("PKEXEC_UID")),
		os.Getenv("USER"),
	}
	for _, name := range candidates {
		if name == "" || name == "root" {
			continue
		}
		u, err := osuser.Lookup(name)
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		return &targetUser{
			Username: u.Username,
			HomeDir:  u.HomeDir,
			uid:      uid,
			gid:      gid,
		}, nil
	}
	return nil, fmt.Errorf("running as root with no SUDO_USER / PKEXEC_UID — refusing to launch app as root (apps like Firefox refuse). Run veil from your user account or via sudo/pkexec.")
}

func lookupByUID(uidStr string) string {
	if uidStr == "" {
		return ""
	}
	u, err := osuser.LookupId(uidStr)
	if err != nil {
		return ""
	}
	return u.Username
}

// inUnprivilegedUserNS reports whether the current process is in a
// user namespace where uid 0 inside the namespace maps to a non-zero
// host uid. That's the user-ns engine path: we're "root" inside but
// were started by uid 1000 outside.
//
// /proc/self/uid_map format is one mapping per line:
//
//	NS_ID HOST_ID COUNT
//
// The init user-ns shows "0 0 4294967295" (identity). Anything else
// for ns id 0 means we were unshared with a non-identity mapping.
func inUnprivilegedUserNS() bool {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "0" && fields[1] != "0" {
			return true
		}
	}
	return false
}

// setEnv returns env with key=val, replacing any prior occurrence of key.
func setEnv(env []string, key, val string) []string {
	prefix := key + "="
	out := env[:0]
	for _, kv := range env {
		if len(kv) >= len(prefix) && kv[:len(prefix)] == prefix {
			continue
		}
		out = append(out, kv)
	}
	return append(out, prefix+val)
}

func envOverridesEnv(p *profile.Profile) map[string]string {
	out := map[string]string{}
	if p.Env.TZ != "" {
		out["TZ"] = p.Env.TZ
	}
	if p.Env.Lang != "" {
		out["LANG"] = p.Env.Lang
	}
	if p.Env.LCAll != "" {
		out["LC_ALL"] = p.Env.LCAll
	}
	for k, v := range p.Env.Custom {
		out[k] = v
	}
	return out
}

func (e *linuxEngine) Down(s *Session) error {
	st := s.State.(*linuxState)
	logger.L().Info("engine.Down", "profile", s.Profile.Name)

	// Stop all backends IN PARALLEL. They don't depend on each other
	// for shutdown — a Tor backend doesn't need a WireGuard backend
	// to finish first to die. Sequential stops were the dominant
	// reason "stopping takes ages" on multi-backend chains. Total
	// time now ≈ max(per-backend-stop), not sum().
	//
	// Per-backend hard timeout 3s (was 5s). Most well-behaved backends
	// finish in <500 ms; if Tor's process-wait or an OpenVPN cleanup
	// hangs longer than that it's not getting any happier with more
	// time, just SIGKILL it via the next phase.
	if len(s.Backends) > 0 {
		var wg sync.WaitGroup
		wg.Add(len(s.Backends))
		for i := len(s.Backends) - 1; i >= 0; i-- {
			go func(b backends.Backend) {
				defer wg.Done()
				done := make(chan error, 1)
				go func() {
					defer func() {
						if r := recover(); r != nil {
							done <- fmt.Errorf("panic in backend.Stop: %v", r)
						}
					}()
					done <- b.Stop()
				}()
				select {
				case err := <-done:
					if err != nil {
						logger.L().Warn("backend stop", "kind", b.Kind(), "err", err)
					}
				case <-time.After(3 * time.Second):
					logger.L().Warn("backend stop timed out — continuing teardown",
						"kind", b.Kind(), "profile", s.Profile.Name)
				}
			}(s.Backends[i])
		}
		wg.Wait()
	}

	// SIGTERM the process GROUP (negative PID) so the launched
	// browser's renderer/GPU/utility subprocesses die too — without
	// the group-kill, those orphan to PID 1 and keep running, holding
	// the data_dir's SingletonLock open. With Setpgid:true at Launch,
	// every child shares the group ID equal to the main PID.
	//
	// 800 ms grace lets Chromium write its lock-cleanup before we
	// escalate to SIGKILL (was 200 ms — too short, browsers leak
	// stale SingletonLock files when killed before they could clean
	// up, breaking the next launch).
	for _, pid := range st.pids {
		_ = syscall.Kill(-pid, syscall.SIGTERM)
	}
	if len(st.pids) > 0 {
		time.Sleep(800 * time.Millisecond)
		for _, pid := range st.pids {
			// Group-kill again, then individual-kill as a fallback in
			// case anything moved out of the group.
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			if err := syscall.Kill(pid, 0); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}

	err := e.cleanup(st)
	e.freeSubnet(s.Profile.Name)
	return err
}

func (e *linuxEngine) cleanup(st *linuxState) error {
	logger.L().Info("engine.cleanup", "ns", st.netnsName)
	// Stop the keyboard jitter daemon FIRST so the user's keyboard
	// returns to the X server before anything else races.
	if st.jitter != nil {
		_ = st.jitter.Stop()
		st.jitter = nil
	}
	if st.mouseJitter != nil {
		_ = st.mouseJitter.Stop()
		st.mouseJitter = nil
	}
	// Cancel the in-process DoH proxy goroutine. Listener closes,
	// in-flight DoH HTTP calls cancel via context. Goroutine returns,
	// no resource leak. Triggered before netns destruction so any
	// pending writes complete cleanly.
	if st.dnsProxyCancel != nil {
		st.dnsProxyCancel()
		st.dnsProxyCancel = nil
	}
	// Tear down host iptables rules first so packets stop flowing through
	// us even before the namespace is dismantled.
	removeHostRules(st)

	var firstErr error
	for i := len(st.cleanupExtra) - 1; i >= 0; i-- {
		if err := st.cleanupExtra[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if st.netns != 0 {
		_ = st.netns.Close()
	}
	return firstErr
}

// cleanupOrphan removes a leftover veil-* netns + its veth from a previous
// run. Best-effort: any error is logged and ignored so engine.Up still
// proceeds.
//
// Refuses to clean a namespace whose corresponding runtime.Session is
// alive — that would tear down a sibling Veil process's session.

// (ExternalIP / ExternalIPInfo / TrafficStats / readNetnsStats /
// writableBuffer / jsonUnmarshalIPInfo moved to engine_linux_ip.go)

// (cleanupOrphan / CleanupAllOrphans / RecoverStale moved to
// engine_linux_recovery.go)

func (e *linuxEngine) Doctor(ctx context.Context) ([]Check, error) {
	var out []Check
	check := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail})
	}
	warn := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail, Warning: !ok})
	}

	if _, err := os.Stat("/proc/sys/net/ipv4/ip_forward"); err == nil {
		b, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		ok := len(b) > 0 && b[0] == '1'
		detail := "enabled"
		if !ok {
			detail = "disabled — run `sudo veil setup` to enable"
		}
		check("net.ipv4.ip_forward", ok, detail)
	} else {
		check("net.ipv4.ip_forward", false, err.Error())
	}

	for _, bin := range []string{"ip", "iptables"} {
		_, err := exec.LookPath(bin)
		check(bin, err == nil, fmt.Sprintf("required on PATH"))
	}
	for _, bin := range []string{"openvpn", "tor", "dbus-launch"} {
		_, err := exec.LookPath(bin)
		warn(bin, err == nil, "optional")
	}
	if os.Geteuid() != 0 {
		warn("running as root", false, "veil must run with sudo for namespace ops")
	} else {
		check("running as root", true, "")
	}
	return out, nil
}

// runInNetns executes fn inside ns by locking the OS thread, switching netns,
// running, and switching back.
func runInNetns(ns netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cur, err := netns.Get()
	if err != nil {
		return err
	}
	defer cur.Close()
	if err := netns.Set(ns); err != nil {
		return err
	}
	defer netns.Set(cur)
	return fn()
}

// chainNeedsTUN reports whether the profile's chain has a backend
// that opens /dev/net/tun (wireguard, openvpn, tor's transparent
// mode). Used so we only pre-flight the device when necessary —
// pure-SOCKS chains don't need it.
func chainNeedsTUN(p *profile.Profile) bool {
	for _, b := range p.Chain {
		switch b.Kind {
		case profile.BackendWireGuard, profile.BackendOpenVPN, profile.BackendTor:
			return true
		}
	}
	return false
}

// chainHasTLSMITM reports whether the profile's chain contains a
// tls_mitm hop. Used to decide whether a profile needs an on-disk
// DataDir for the per-profile CA even when the launched app isn't a
// browser.
func chainHasTLSMITM(chain []profile.Backend) bool {
	for _, b := range chain {
		if b.Kind == profile.BackendTLSMITM {
			return true
		}
	}
	return false
}

// preflightTUN verifies /dev/net/tun is readable by the current
// process before any backend tries to open it. Inside the user-ns
// engine path the user must be in the `veil` group AND that group
// must be active in the current session — udev's MODE/GROUP only
// matters if the user's process credentials include the group.
//
// Returns an actionable error (not a generic "permission denied")
// pointing at the exact remediation when access is missing.
func preflightTUN() error {
	const dev = "/dev/net/tun"
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return nil
	}
	// Read /dev/net/tun's actual permissions to give a precise hint.
	st, statErr := os.Stat(dev)
	if statErr != nil {
		return fmt.Errorf("/dev/net/tun missing on host: %w (kernel TUN module not loaded? `sudo modprobe tun`)", statErr)
	}
	mode := st.Mode().Perm()
	gid := -1
	if sysStat, ok := st.Sys().(*syscall.Stat_t); ok {
		gid = int(sysStat.Gid)
	}
	// gid=65534 inside a user-ns is the OVERFLOW gid — it means the
	// device's host gid (likely the veil group) isn't mapped into
	// the current user-ns's gid_map. NOT necessarily a udev failure.
	// Most common cause: process was started before its session
	// picked up the veil supplementary group. Veil-gui auto-reexecs
	// via `sg veil` to fix this; if that didn't trigger, the user
	// either isn't in the group or sg isn't installed.
	hint := "fix: sudo veil setup --install-helpers   # if you haven't run it\n" +
		"       then LOG OUT + LOG BACK IN, or run `newgrp veil` in this shell\n" +
		"  why: groups are evaluated at login time; usermod -aG veil only affects NEW sessions"
	if gid == 65534 {
		hint = "fix: this is the user-ns overflow gid — your process credentials don't include the\n" +
			"       host's veil group. The auto-reexec via `sg veil` should have fixed this; if\n" +
			"       you're still seeing it, run: `sudo usermod -aG veil $USER` and then either\n" +
			"       `newgrp veil` in this shell OR log out + log back in"
	}
	return fmt.Errorf(
		"open /dev/net/tun: %w\n"+
			"  device: mode=%04o gid=%d (expected mode 0660 group=veil after install)\n"+
			"  %s",
		err, mode, gid, hint)
}

func defaultWANInterface() (string, error) {
	out, err := exec.Command("ip", "-o", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	// "default via X.X.X.X dev eth0 ..."
	fields := splitFields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route")
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
