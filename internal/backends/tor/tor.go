// Package tor implements a Tor backend.
//
// Modes:
//
//   - Default (transparent=true): launches a managed Tor inside the
//     namespace with SocksPort + TransPort + DNSPort, then installs
//     iptables nat REDIRECT rules so every TCP connection (regardless
//     of whether the app honors a proxy) goes through Tor's TransPort,
//     and every DNS query goes through DNSPort. UDP is dropped because
//     Tor can't carry it. This is the safe default — no leaks possible.
//
//   - Transparent=false: just runs Tor with SocksPort. The launched app
//     must be proxy-aware (Firefox uses a SOCKS5 user.js, Chromium uses
//     --proxy-server). Apps that ignore proxies leak.
//
//   - SocksAddr set + reachable: skip launching a managed Tor and use
//     the supplied SOCKS address as Level-1 Tor. No transparent mode
//     in this case (Veil doesn't own the Tor instance).
package tor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mstampfli/veil/internal/backends"
	"github.com/mstampfli/veil/internal/logger"
	"github.com/mstampfli/veil/internal/profile"
)

type Backend struct {
	socksAddr          string // empty means "auto"
	managed            bool   // force managed even if a system tor would work
	transparent        bool   // install REDIRECT rules in the namespace
	useBridges         bool
	bridges            []string
	pluggableTransport string
	exitCountry        string // ISO-3166 alpha-2; empty = unrestricted

	mu          sync.Mutex
	cmd         *exec.Cmd
	dataDir     string
	persistDir  bool // true when dataDir is the per-profile persistent path
	socksPort   int
	transPort   int
	dnsPort     int
	controlPort int
	managedURL  string

	// natNs is the namespace name where we installed iptables nat
	// rules. Empty when no rules were installed.
	natNs string

	// torSourceIP is the secondary IP we add to the namespace's
	// veth (when running in the unprivileged user-ns engine path)
	// and bind tor's outbound to via OutboundBindAddress*. iptables
	// OUTPUT rules then exempt tor's traffic by `-s torSourceIP`
	// instead of by uid (we have no separate tor uid in user-ns).
	// Empty in legacy/root mode where uid-based exemption is used.
	torSourceIP string
}

// ControlInfo returns enough metadata for the CLI/GUI to talk to this
// Tor's control port.
func (b *Backend) ControlInfo() (port int, cookiePath string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.controlPort, controlCookiePath(b.dataDir)
}

// SocksPort returns the local SOCKS5 port Tor is bound to, or 0 if
// the backend hasn't started yet. Used by the engine to dial Tor
// directly (e.g. for the at-launch ipinfo cross-check) without going
// through the published Steering URL.
func (b *Backend) SocksPort() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.socksPort
}

// ExitCountry returns the ISO-3166 alpha-2 code the chain hop's
// tor_exit_country was set to (lowercased), or "" when no pin was
// requested. The engine reads this after Backend.Start completes to
// apply ExitNodes + StrictNodes via the control protocol from inside
// the netns where Tor's control port actually lives.
func (b *Backend) ExitCountry() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exitCountry
}

func controlCookiePath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return dataDir + "/control_auth_cookie"
}

func init() {
	backends.Register(profile.BackendTor, func(b profile.Backend) (backends.Backend, error) {
		// Transparent defaults to true (safer): force everything through
		// Tor in the namespace. Explicit false disables.
		transparent := true
		if b.Transparent != nil {
			transparent = *b.Transparent
		}
		return &Backend{
			socksAddr:          b.SocksAddr,
			managed:            b.ManagedTor,
			transparent:        transparent,
			useBridges:         b.UseBridges,
			bridges:            append([]string(nil), b.Bridges...),
			pluggableTransport: b.PluggableTransport,
			exitCountry:        strings.ToLower(strings.TrimSpace(b.TorExitCountry)),
		}, nil
	})
}

func (b *Backend) Kind() profile.BackendKind { return profile.BackendTor }

func (b *Backend) Start(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	hasUpstreamProxy := prev != nil && prev.ProxyURL != ""
	wantsManaged := b.managed || b.transparent || hasUpstreamProxy

	if !wantsManaged {
		// Try existing system Tor.
		if b.socksAddr != "" {
			if reachable(ctx, b.socksAddr) {
				logger.L().Info("tor: using existing socks", "addr", b.socksAddr)
				return &backends.Steering{ProxyURL: "socks5://" + b.socksAddr}, nil
			}
		}
		if reachable(ctx, "127.0.0.1:9050") {
			logger.L().Info("tor: using system tor at 127.0.0.1:9050")
			return &backends.Steering{ProxyURL: "socks5://127.0.0.1:9050"}, nil
		}
	}
	return b.startManaged(ctx, prev)
}

func reachable(ctx context.Context, addr string) bool {
	d := &net.Dialer{Timeout: 1 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (b *Backend) startManaged(ctx context.Context, prev *backends.Steering) (*backends.Steering, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd != nil {
		return &backends.Steering{ProxyURL: b.managedURL}, nil
	}

	binPath, err := exec.LookPath("tor")
	if err != nil {
		return nil, fmt.Errorf("system tor not running and `tor` binary not on PATH — install it (Debian/Parrot: sudo apt install tor)")
	}

	// Draw DISTINCT ports. pickPort is random, so four independent draws
	// can collide (~1 in 2700 launches); two Tor listeners sharing a port
	// makes Tor fail to bind one and the whole launch fail. Per-netns
	// loopback isolation rules out cross-profile collisions, but not
	// intra-launch duplicates. (dnsPort is forced to 53 below; drawing it
	// here keeps the remaining listeners distinct from that draw too.)
	ports, err := pickDistinctPorts(4)
	if err != nil {
		return nil, err
	}
	socksPort, transPort, dnsPort, controlPort := ports[0], ports[1], ports[2], ports[3]
	// Tor data dir: prefer a per-profile persistent path under the
	// profile's data dir, falling back to a /tmp tempdir when the
	// engine didn't supply a profile data dir (test paths, ad-hoc
	// CLI). Persistence matters for two reasons:
	//   1. cached-microdesc-consensus + cached-microdescs is ~50 MB
	//      that Tor would otherwise re-download on every launch. Cold
	//      bootstrap stalls past 90 s under any uplink contention;
	//      warm bootstrap finishes in 5–10 s.
	//   2. `state` holds the entry-guard set. Tor docs explicitly
	//      recommend persisting guards across restarts — random new
	//      guards every session weakens anonymity. Veil was rotating
	//      guards on every launch with the old MkdirTemp scheme.
	// The cache is self-validating: expired consensus is discarded,
	// missing descriptors get re-fetched, version-skew triggers a
	// warn + rebuild. Stale != broken.
	var dataDir string
	persistDir := false
	if profDir := backends.ProfileDataDirFrom(ctx); profDir != "" {
		dataDir = filepath.Join(profDir, "tor")
		// MkdirAll succeeds on a pre-existing dir, so it does NOT catch
		// a stale tor/ left owned by another user (e.g. debian-tor, from
		// an earlier root run's uid-drop) which we then can't write
		// torrc into. Verify we can actually write; if not, fall back to
		// a private temp dir instead of hard-failing the whole launch
		// (we lose only the warm consensus cache for this run).
		if err := os.MkdirAll(dataDir, 0o700); err != nil || !dirWritable(dataDir) {
			// The canonical tor/ dir is unwritable — almost always a
			// stale dir left owned by debian-tor by a pre-user-ns root
			// run's uid-drop. We can't chown/remove it (that uid isn't
			// mapped into our user-ns). A random temp dir works but
			// discards the warm consensus cache on EVERY launch, so tor
			// cold-bootstraps each time and occasionally misses the 90s
			// cap (the intermittent selftest failures). Prefer a STABLE
			// per-profile sibling dir we own, so the cache persists
			// across launches; only fall back to a temp dir if even that
			// can't be created.
			alt := filepath.Join(profDir, "tor-uns")
			if aerr := os.MkdirAll(alt, 0o700); aerr == nil && dirWritable(alt) {
				logger.L().Warn("tor: canonical data dir unwritable (stale owner); using stable per-profile fallback so the consensus cache persists",
					"stale", dataDir, "using", alt, "mkdir_err", err)
				dataDir = alt
				persistDir = true
			} else {
				logger.L().Warn("tor: persistent data dir not writable, using temp dir (stale owner from an old root run?)",
					"dir", dataDir, "mkdir_err", err, "alt_err", aerr)
				tmp, terr := os.MkdirTemp("", "veil-tor-")
				if terr != nil {
					return nil, fmt.Errorf("tor: persistent data dir %q unusable and temp fallback failed: %w", dataDir, terr)
				}
				dataDir = tmp
			}
		} else {
			persistDir = true
		}
	} else {
		var err error
		dataDir, err = os.MkdirTemp("", "veil-tor-")
		if err != nil {
			return nil, err
		}
	}

	// Warm-start ad-hoc (non-persistent) sessions from a shared
	// consensus cache so Tor validates and reuses a recent consensus
	// instead of re-downloading ~3.5MB every cold start (cuts bootstrap
	// from ~5-8s to ~2-3s). Only signed network documents are shared,
	// never the guard `state` file — guards stay per-session so distinct
	// profiles can't be correlated via a shared entry guard.
	if !persistDir {
		seedTorConsensusCache(dataDir)
	}

	// In transparent mode, disable IPv6 in the namespace BEFORE starting
	// tor so tor doesn't bind v6 listening sockets that we'd then have
	// to deal with.
	if b.transparent {
		if ns := backends.NamespaceFrom(ctx); ns != "" {
			disableIPv6(ns)
		}
	}

	torrcLines := []string{
		fmt.Sprintf("SocksPort 127.0.0.1:%d IsolateDestAddr", socksPort),
		fmt.Sprintf("ControlPort 127.0.0.1:%d", controlPort),
		"CookieAuthentication 1",
		"CookieAuthFileGroupReadable 1",
		"DataDirectory " + dataDir,
		"Log notice stdout",
		"AvoidDiskWrites 1",
		"ClientUseIPv6 1",
		"RunAsDaemon 0",
	}

	// User-ns engine path: we can't use --uid-owner for the iptables
	// exemption because debian-tor's uid isn't mapped in our user-ns.
	// Instead, set up a secondary IP that ONLY tor binds outbound to,
	// then use `-s SECONDARY` for the iptables exemption — distinguishes
	// tor's traffic from the browser's without needing a separate uid.
	if inUnprivilegedUserNS() {
		ns := backends.NamespaceFrom(ctx)
		if ns == "" {
			return nil, fmt.Errorf("tor in user-ns mode requires a network namespace (engine should have set one)")
		}
		secondaryIP, err := setupTorSecondaryIP(ns)
		if err != nil {
			return nil, fmt.Errorf("tor user-ns secondary IP setup: %w", err)
		}
		b.torSourceIP = secondaryIP
		torrcLines = append(torrcLines,
			"OutboundBindAddressOR "+secondaryIP,
			"OutboundBindAddressExit "+secondaryIP,
			"OutboundBindAddressPT "+secondaryIP,
		)
		logger.L().Info("tor: user-ns mode — using source-IP exemption",
			"source_ip", secondaryIP, "ns", ns)
	}

	// Bind Tor's DNSPort on the STANDARD port 53 in BOTH modes: the netns
	// resolver (resolv.conf -> nameserver 127.0.0.1) reaches it directly
	// over loopback with NO NAT. Without this, a non-transparent app that
	// resolves DNS LOCALLY — e.g. Chromium with --proxy-server=socks5://,
	// which does NOT proxy DNS — finds nothing listening on 127.0.0.1:53
	// and every lookup fails (curl exit 6). Binding 53 directly (rather
	// than REDIRECT-ing loopback :53 to a high DNSPort, which silently
	// fails because netfilter does not reliably NAT loopback->loopback)
	// makes those lookups resolve through Tor with no leak. The
	// non-transparent kill switch already allows loopback, so 127.0.0.1:53
	// is reachable. We are root inside the user-ns (and Tor binds its
	// listeners before any setuid in the legacy path), so binding 53 is
	// permitted.
	dnsPort = 53
	torrcLines = append(torrcLines, fmt.Sprintf("DNSPort 127.0.0.1:%d", dnsPort))

	// Transparent mode additionally binds TransPort and enables automap so
	// EVERY TCP connection (proxy-aware or not) and .onion name is forced
	// through Tor. AutomapHostsOnResolve hands out virtual IPs that only
	// the TransPort REDIRECT can route, so it stays transparent-only;
	// non-transparent .onion access goes through Tor's SOCKS port instead.
	// Optionally drop privileges to a tor user so we can exempt that uid
	// from the nat REDIRECT rules.
	torUID := -1
	if b.transparent {
		torrcLines = append(torrcLines,
			fmt.Sprintf("TransPort 127.0.0.1:%d IsolateDestAddr", transPort),
			"VirtualAddrNetworkIPv4 10.192.0.0/10",
			"AutomapHostsOnResolve 1",
		)
		// Skip the User+chown setuid dance when in user-ns mode —
		// the source-IP exemption above replaces it.
		if b.torSourceIP == "" {
			if uid := lookupTorUID(); uid != -1 {
				torrcLines = append(torrcLines, "User "+lookupTorUserName())
				// Tor needs the data dir owned by its target user to
				// avoid "Directory ... is not owned by this user" errors.
				_ = os.Chown(dataDir, uid, uid)
				torUID = uid
			} else {
				logger.L().Warn("tor: no tor/debian-tor system user — transparent mode will run tor as root and skip uid-exempt nat rules")
			}
		}
	}

	// Exit country pinning: do NOT write ExitNodes (or StrictNodes)
	// to torrc. Both are applied via control-port SETCONF AFTER
	// bootstrap completes. Empirically, ExitNodes in torrc changes
	// Tor's microdescriptor-fetch loop in ways that stall the
	// "Bootstrapped 50% (loading_descriptors)" phase on slower
	// chained transports (Tor over WG/OVPN). Bootstrapping pure-
	// default Tor avoids that stall entirely; the strict country
	// pin then takes effect the instant Bootstrapped 100% fires.
	// Net guarantee is the same: every user circuit built after
	// the post-bootstrap SETCONF refuses to exit anywhere except
	// the configured country.
	if b.exitCountry != "" {
		logger.L().Info("tor: pinning exit country (ExitNodes + StrictNodes both deferred to post-bootstrap SETCONF)",
			"country", b.exitCountry)
	}

	// Bridges: when enabled, push Bridge lines and an appropriate
	// ClientTransportPlugin so Tor uses pluggable transports instead of
	// connecting directly to its directory authorities.
	if b.useBridges && len(b.bridges) > 0 {
		torrcLines = append(torrcLines, "UseBridges 1")
		// If any bridge is obfs4 / snowflake / meek_lite, configure a
		// matching ClientTransportPlugin entry.
		transports := map[string]bool{}
		for _, br := range b.bridges {
			fields := strings.Fields(br)
			if len(fields) > 0 {
				transports[strings.ToLower(fields[0])] = true
			}
		}
		ptBin := b.pluggableTransport
		for t := range transports {
			switch t {
			case "obfs4", "obfs3", "scramblesuit":
				bin := ptBin
				if bin == "" {
					if p, err := exec.LookPath("obfs4proxy"); err == nil {
						bin = p
					}
				}
				if bin != "" {
					torrcLines = append(torrcLines, fmt.Sprintf("ClientTransportPlugin %s exec %s", t, bin))
				}
			case "snowflake":
				bin := ptBin
				if bin == "" {
					if p, err := exec.LookPath("snowflake-client"); err == nil {
						bin = p
					}
				}
				if bin != "" {
					torrcLines = append(torrcLines,
						fmt.Sprintf("ClientTransportPlugin snowflake exec %s -url https://snowflake-broker.torproject.net.global.prod.fastly.net/ -front foursquare.com -ice stun:stun.l.google.com:19302", bin))
				}
			case "meek_lite":
				bin := ptBin
				if bin == "" {
					if p, err := exec.LookPath("meek-client"); err == nil {
						bin = p
					}
				}
				if bin != "" {
					torrcLines = append(torrcLines, "ClientTransportPlugin meek_lite exec "+bin)
				}
			}
		}
		for _, br := range b.bridges {
			torrcLines = append(torrcLines, "Bridge "+br)
		}
		logger.L().Info("tor: using bridges", "count", len(b.bridges))
	}

	// Chain support: upstream proxy.
	if prev != nil && prev.ProxyURL != "" {
		if u, err := url.Parse(prev.ProxyURL); err == nil {
			switch strings.ToLower(u.Scheme) {
			case "socks5", "socks5h":
				torrcLines = append(torrcLines, "Socks5Proxy "+u.Host)
				if u.User != nil {
					torrcLines = append(torrcLines, "Socks5ProxyUsername "+u.User.Username())
					if pw, ok := u.User.Password(); ok {
						torrcLines = append(torrcLines, "Socks5ProxyPassword "+pw)
					}
				}
				logger.L().Info("tor: chaining via upstream socks5", "addr", u.Host)
			case "http", "https":
				torrcLines = append(torrcLines, "HTTPSProxy "+u.Host)
				if u.User != nil {
					pw, _ := u.User.Password()
					torrcLines = append(torrcLines, fmt.Sprintf("HTTPSProxyAuthenticator %s:%s", u.User.Username(), pw))
				}
				logger.L().Info("tor: chaining via upstream https proxy", "addr", u.Host)
			}
		}
	}

	torrc := strings.Join(torrcLines, "\n") + "\n"
	torrcPath := filepath.Join(dataDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		return nil, err
	}

	args := []string{"-f", torrcPath, "--quiet"}
	var cmd *exec.Cmd
	if ns := backends.NamespaceFrom(ctx); ns != "" {
		cmd = exec.Command("ip", append([]string{"netns", "exec", ns, binPath}, args...)...)
	} else {
		cmd = exec.Command(binPath, args...)
	}

	// HARD KILL on parent death. Without Pdeathsig the Tor process
	// outlives a crashed/SIGKILL'd veil-gui — we've seen 12+ orphan
	// Tor instances accumulate after rough sessions, each holding
	// memory + an open netns + iptables rules + control port. Ship
	// SIGKILL to Tor when our parent (the engine process) goes away.
	// Also Setpgid: 1 so the whole `ip netns exec → tor` group dies
	// together if we signal the leader.
	cmd.SysProcAttr = torSysProcAttr()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout

	logPath := filepath.Join(dataDir, "notices.log")
	logFile, _ := os.Create(logPath)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tor start: %w", err)
	}
	logger.L().Info("tor: starting managed instance",
		"socks", socksPort, "trans", transPort, "dns", dnsPort,
		"transparent", b.transparent, "datadir", dataDir, "log", logPath)

	b.cmd = cmd
	b.dataDir = dataDir
	b.persistDir = persistDir
	b.socksPort = socksPort
	b.transPort = transPort
	b.dnsPort = dnsPort
	b.controlPort = controlPort

	bootCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ready := make(chan struct{})
	failed := make(chan error, 1)

	var teeReader io.Reader = stdout
	if logFile != nil {
		teeReader = io.TeeReader(stdout, logFile)
	}
	// scanBootstrap also forwards progress lines to logger.L() so the
	// user sees live "Bootstrapped 25%, 50%, ..." in the GUI log
	// instead of staring at a frozen "starting tor".
	go scanBootstrap(teeReader, ready, failed)

	select {
	case <-ready:
	case err := <-failed:
		_ = cmd.Process.Kill()
		// Keep dataDir / log on failure — error message points the
		// user there for diagnosis. We only clean up the SUCCESS
		// path's stale dirs (handled in Stop / process exit hooks).
		b.cmd = nil
		return nil, fmt.Errorf("%w (see %s)", err, logPath)
	case <-bootCtx.Done():
		_ = cmd.Process.Kill()
		b.cmd = nil
		return nil, fmt.Errorf("tor failed to bootstrap within 90s — log preserved at %s; ExitNodes pin = %q; check log for which Bootstrapped %% it stalled at", logPath, b.exitCountry)
	}

	b.managedURL = fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)

	// Country-pin SETCONF used to live here, but dialing 127.0.0.1
	// from this code path hits the engine's loopback — NOT the
	// netns where Tor actually binds its control port. The engine
	// applies the pin via runInNetns after the chain is fully up.
	// See linuxEngine.applyTorCountryPin / usernsChild's equivalent.

	// Install REDIRECT nat rules + UDP DROP rules in the namespace.
	if b.transparent {
		ns := backends.NamespaceFrom(ctx)
		if ns == "" {
			logger.L().Warn("tor: transparent requested but no namespace — skipping nat rules")
		} else {
			if err := b.installNatRules(ns, torUID); err != nil {
				_ = cmd.Process.Kill()
				// Don't RemoveAll — the persistent profile data dir
				// holds Tor's cache (consensus, descriptors, guards).
				// Wiping it would force a slow re-bootstrap next try.
				b.cmd = nil
				return nil, fmt.Errorf("install non-transparent rules: %w", err)
			}
			b.natNs = ns
		}
	} else {
		// Non-transparent kill switch: SOCKS-aware apps go through Tor
		// via 127.0.0.1:SocksPort, but non-SOCKS apps would route
		// directly via the netns's default route, leaking the host's
		// real IP. We drop everything outbound EXCEPT loopback and
		// Tor's own UID, so non-SOCKS apps just have no internet
		// (kill-switched) while SOCKS-aware apps still work through
		// Tor. DNS is already safe — resolv.conf points at
		// 127.0.0.1:DNSPort (see dnsForTransparent above).
		ns := backends.NamespaceFrom(ctx)
		if ns != "" {
			// Fail CLOSED, like the transparent nat path above: the kill
			// switch is the only thing stopping a non-SOCKS app from
			// routing out the netns default route and leaking the real
			// IP. If it can't install (partial rules are rolled back, so
			// none remain), refuse to run rather than proceed unprotected
			// — matches this mode's stated philosophy below.
			if err := b.installNonTransparentKillSwitch(ns, torUID); err != nil {
				_ = cmd.Process.Kill()
				b.cmd = nil
				return nil, fmt.Errorf("tor non-transparent kill switch install failed (refusing to run: non-SOCKS apps would leak the real IP): %w", err)
			}
			b.natNs = ns
		}
	}

	logger.L().Info("tor: bootstrap complete", "url", b.managedURL, "transparent", b.transparent)
	// Refresh the shared consensus cache from this just-bootstrapped
	// session so the next ad-hoc launch warm-starts. Rate-limited inside
	// saveTorConsensusCache so concurrent sessions don't thrash ~15MB.
	if !persistDir {
		saveTorConsensusCache(dataDir)
	}
	return &backends.Steering{
		ProxyURL: b.managedURL,
		// DNS inside the namespace should resolve to localhost so
		// /etc/resolv.conf hits DNSPort. (REDIRECT rules also catch
		// any DNS aimed elsewhere, but this saves a round-trip.)
		DNS: dnsForTransparent(b.transparent),
	}, nil
}

func dnsForTransparent(t bool) []string {
	// Point /etc/resolv.conf at 127.0.0.1 in BOTH modes. Tor's DNSPort is
	// now bound on 127.0.0.1:53 in both transparent and non-transparent
	// mode (see the unconditional DNSPort line in startManaged), so this
	// routes every system-resolver DNS query inside the netns through Tor.
	//
	// Why this matters in non-transparent mode: SOCKS-aware browsers
	// like Firefox honor socks_remote_dns and resolve via the SOCKS
	// proxy (Tor). But Chromium-family with --proxy-server=socks5://
	// resolves DNS LOCALLY by default — meaning if /etc/resolv.conf
	// points at the host's DNS or a WG-pushed resolver, DNS leaks
	// out the netns's default route, bypassing Tor. Pointing
	// resolv.conf at 127.0.0.1 forces every system-resolver lookup
	// through Tor's DNSPort. No SOCKS-DNS-aware browser config
	// needed. No leak.
	//
	// _ argument t kept for compat; both branches return same value.
	_ = t
	return []string{"127.0.0.1"}
}

// installNonTransparentKillSwitch sets up minimal iptables for a Tor
// session running in non-transparent mode. Only Tor's own outbound
// (uid match) and loopback escape; everything else from the netns is
// dropped. SOCKS-aware apps connecting to 127.0.0.1:SocksPort still
// work — that's loopback. Non-SOCKS apps lose internet — that's the
// kill switch (failing closed = correct behavior; better than
// leaking the real IP).
func (b *Backend) installNonTransparentKillSwitch(ns string, torUID int) error {
	// Belt-and-suspenders ip6tables drop all v6 traffic.
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		args := []string{"netns", "exec", ns, "ip6tables", "-w", "5", "-P", chain, "DROP"}
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			logger.L().Warn("ip6tables policy DROP failed", "chain", chain, "err", err, "out", string(out))
		}
	}

	rules := [][]string{
		// Allow loopback (SOCKS-aware apps reach Tor at 127.0.0.1).
		{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
	}
	switch {
	case b.torSourceIP != "":
		// User-ns mode: tor binds outbound to a dedicated secondary
		// IP. Exempt by source IP rather than uid — same effect, no
		// separate uid required.
		rules = append(rules, []string{
			"-A", "OUTPUT", "-s", b.torSourceIP, "-j", "ACCEPT",
		})
	case torUID >= 0:
		// Legacy mode: exempt by tor's uid.
		rules = append(rules, []string{
			"-A", "OUTPUT",
			"-m", "owner", "--uid-owner", strconv.Itoa(torUID),
			"-j", "ACCEPT",
		})
	}
	// Drop everything else outbound — non-SOCKS apps die here.
	rules = append(rules, []string{"-A", "OUTPUT", "-j", "REJECT", "--reject-with", "icmp-net-unreachable"})

	for _, r := range rules {
		args := append([]string{"netns", "exec", ns, "iptables", "-w", "5"}, r...)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			_ = b.removeNonTransparentKillSwitch(ns, torUID)
			return fmt.Errorf("iptables %v: %s: %w", r, string(out), err)
		}
	}
	logger.L().Info("tor: non-transparent kill switch installed", "ns", ns, "tor_uid", torUID)
	return nil
}

func (b *Backend) removeNonTransparentKillSwitch(ns string, torUID int) error {
	// Walk the same rule set in reverse with -D to drop them.
	rules := [][]string{
		{"-D", "OUTPUT", "-j", "REJECT", "--reject-with", "icmp-net-unreachable"},
	}
	switch {
	case b.torSourceIP != "":
		rules = append(rules, []string{"-D", "OUTPUT", "-s", b.torSourceIP, "-j", "ACCEPT"})
	case torUID >= 0:
		rules = append(rules, []string{
			"-D", "OUTPUT",
			"-m", "owner", "--uid-owner", strconv.Itoa(torUID),
			"-j", "ACCEPT",
		})
	}
	rules = append(rules, []string{"-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"})
	for _, r := range rules {
		args := append([]string{"netns", "exec", ns, "iptables", "-w", "5"}, r...)
		_ = exec.Command("ip", args...).Run()
	}
	return nil
}

// installNatRules installs REDIRECT + UDP-DROP rules in the namespace so
// all TCP and DNS go through Tor's TransPort/DNSPort. IPv6 was disabled
// before tor started; here we add ip6tables policy DROP as a backstop in
// case any v6 stack remains addressable.
func (b *Backend) installNatRules(ns string, torUID int) error {
	// Belt-and-suspenders ip6tables drop all v6 traffic in case sysctl
	// disable_ipv6 didn't fully take effect.
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		args := []string{"netns", "exec", ns, "ip6tables", "-w", "5", "-P", chain, "DROP"}
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			logger.L().Warn("ip6tables policy DROP failed", "chain", chain, "err", err, "out", string(out))
		}
	}

	// Allow the externally-addressed DNS REDIRECT (non-loopback :53 ->
	// 127.0.0.1:53) to deliver: a non-loopback -> loopback DNAT needs
	// route_localnet on the interface. Harmless inside the isolated
	// netns; best-effort (loopback resolv.conf works without it).
	_ = exec.Command("ip", "netns", "exec", ns, "sysctl", "-w",
		"net.ipv4.conf.all.route_localnet=1").Run()

	rules := buildTransparentRules(b.transPort, b.dnsPort, torUID, b.torSourceIP)
	for _, r := range rules {
		args := append([]string{"netns", "exec", ns, "iptables", "-w", "5"}, r...)
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			_ = b.removeNatRules(ns, torUID)
			return fmt.Errorf("iptables %v: %s: %w", r, string(out), err)
		}
	}
	logger.L().Info("tor: transparent rules installed", "ns", ns, "tor_uid", torUID,
		"trans_port", b.transPort, "dns_port", b.dnsPort, "ipv6", "disabled")
	return nil
}

func (b *Backend) removeNatRules(ns string, torUID int) error {
	rules := buildTransparentRules(b.transPort, b.dnsPort, torUID, b.torSourceIP)
	for i := len(rules) - 1; i >= 0; i-- {
		del := toDeleteForm(rules[i])
		if del == nil {
			continue
		}
		args := append([]string{"netns", "exec", ns, "iptables", "-w", "5"}, del...)
		_ = exec.Command("ip", args...).Run()
	}
	// IPv6 sysctls are inside the namespace; namespace teardown drops
	// them, so no explicit re-enable here.
	return nil
}

// buildTransparentRules returns the iptables rule sets for transparent
// Tor. Each rule is in -A/-I form; toDeleteForm produces the matching
// -D form for cleanup.
func buildTransparentRules(transPort, dnsPort, torUID int, torSourceIP string) [][]string {
	rules := [][]string{
		// Loopback exempt FIRST: the netns resolver points at
		// 127.0.0.1 and Tor's DNSPort listens there on :53, so loopback
		// DNS must reach Tor DIRECTLY without NAT (netfilter does not
		// reliably NAT loopback->loopback traffic). This also lets
		// SOCKS-aware apps reach 127.0.0.1:SocksPort.
		{"-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "RETURN"},
	}
	// Exempt tor's own outbound traffic so it doesn't redirect to itself.
	switch {
	case torSourceIP != "":
		rules = append(rules, []string{
			"-t", "nat", "-A", "OUTPUT", "-s", torSourceIP, "-j", "RETURN",
		})
	case torUID != -1:
		rules = append(rules, []string{
			"-t", "nat", "-A", "OUTPUT",
			"-m", "owner", "--uid-owner", strconv.Itoa(torUID),
			"-j", "RETURN",
		})
	}
	rules = append(rules,
		// Apps that hardcode an external resolver (ignoring resolv.conf)
		// are still captured: redirect any non-loopback :53 to Tor's
		// DNSPort. The external->loopback DNAT needs route_localnet=1
		// (set in installNatRules). Both UDP and TCP DNS.
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(dnsPort)},
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(dnsPort)},
		// All remaining TCP → TransPort.
		[]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(transPort)},
		// Allow loopback UDP (filter table) so DNS reaches Tor's DNSPort
		// on 127.0.0.1:53 — both the resolv.conf path and any external
		// DNS DNAT'd to loopback. MUST precede the blanket UDP drop
		// below, which otherwise REJECTs the lookup (icmp-port-unreach →
		// curl exit 6). Loopback can't leak to the real uplink.
		[]string{"-A", "OUTPUT", "-o", "lo", "-p", "udp", "-j", "ACCEPT"},
		// Drop all other UDP. Tor can't carry UDP — leaving it unblocked
		// would let things like WebRTC, QUIC and BitTorrent leak.
		[]string{"-A", "OUTPUT", "-p", "udp", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
	)
	return rules
}

// toDeleteForm rewrites an iptables ADD form (-A or -I) into its DELETE
// form. Returns nil if the rule has no recognizable add op.
func toDeleteForm(r []string) []string {
	out := make([]string, 0, len(r))
	swapped := false
	for i := 0; i < len(r); i++ {
		t := r[i]
		switch t {
		case "-I":
			out = append(out, "-D")
			if i+1 < len(r) {
				out = append(out, r[i+1])
				i++
			}
			if i+1 < len(r) {
				if _, err := strconv.Atoi(r[i+1]); err == nil {
					i++
				}
			}
			swapped = true
		case "-A":
			out = append(out, "-D")
			swapped = true
		default:
			out = append(out, t)
		}
	}
	if !swapped {
		return nil
	}
	return out
}

// disableIPv6 turns off the v6 stack inside the namespace so apps can't
// resolve AAAA records and connect over v6 (bypassing the v4 REDIRECT
// rules used for transparent Tor). Best-effort: each sysctl that fails
// is logged but doesn't abort the launch — the ip6tables backstop in
// installNatRules catches anything that slips through.
func disableIPv6(ns string) {
	for _, k := range []string{
		"net.ipv6.conf.all.disable_ipv6",
		"net.ipv6.conf.default.disable_ipv6",
		"net.ipv6.conf.lo.disable_ipv6",
	} {
		args := []string{"netns", "exec", ns, "sysctl", "-w", k + "=1"}
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			logger.L().Warn("ipv6 disable failed", "key", k, "err", err, "out", string(out))
		}
	}
	logger.L().Info("ipv6 disabled in namespace", "ns", ns)
}

// torConsensusFiles are the signed, self-validating Tor network
// documents safe to share across profiles for warm-start. The guard
// `state` file and identity keys are deliberately excluded — sharing
// them would correlate otherwise-independent profiles.
var torConsensusFiles = []string{
	"cached-microdesc-consensus",
	"cached-microdescs",
	"cached-microdescs.new",
	"cached-certs",
}

// torSharedConsensusDir is the cross-profile cache of Tor consensus
// material used to warm-start ad-hoc sessions. Empty if no user cache
// dir is resolvable (warm-start then degrades to a normal cold start).
func torSharedConsensusDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "veil", "tor-consensus")
}

// seedTorConsensusCache copies shared consensus material into a fresh
// Tor data dir so Tor reuses it instead of downloading the full
// consensus. Best-effort: a missing/torn file just means Tor discards
// it and cold-bootstraps as normal (the documents are signed, so a bad
// copy can't poison the session).
func seedTorConsensusCache(dataDir string) {
	src := torSharedConsensusDir()
	if src == "" {
		return
	}
	for _, name := range torConsensusFiles {
		_ = copyFileTrunc(filepath.Join(src, name), filepath.Join(dataDir, name))
	}
}

// saveTorConsensusCache refreshes the shared cache from a freshly
// bootstrapped data dir. Rate-limited to ~30 min (the consensus is
// valid for hours; copying ~15MB on every teardown would be wasteful)
// and written atomically so a concurrent seeder never reads a torn file.
func saveTorConsensusCache(dataDir string) {
	dst := torSharedConsensusDir()
	if dst == "" {
		return
	}
	marker := filepath.Join(dst, "cached-microdesc-consensus")
	if fi, err := os.Stat(marker); err == nil && time.Since(fi.ModTime()) < 30*time.Minute {
		return
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return
	}
	for _, name := range torConsensusFiles {
		_ = copyFileAtomic(filepath.Join(dataDir, name), filepath.Join(dst, name))
	}
}

// copyFileTrunc copies src over dst (truncating). Returns an error if
// src can't be read or dst can't be written; callers treat it as
// best-effort.
func copyFileTrunc(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyFileAtomic copies src to dst via a temp file + rename so a
// concurrent reader sees either the old or the new file, never a
// partial one.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".veil-tor-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dst)
}

// dirWritable reports whether we can create a file in dir. Used to
// detect a stale tor data dir owned by another user (which MkdirAll
// silently accepts) before Tor fails opaquely writing its torrc.
func dirWritable(dir string) bool {
	probe := filepath.Join(dir, ".veil-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

func lookupTorUserName() string {
	for _, n := range []string{"debian-tor", "tor", "_tor"} {
		if _, err := osuser.Lookup(n); err == nil {
			return n
		}
	}
	return ""
}

func lookupTorUID() int {
	name := lookupTorUserName()
	if name == "" {
		return -1
	}
	u, err := osuser.Lookup(name)
	if err != nil {
		return -1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1
	}
	return uid
}

// scanBootstrap watches tor stdout for "Bootstrapped 100%" and signals
// ready. Sends to failed if tor exits before bootstrapping. Forwards
// only bootstrap-progress + warn/err lines to logger so the GUI log
// shows status without being flooded with every Tor notice.
func scanBootstrap(r io.Reader, ready chan<- struct{}, failed chan<- error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 8192), 1<<20)
	bootstrapped := false
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.Contains(line, "[err]"):
			logger.L().Error("tor", "line", line)
		case strings.Contains(line, "[warn]"):
			logger.L().Warn("tor", "line", line)
		case strings.Contains(line, "Bootstrapped"):
			logger.L().Info("tor bootstrap", "line", line)
		}
		if !bootstrapped && strings.Contains(line, "Bootstrapped 100%") {
			bootstrapped = true
			close(ready)
		}
	}
	if !bootstrapped {
		select {
		case failed <- fmt.Errorf("tor exited before bootstrapping"):
		default:
		}
	}
}

func pickPort() (int, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	p := int(binary.BigEndian.Uint16(b[:]))%(65535-49152) + 49152
	return p, nil
}

// pickDistinctPorts returns n mutually distinct random ephemeral ports so
// no two Tor listeners are assigned the same port.
func pickDistinctPorts(n int) ([]int, error) {
	seen := make(map[int]bool, n)
	out := make([]int, 0, n)
	for len(out) < n {
		p, err := pickPort()
		if err != nil {
			return nil, err
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

func (b *Backend) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Remove the nat rules first so traffic stops being redirected to
	// a tor that's about to die. natNs is set in both transparent
	// (REDIRECT rules) and non-transparent (kill switch) modes; try
	// both removers — each is idempotent and silent on no-op.
	if b.natNs != "" {
		uid := lookupTorUID()
		if b.transparent {
			_ = b.removeNatRules(b.natNs, uid)
		} else {
			_ = b.removeNonTransparentKillSwitch(b.natNs, uid)
		}
		b.natNs = ""
	}

	if b.cmd != nil && b.cmd.Process != nil {
		// SIGINT first, then escalate. Tor responds to SIGINT with a
		// clean shutdown if it can; if not, we don't wait long.
		_ = b.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = b.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			// Don't wait the full 3s — multi-hop chains where the
			// next-hop tunnel is also tearing down will block Tor's
			// last-gasp network ops. Just kill.
			_ = b.cmd.Process.Kill()
			// One more brief wait so the kernel actually reaps the
			// process before we touch its data dir.
			select {
			case <-done:
			case <-time.After(300 * time.Millisecond):
			}
		}
		b.cmd = nil
	}
	// Persistent per-profile data dir: KEEP it. cached-microdescs +
	// state (entry guards) is the whole point — wiping it on Stop
	// puts us back to the cold-bootstrap stall this fix exists to
	// avoid. Just clear our handle so repeat Stop calls are no-ops.
	//
	// Legacy /tmp tempdir path: still RemoveAll, off the critical
	// path. Tor caches enough that RemoveAll on btrfs can take a
	// few seconds; user's Stop shouldn't block on it.
	if dir := b.dataDir; dir != "" {
		legacy := !b.persistDir
		b.dataDir = ""
		b.persistDir = false
		if legacy {
			go func() {
				_ = os.RemoveAll(dir)
			}()
		}
	}
	return nil
}

func (b *Backend) Status() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd != nil {
		mode := "socks-only"
		if b.transparent {
			mode = "transparent"
		}
		return fmt.Sprintf("tor (managed, %s) socks=:%d trans=:%d dns=:%d",
			mode, b.socksPort, b.transPort, b.dnsPort)
	}
	if b.socksAddr != "" {
		return "tor via " + b.socksAddr
	}
	return "tor stopped"
}

// setupTorSecondaryIP allocates a deterministic /32 IP from
// 10.249.0.0/16, attaches it to the inner netns's primary veth as
// an alias, and adds an iptables MASQUERADE rule for it inside the
// netns.
//
// Why: in the user-ns engine path we can't use --uid-owner for the
// iptables exemption that distinguishes tor's outbound from other
// apps' (no separate uid available). Source-IP exemption is the
// substitute. Tor binds OutboundBindAddress* to this secondary IP;
// other apps in the netns use the primary IP. iptables rules then
// match by `-s SECONDARY` instead of `--uid-owner`.
//
// The MASQUERADE rule rewrites the source from SECONDARY back to
// the netns's primary IP on egress, so the engine's existing
// per-namespace MASQUERADE (which matches the primary subnet)
// catches it on the way to the wire — no need to wire the
// secondary subnet through the bridge or host iptables.
func setupTorSecondaryIP(ns string) (string, error) {
	// Find the netns's default-route interface (the engine's veth peer).
	out, err := exec.Command("ip", "netns", "exec", ns,
		"ip", "-o", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("read netns default route: %w", err)
	}
	iface := ""
	for _, fld := range strings.Fields(string(out)) {
		if iface == "skip" {
			iface = fld
			break
		}
		if fld == "dev" {
			iface = "skip"
		}
	}
	if iface == "" || iface == "skip" {
		return "", fmt.Errorf("no default-route interface in netns %s (got: %s)", ns, strings.TrimSpace(string(out)))
	}

	// Pick a /32 from 10.249.0.0/16. Seed the starting point from the
	// netns name (stable per profile), then probe FORWARD until one is
	// free. A chain with more than one tor hop (tor -> tor, wg -> tor ->
	// ... -> tor) shares a single netns, so each hop needs a DISTINCT
	// source IP — the first candidate is already assigned by the
	// sibling hop (or a stale alias from a crashed run), so we advance
	// to the next. Without this, the second tor hop died with
	// "ip addr add: Address already assigned".
	h := fnv.New32()
	_, _ = h.Write([]byte(ns))
	base := h.Sum32()
	secondaryIP := ""
	for i := uint32(0); i < 256; i++ {
		v := base + i
		cand := fmt.Sprintf("10.249.%d.%d", (v>>8)&0xff, v&0xff)
		addArgs := []string{"netns", "exec", ns, "ip", "addr", "add", cand + "/32", "dev", iface}
		out, err := exec.Command("ip", addArgs...).CombinedOutput()
		if err == nil {
			secondaryIP = cand
			break
		}
		if strings.Contains(string(out), "File exists") || strings.Contains(string(out), "Address already assigned") {
			continue // taken by a sibling hop / stale alias — try the next
		}
		return "", fmt.Errorf("ip addr add %s: %s: %w", cand, strings.TrimSpace(string(out)), err)
	}
	if secondaryIP == "" {
		return "", fmt.Errorf("no free tor secondary IP in 10.249.0.0/16 for netns %s", ns)
	}

	// MASQUERADE rule: rewrite source from SECONDARY → veth's primary
	// IP on egress, so the engine's per-namespace MASQUERADE catches
	// it. -t nat -A POSTROUTING. Idempotent: pre-delete then add.
	delArgs := []string{
		"netns", "exec", ns, "iptables", "-w", "5",
		"-t", "nat", "-D", "POSTROUTING",
		"-s", secondaryIP + "/32", "-o", iface, "-j", "MASQUERADE",
	}
	for i := 0; i < 8; i++ {
		if err := exec.Command("ip", delArgs...).Run(); err != nil {
			break
		}
	}
	addRule := []string{
		"netns", "exec", ns, "iptables", "-w", "5",
		"-t", "nat", "-A", "POSTROUTING",
		"-s", secondaryIP + "/32", "-o", iface, "-j", "MASQUERADE",
	}
	if out, err := exec.Command("ip", addRule...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("iptables MASQUERADE for %s: %s: %w", secondaryIP, strings.TrimSpace(string(out)), err)
	}
	return secondaryIP, nil
}

// inUnprivilegedUserNS reports whether the current process is in a
// user namespace where uid 0 inside the namespace maps to a non-zero
// host uid — that is, the user-ns engine path. /proc/self/uid_map
// for ns id 0 maps to a non-zero host id only when we have been
// unshared with a non-identity mapping.
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
