// veil-bridge — minimum-privilege helper for the host-side veth + NAT
// setup that a user-namespaced Veil engine cannot do itself.
//
// Why this exists separately from the main `veil` binary:
//
//   The new Veil isolation model runs the engine inside an unprivileged
//   user namespace + net namespace + time namespace. That gives the
//   engine "fake root" inside the namespaces — netns plumbing, iptables,
//   NFQUEUE, etc. all work as if it were root. But it cannot create a
//   veth pair where one end attaches to the host's network device:
//   that requires CAP_NET_ADMIN on the HOST, which the user namespace
//   doesn't grant.
//
//   This binary is the only thing in Veil that holds CAP_NET_ADMIN on
//   the host (via `setcap cap_net_admin+ep`). Everything else runs
//   unprivileged. Keep this small, auditable, and side-effect-bounded:
//
//     - Only operates on devices it created (name prefix "veil-").
//     - Refuses to touch interfaces or rules outside that pattern.
//     - Subcommand-style: each invocation does one thing and exits.
//     - JSON-only output so callers can parse without ambiguity.
//
// Subcommands:
//
//   create-veth --profile NAME --host-cidr A.B.C.D/30 --ns-cidr A.B.C.E/30 --ns-pid PID
//     Creates two veth devices named "veil-<hash>0" / "veil-<hash>1".
//     Assigns host-cidr to the host end, brings it up, and moves the
//     peer end into the netns of the given pid. The caller (engine
//     inside the user-ns) configures the peer end's address and routes.
//
//   remove-veth --profile NAME
//     Idempotently removes the host-side veth device for a profile.
//
//   add-nat --subnet A.B.C.0/24 --iface eth0
//     Adds the FORWARD ACCEPT pair + POSTROUTING MASQUERADE rule that
//     lets traffic from the namespace reach the WAN.
//
//   remove-nat --subnet A.B.C.0/24 --iface eth0
//     Removes the rules added by add-nat. Idempotent.
//
//   doctor
//     Self-test: prints whether this binary holds CAP_NET_ADMIN, lists
//     veil-* devices currently present, and exits 0 if usable.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/mstampfli/veil/internal/osutil"
)

// Versioned name prefix Veil uses for every device this helper
// creates. The bridge refuses to operate on names that don't match,
// so a misuse can't accidentally rename or delete the user's eth0.
const veilDevicePrefix = "veil-"

// nameRE bounds what we accept as a profile name. Same shape as
// internal/profile name regex. Keeps device names sane (the kernel
// has a 15-char limit on interface names) and rejects shell
// metacharacters before they reach iptables.
var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,30}$`)

func main() {
	// veil-bridge is invoked from veil-gui which itself may have
	// been launched with a stripped PATH. iptables lives in
	// /usr/sbin on most distros — make sure we can find it.
	osutil.EnsureSysPath()
	osutil.EnsureIPTablesLock()

	// File capabilities (cap_net_admin+ep) put us in
	// permitted+effective. But child processes we exec — like
	// iptables — only inherit caps via the AMBIENT set. Without
	// this, iptables exec'd from here runs as plain user 1000 and
	// fails with "you must be root" even though we have the cap.
	// Print failures to stderr so they're visible in journalctl.
	if err := raiseAmbientCapNetAdmin(); err != nil {
		fmt.Fprintln(os.Stderr,
			"veil-bridge: ambient-cap raise failed:", err)
	}

	if len(os.Args) < 2 {
		usageAndExit()
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	var out any

	switch sub {
	case "create-veth":
		out, err = cmdCreateVeth(args)
	case "remove-veth":
		out, err = cmdRemoveVeth(args)
	case "add-nat":
		out, err = cmdAddNAT(args)
	case "remove-nat":
		out, err = cmdRemoveNAT(args)
	case "doctor":
		out, err = cmdDoctor(args)
	case "caps":
		out, err = cmdCaps(args)
	case "selftest":
		out, err = cmdSelftest(args)
	case "-h", "--help", "help":
		usageAndExit()
	default:
		fail(fmt.Errorf("unknown subcommand %q (run with --help)", sub))
	}
	if err != nil {
		fail(err)
	}
	if out != nil {
		_ = json.NewEncoder(os.Stdout).Encode(out)
	}
}

// vethNames derives the deterministic host-side and peer-side veth
// names for a profile. Same hash function as the engine's existing
// createVethPair so that a user-ns engine looking up its own veth by
// name finds what the bridge created.
func vethNames(profile string) (host, peer string) {
	h := fnv.New32()
	_, _ = h.Write([]byte(profile))
	hash := h.Sum32() % 0xffff
	return fmt.Sprintf("%s%x0", veilDevicePrefix, hash),
		fmt.Sprintf("%s%x1", veilDevicePrefix, hash)
}

// ---------- create-veth ----------

func cmdCreateVeth(args []string) (any, error) {
	fs := flag.NewFlagSet("create-veth", flag.ContinueOnError)
	profile := fs.String("profile", "", "profile name (alphanumeric+_-)")
	hostCIDR := fs.String("host-cidr", "", "host-side address with /30 mask, e.g. 10.13.0.1/30")
	nsCIDR := fs.String("ns-cidr", "", "namespace-side address with /30 mask, e.g. 10.13.0.2/30")
	nsPID := fs.Int("ns-pid", 0, "PID of a process whose net-ns the peer device is moved into")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(*profile) {
		return nil, fmt.Errorf("invalid --profile (must match %s)", nameRE.String())
	}
	if *nsPID <= 0 {
		return nil, fmt.Errorf("--ns-pid required and must be > 0")
	}
	hIP, hNet, err := net.ParseCIDR(*hostCIDR)
	if err != nil {
		return nil, fmt.Errorf("--host-cidr: %w", err)
	}
	if hSize, _ := hNet.Mask.Size(); hSize != 30 {
		return nil, fmt.Errorf("--host-cidr must be /30 (got /%d)", hSize)
	}
	_, _, err = net.ParseCIDR(*nsCIDR) // peer end configured by engine; we just validate format
	if err != nil {
		return nil, fmt.Errorf("--ns-cidr: %w", err)
	}

	hostDev, peerDev := vethNames(*profile)

	// Defensive teardown of stale device with the same name (last run
	// crashed before remove-veth ran). Same fail-soft pattern as the
	// existing engine.
	if old, err := netlink.LinkByName(hostDev); err == nil {
		_ = netlink.LinkDel(old)
	}

	la := netlink.NewLinkAttrs()
	la.Name = hostDev
	veth := &netlink.Veth{LinkAttrs: la, PeerName: peerDev}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("veth add: %w", err)
	}

	// Configure host-side address + bring up.
	host, err := netlink.LinkByName(hostDev)
	if err != nil {
		return nil, fmt.Errorf("lookup host veth: %w", err)
	}
	if err := netlink.AddrAdd(host, &netlink.Addr{IPNet: &net.IPNet{IP: hIP, Mask: hNet.Mask}}); err != nil {
		_ = netlink.LinkDel(host)
		return nil, fmt.Errorf("host addr add: %w", err)
	}
	if err := netlink.LinkSetUp(host); err != nil {
		_ = netlink.LinkDel(host)
		return nil, fmt.Errorf("host link up: %w", err)
	}

	// Move peer end into target netns. We open the netns by /proc path
	// rather than netns name because the engine, running inside an
	// unprivileged user-ns, has no /var/run/netns mount of its own.
	nsPath := fmt.Sprintf("/proc/%d/ns/net", *nsPID)
	nsFile, err := os.Open(nsPath)
	if err != nil {
		_ = netlink.LinkDel(host)
		return nil, fmt.Errorf("open ns %s: %w", nsPath, err)
	}
	defer nsFile.Close()

	peer, err := netlink.LinkByName(peerDev)
	if err != nil {
		_ = netlink.LinkDel(host)
		return nil, fmt.Errorf("lookup peer veth: %w", err)
	}
	if err := netlink.LinkSetNsFd(peer, int(nsFile.Fd())); err != nil {
		_ = netlink.LinkDel(host)
		return nil, fmt.Errorf("move peer to ns: %w", err)
	}

	return map[string]any{
		"profile":      *profile,
		"host_dev":     hostDev,
		"peer_dev":     peerDev,
		"host_address": hIP.String(),
		"ns_pid":       *nsPID,
	}, nil
}

// ---------- remove-veth ----------

func cmdRemoveVeth(args []string) (any, error) {
	fs := flag.NewFlagSet("remove-veth", flag.ContinueOnError)
	profile := fs.String("profile", "", "profile name")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if !nameRE.MatchString(*profile) {
		return nil, fmt.Errorf("invalid --profile")
	}
	hostDev, _ := vethNames(*profile)
	link, err := netlink.LinkByName(hostDev)
	if err != nil {
		// Not present — idempotent success. Distinguish "not found"
		// from other errors by string match because netlink doesn't
		// expose a typed sentinel here.
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such") {
			return map[string]any{"profile": *profile, "removed": false, "note": "not present"}, nil
		}
		return nil, fmt.Errorf("lookup veth: %w", err)
	}
	if !strings.HasPrefix(link.Attrs().Name, veilDevicePrefix) {
		return nil, fmt.Errorf("refusing to delete non-Veil device %q", link.Attrs().Name)
	}
	if err := netlink.LinkDel(link); err != nil {
		return nil, fmt.Errorf("link del: %w", err)
	}
	return map[string]any{"profile": *profile, "removed": true, "host_dev": hostDev}, nil
}

// ---------- add-nat / remove-nat ----------

// validateSubnet rejects anything that isn't a private IPv4 /N. We
// don't ever NAT 0.0.0.0/0 or any public subnet — that would be a
// reachable misuse vector for a setcap binary.
func validateSubnet(s string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("--subnet: %w", err)
	}
	if !n.IP.IsPrivate() {
		return nil, fmt.Errorf("--subnet must be RFC1918 private (10/8, 172.16/12, 192.168/16)")
	}
	return n, nil
}

// validateIface accepts only kernel-shape interface names. iptables
// normally validates this too, but we want the rejection to come
// before exec.
var ifaceRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

func validateIface(s string) error {
	if !ifaceRE.MatchString(s) {
		return fmt.Errorf("--iface %q rejected (kernel name shape)", s)
	}
	return nil
}

func cmdAddNAT(args []string) (any, error) {
	fs := flag.NewFlagSet("add-nat", flag.ContinueOnError)
	subnet := fs.String("subnet", "", "private subnet to MASQUERADE, e.g. 10.13.0.0/30")
	iface := fs.String("iface", "", "WAN interface to MASQUERADE through, e.g. eth0")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	n, err := validateSubnet(*subnet)
	if err != nil {
		return nil, err
	}
	if err := validateIface(*iface); err != nil {
		return nil, err
	}
	cidr := n.String()
	// All rule changes go through a single in-process netlink
	// connection (see nft_linux.go). Avoids the iptables-nft
	// cross-process EPERM behavior we hit on Parrot 6.17.
	if err := nftAddNAT(n, *iface); err != nil {
		return nil, err
	}
	return map[string]any{"subnet": cidr, "iface": *iface, "added": 3}, nil
}

// add-nat / remove-nat now go through the in-process netlink path
// in nft_linux.go. The old iptables-restore shell-out helpers were
// removed once they had no remaining callers.

func cmdRemoveNAT(args []string) (any, error) {
	fs := flag.NewFlagSet("remove-nat", flag.ContinueOnError)
	subnet := fs.String("subnet", "", "private subnet")
	iface := fs.String("iface", "", "WAN interface")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	n, err := validateSubnet(*subnet)
	if err != nil {
		return nil, err
	}
	if err := validateIface(*iface); err != nil {
		return nil, err
	}
	cidr := n.String()
	if err := nftRemoveNAT(n, *iface); err != nil {
		return nil, err
	}
	return map[string]any{"subnet": cidr, "iface": *iface, "removed": true}, nil
}


// ---------- doctor ----------

// cmdCaps dumps every relevant capability bit + the NoNewPrivs
// state from /proc/self/status. Run as a child of veil-bridge to
// see what an iptables-spawned-from-bridge would inherit:
//
//   veil-bridge caps               # what bridge itself has
//   veil-bridge caps --child       # what an exec'd child sees
func cmdCaps(args []string) (any, error) {
	asChild := false
	for _, a := range args {
		if a == "--child" {
			asChild = true
		}
	}
	if asChild {
		// Exec ourselves with no flag so the child path is reached.
		// The child runs main() → ambient raise → cmdCaps with no
		// flag → reports its caps (which are what iptables would see).
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "caps")
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("child caps: %w (out: %s)", err, out)
		}
		os.Stdout.Write(out)
		return nil, nil
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	keep := map[string]bool{
		"Name:": true, "Pid:": true, "Uid:": true, "Gid:": true,
		"CapInh:": true, "CapPrm:": true, "CapEff:": true,
		"CapBnd:": true, "CapAmb:": true, "NoNewPrivs:": true,
	}
	out := map[string]string{}
	for _, line := range lines {
		for prefix := range keep {
			if strings.HasPrefix(line, prefix) {
				k := strings.TrimSuffix(prefix, ":")
				out[k] = strings.TrimSpace(strings.TrimPrefix(line, prefix))
			}
		}
	}
	const capNetAdmin = 12
	checkBit := func(hex string) string {
		n, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return "?"
		}
		if n&(1<<capNetAdmin) != 0 {
			return "yes"
		}
		return "no"
	}
	out["NetAdmin_in_Eff"] = checkBit(out["CapEff"])
	out["NetAdmin_in_Prm"] = checkBit(out["CapPrm"])
	out["NetAdmin_in_Inh"] = checkBit(out["CapInh"])
	out["NetAdmin_in_Amb"] = checkBit(out["CapAmb"])
	return out, nil
}

// cmdSelftest exercises the path that fails in production: ambient
// cap raise (already done in main), then iptables-nft via the same
// shell-out shape as add-nat. Tests both READ and WRITE paths since
// they may behave differently.
func cmdSelftest(_ []string) (any, error) {
	parent, _ := os.ReadFile("/proc/self/status")
	parentSummary := map[string]string{}
	for _, line := range strings.Split(string(parent), "\n") {
		for _, p := range []string{"Name", "Pid", "Uid", "CapInh", "CapPrm", "CapEff", "CapAmb", "CapBnd", "NoNewPrivs", "Seccomp"} {
			if strings.HasPrefix(line, p+":") {
				parentSummary[p] = strings.TrimSpace(strings.TrimPrefix(line, p+":"))
			}
		}
	}

	// Test 1: READ (iptables -L) — proven to work for the user.
	readCmd := exec.Command("iptables", "-w", "5", "-t", "nat", "-L", "POSTROUTING", "-n")
	readOut, readErr := readCmd.CombinedOutput()
	readExit := 0
	if readCmd.ProcessState != nil {
		readExit = readCmd.ProcessState.ExitCode()
	}

	// Test 2: WRITE (iptables -A then -D) on a definitely-unique
	// throwaway subnet. This is the exact path that's failing in
	// add-nat. If it fails here, we have an isolated repro from
	// inside veil-bridge's own code path.
	const testCIDR = "10.255.255.252/30"
	writeAdd := exec.Command("iptables", "-w", "5", "-t", "nat", "-A", "POSTROUTING", "-s", testCIDR, "-o", "lo", "-j", "MASQUERADE")
	writeAddOut, writeAddErr := writeAdd.CombinedOutput()
	writeAddExit := 0
	if writeAdd.ProcessState != nil {
		writeAddExit = writeAdd.ProcessState.ExitCode()
	}
	// Always try to clean up, even if add succeeded.
	_ = exec.Command("iptables", "-w", "5", "-t", "nat", "-D", "POSTROUTING", "-s", testCIDR, "-o", "lo", "-j", "MASQUERADE").Run()

	report := map[string]any{
		"parent_state":     parentSummary,
		"xtables_lockfile": os.Getenv("XTABLES_LOCKFILE"),
		"read_exit":        readExit,
		"read_err":         fmt.Sprintf("%v", readErr),
		"write_exit":       writeAddExit,
		"write_out":        strings.TrimSpace(string(writeAddOut)),
		"write_err":        fmt.Sprintf("%v", writeAddErr),
		// Keep the legacy field so existing scripts work:
		"iptables_exit":    readExit,
		"iptables_out":     strings.TrimSpace(string(readOut)),
		"iptables_err":     fmt.Sprintf("%v", readErr),
	}

	const capNetAdmin = 12
	parseCap := func(hex string) bool {
		n, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return false
		}
		return n&(1<<capNetAdmin) != 0
	}
	switch {
	case readExit == 0 && writeAddExit == 0:
		report["diagnosis"] = "OK — both READ and WRITE work. If add-nat from veil-gui still fails, something in the launch context (sandbox, seccomp) is stripping caps when veil-gui spawns veil-bridge. Compare: veil-bridge selftest from terminal vs. spawned by veil-gui."
	case readExit == 0 && writeAddExit != 0:
		report["diagnosis"] = "READ works, WRITE fails — kernel rejects nft writes despite caps. This is unusual; check Seccomp + Apparmor. Try: sudo aa-status | grep -i iptables. Also try: sudo iptables -t nat -L POSTROUTING (clear stale rules). Or check kernel.unprivileged_bpf_disabled / kernel.dmesg_restrict for AppArmor/SELinux denials (sudo dmesg | tail -50)."
	case !parseCap(parentSummary["CapEff"]):
		report["diagnosis"] = "veil-bridge itself doesn't have CAP_NET_ADMIN effective. setcap was lost. Run: sudo setcap cap_net_admin+ep " + mustExe()
	case !parseCap(parentSummary["CapAmb"]):
		report["diagnosis"] = "Bridge has CapEff but not CapAmb — ambient raise dance failed. Most likely: NoNewPrivs is set in the calling environment."
	default:
		report["diagnosis"] = "Caps look right but iptables refused us. Suspect AppArmor / SELinux."
	}
	return report, nil
}

func cmdDoctor(_ []string) (any, error) {
	info := map[string]any{
		"binary":      mustExe(),
		"euid":        os.Geteuid(),
		"has_caps":    hasNetAdmin(),
		"veil_devs":   listVeilDevs(),
	}
	if !info["has_caps"].(bool) {
		return info, errors.New("CAP_NET_ADMIN not present — run: sudo setcap cap_net_admin+ep " + mustExe())
	}
	return info, nil
}

func mustExe() string {
	p, err := os.Executable()
	if err != nil {
		return "(unknown)"
	}
	return p
}

// hasNetAdmin reads /proc/self/status to detect the cap bit. We
// don't link libcap because that's another dependency; the kernel
// already exposes the bitset as text.
func hasNetAdmin() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	const capNetAdmin = 12 // CAP_NET_ADMIN bit
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			n, err := strconv.ParseUint(hex, 16, 64)
			if err != nil {
				return false
			}
			return n&(1<<capNetAdmin) != 0
		}
	}
	return false
}

func listVeilDevs() []string {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range links {
		n := l.Attrs().Name
		if strings.HasPrefix(n, veilDevicePrefix) {
			out = append(out, n)
		}
	}
	return out
}

// ---------- helpers ----------

func usageAndExit() {
	fmt.Fprintln(os.Stderr, "veil-bridge — privileged helper for Veil's user-ns engine.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  create-veth --profile N --host-cidr A/30 --ns-cidr B/30 --ns-pid PID")
	fmt.Fprintln(os.Stderr, "  remove-veth --profile N")
	fmt.Fprintln(os.Stderr, "  add-nat     --subnet A.B.C.0/N --iface IFACE")
	fmt.Fprintln(os.Stderr, "  remove-nat  --subnet A.B.C.0/N --iface IFACE")
	fmt.Fprintln(os.Stderr, "  doctor")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Install: sudo setcap cap_net_admin+ep $(realpath veil-bridge)")
	os.Exit(2)
}

func fail(err error) {
	_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": err.Error()})
	os.Exit(1)
}

// raiseAmbientCapNetAdmin is implemented per-platform (Linux only;
// no-op stub on other GOOSes). See caps_linux.go.
