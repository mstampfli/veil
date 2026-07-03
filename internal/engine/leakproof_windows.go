//go:build windows

package engine

// Windows session-level leak-proofing.
//
// The per-PID WinDivert filter (in windivert_windows.go) catches the
// launched app's direct egress. But several leak channels happen
// OUTSIDE the launched process — they're driven by Windows system
// services (svchost) on behalf of the user, with their own PIDs that
// our per-app filter doesn't see. This file installs and tears down
// system-level mitigations for those channels:
//
//   1. DNS: pin every active interface's resolver to the tunnel's DNS
//      via `netsh interface ipv4 set dnsservers ... validate=no`.
//      Saved and restored on Down. Plus the per-PID WinDivert filter
//      already drops port 53 from the app to anywhere not the tunnel.
//
//   2. LLMNR (Link-Local Multicast Name Resolution): the most common
//      local-name fallback when DNS fails. Can leak the username +
//      query content over the LAN. Disabled via Group Policy
//      registry key for the duration of the session.
//
//   3. NetBIOS over TCP/IP: even older fallback. Disabled per-adapter.
//
//   4. WPAD (Web Proxy Auto-Discovery): browsers can be told via
//      browser flags, but a system-wide WinHTTP/IE proxy auto-detect
//      can still leak DNS for `wpad.<domain>`. Disabled via WinHTTP
//      reset and AutoDetect registry key.
//
//   5. mDNS / WS-Discovery: Windows 10's "Function Discovery" service
//      emits multicast queries. Per-PID filter catches these from the
//      launched app; the host's own service still emits them, but
//      those come from the OS not the user — out of scope for app-
//      isolation guarantees.
//
//   6. CPU rate cap: assigns the launched process to a Job Object
//      with JOBOBJECT_CPU_RATE_CONTROL_INFORMATION set to a hard cap.
//      Mirrors the Linux cgroup-v2 cpu.max throttle and defeats the
//      same JS-perf-benchmark fingerprinting attacks.
//
// All of these are best-effort; the engine never aborts launch over
// a hardening step failure (except for the kill switch itself, which
// is a different code path). They install on Up, register a restore
// callback in cleanupExtra-equivalent state, and undo on Down.

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// --- Hardening state ---

// systemHardening captures saved values for everything we overwrite,
// so Down can restore the user's environment.
type systemHardening struct {
	// Per-interface DNS server lists captured before pinning.
	savedDNS map[string][]string

	// LLMNR was previously set, unset, or default. We remember enough
	// to restore: hadLLMNR true means key existed; llmnrValue is the
	// EnableMulticastName value if it did.
	hadLLMNR     bool
	llmnrPrev    uint32

	// WPAD: track whether IE AutoDetect was enabled.
	hadAutoDetect  bool
	autoDetectPrev uint32

	// NetBIOS: per-adapter saved NetbiosOptions (under
	// HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\<id>).
	netbios map[string]uint32

	// What we pinned DNS to (for logs / Doctor).
	pinnedDNS []string
}

// installSystemHardening pins DNS to the tunnel resolver, disables
// LLMNR/NetBIOS/WPAD, and returns a struct the caller can use to
// restore the previous state on session teardown. tunnelDNS is the
// resolver IP the tunnel pushed (read from the WG/OVPN config); pass
// nil to skip DNS pinning.
//
// Best-effort: every step that fails just gets logged and skipped.
// We never break the user's networking over a hardening misstep.
func installSystemHardening(tunnelDNS []string) *systemHardening {
	h := &systemHardening{
		savedDNS: map[string][]string{},
		netbios:  map[string]uint32{},
	}

	if len(tunnelDNS) > 0 {
		h.pinDNS(tunnelDNS)
	}
	h.disableLLMNR()
	h.disableNetBIOS()
	h.disableWPAD()
	return h
}

// Restore reverses everything installSystemHardening changed. Safe
// to call when h is nil (e.g. hardening was never installed).
func (h *systemHardening) Restore() {
	if h == nil {
		return
	}
	h.restoreDNS()
	h.restoreLLMNR()
	h.restoreNetBIOS()
	h.restoreWPAD()
}

// --- DNS pinning ---

// pinDNS rewrites every active IPv4 interface's DNS servers to the
// supplied list. Captures the previous value first. Skips loopback
// and tunnel adapters (those already have correct DNS).
func (h *systemHardening) pinDNS(servers []string) {
	if len(servers) == 0 {
		return
	}
	h.pinnedDNS = append([]string(nil), servers...)

	// Enumerate interfaces.
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "dnsservers").Output()
	if err != nil {
		return
	}
	ifaces := parseDNSConfig(out)
	for name, prev := range ifaces {
		if name == "" {
			continue
		}
		// Skip loopback by alias (Windows always names it "Loopback Pseudo-Interface").
		if strings.HasPrefix(strings.ToLower(name), "loopback") {
			continue
		}
		h.savedDNS[name] = prev
	}

	// Set the new DNS servers on each captured interface. The first
	// is "primary", rest get added with index>=2.
	for name := range h.savedDNS {
		_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
			"name="+name, "source=static", "address="+servers[0], "validate=no").Run()
		for i := 1; i < len(servers); i++ {
			_ = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
				"name="+name, "address="+servers[i], "index="+strconv.Itoa(i+1), "validate=no").Run()
		}
	}
}

func (h *systemHardening) restoreDNS() {
	for name, prev := range h.savedDNS {
		if len(prev) == 0 {
			// Was DHCP-assigned originally.
			_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
				"name="+name, "source=dhcp").Run()
			continue
		}
		_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
			"name="+name, "source=static", "address="+prev[0], "validate=no").Run()
		for i := 1; i < len(prev); i++ {
			_ = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
				"name="+name, "address="+prev[i], "index="+strconv.Itoa(i+1), "validate=no").Run()
		}
	}
}

// parseDNSConfig parses the output of `netsh interface ipv4 show dnsservers`.
// Format:
//
//	Configuration for interface "Ethernet"
//	    DNS servers configured through DHCP:  192.168.1.1
//	                                           192.168.1.2
//	    Register with which suffix:           Primary only
func parseDNSConfig(out []byte) map[string][]string {
	res := map[string][]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var currentIf string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Configuration for interface") {
			// extract quoted name
			lq := strings.Index(trimmed, `"`)
			rq := strings.LastIndex(trimmed, `"`)
			if lq >= 0 && rq > lq {
				currentIf = trimmed[lq+1 : rq]
				res[currentIf] = nil
			}
			continue
		}
		// DNS server entries: lines that start with whitespace and
		// contain only an IP address (or 'None').
		fields := strings.Fields(trimmed)
		if currentIf == "" || len(fields) == 0 {
			continue
		}
		// Capture both the "DNS servers configured through DHCP: 1.2.3.4"
		// shape and the continuation lines that contain just an IP.
		var ipStr string
		if strings.Contains(trimmed, ":") {
			// "DNS servers ...: <ip>" — ip is the last field.
			last := fields[len(fields)-1]
			if isIPv4Literal(last) {
				ipStr = last
			}
		} else if isIPv4Literal(fields[0]) {
			ipStr = fields[0]
		}
		if ipStr != "" {
			res[currentIf] = append(res[currentIf], ipStr)
		}
	}
	return res
}

func isIPv4Literal(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// --- LLMNR ---

func (h *systemHardening) disableLLMNR() {
	// Group Policy key. The presence of this key with value 0 fully
	// disables LLMNR queries by the system's DNS Client.
	const key = `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
	prev, prevSet := readRegDWORD(key, "EnableMulticast")
	h.hadLLMNR = prevSet
	h.llmnrPrev = prev
	_ = setRegDWORD(key, "EnableMulticast", 0)
}

func (h *systemHardening) restoreLLMNR() {
	const key = `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
	if h.hadLLMNR {
		_ = setRegDWORD(key, "EnableMulticast", h.llmnrPrev)
	} else {
		_ = deleteRegValue(key, "EnableMulticast")
	}
}

// --- NetBIOS ---

func (h *systemHardening) disableNetBIOS() {
	// Iterate every interface key under
	// HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\
	// Set NetbiosOptions=2 (disabled). Save previous values for restore.
	const root = `HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces`
	out, err := exec.Command("reg", "query", root).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\r\n") {
		l := strings.TrimSpace(line)
		if !strings.HasPrefix(l, root) || l == root {
			continue
		}
		prev, ok := readRegDWORD(l, "NetbiosOptions")
		if ok {
			h.netbios[l] = prev
		}
		_ = setRegDWORD(l, "NetbiosOptions", 2)
	}
}

func (h *systemHardening) restoreNetBIOS() {
	for k, prev := range h.netbios {
		_ = setRegDWORD(k, "NetbiosOptions", prev)
	}
}

// --- WPAD ---

func (h *systemHardening) disableWPAD() {
	// Per-user IE / Edge auto-detect setting.
	const ieKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	prev, prevSet := readRegDWORD(ieKey, "AutoDetect")
	h.hadAutoDetect = prevSet
	h.autoDetectPrev = prev
	_ = setRegDWORD(ieKey, "AutoDetect", 0)

	// Reset WinHTTP system proxy so background services don't auto-
	// discover. This is "Direct access (no proxy)" — the same as
	// `netsh winhttp reset proxy`.
	_ = exec.Command("netsh", "winhttp", "reset", "proxy").Run()
}

func (h *systemHardening) restoreWPAD() {
	const ieKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if h.hadAutoDetect {
		_ = setRegDWORD(ieKey, "AutoDetect", h.autoDetectPrev)
	} else {
		_ = deleteRegValue(ieKey, "AutoDetect")
	}
	// We don't restore winhttp proxy because we don't know what the
	// user had before; the safe default is "Direct access".
}

// --- Registry helpers (use reg.exe, no third-party dep) ---

func setRegDWORD(key, name string, value uint32) error {
	return exec.Command("reg", "add", key,
		"/v", name, "/t", "REG_DWORD", "/d", strconv.FormatUint(uint64(value), 10),
		"/f").Run()
}

func readRegDWORD(key, name string) (uint32, bool) {
	out, err := exec.Command("reg", "query", key, "/v", name).Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		idx := strings.Index(l, "REG_DWORD")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(l[idx+len("REG_DWORD"):])
		// Value may be hex (0xABCD) or decimal.
		if strings.HasPrefix(val, "0x") {
			n, err := strconv.ParseUint(val[2:], 16, 32)
			if err != nil {
				return 0, false
			}
			return uint32(n), true
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(n), true
	}
	return 0, false
}

func deleteRegValue(key, name string) error {
	return exec.Command("reg", "delete", key, "/v", name, "/f").Run()
}

// --- CPU throttle via Job Object ---

// procSetInformationJobObject + JOBOBJECT_CPU_RATE_CONTROL_INFORMATION.
var (
	procCreateJobObject       = modKernel32.NewProc("CreateJobObjectW")
	procSetInfoJobObject      = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcToJobObject = modKernel32.NewProc("AssignProcessToJobObject")
)

const (
	jobObjectCPURateControlInformation = 15
	jobObjectCPURateControlEnable      = 0x00000001
	jobObjectCPURateControlHardCap     = 0x00000004
)

type jobobjectCPURateControlInformation struct {
	ControlFlags uint32
	CPURate      uint32 // when HARD_CAP+ENABLE: 1/100ths of one percent (e.g. 30% = 3000)
}

// installCPUThrottle creates a Job Object with a CPU rate hard cap,
// assigns the launched process to it, and returns the job handle.
// throttle is the user-facing string ("30%", "50%", etc.) — same
// format as the Linux engine's CPUThrottle field. Returns 0 / nil
// silently on parse failures or insufficient privileges; caller
// treats the absence as "not throttled".
func installCPUThrottle(pid int, throttle string) (syscall.Handle, error) {
	if throttle == "" {
		return 0, nil
	}
	pct := parsePercent(throttle)
	if pct <= 0 || pct > 100 {
		return 0, fmt.Errorf("invalid throttle %q", throttle)
	}

	// CreateJobObjectW(NULL, NULL) = anonymous job.
	r1, _, e1 := procCreateJobObject.Call(0, 0)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateJobObject: %w", e1)
	}
	job := syscall.Handle(r1)

	info := jobobjectCPURateControlInformation{
		ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
		CPURate:      uint32(pct * 100), // 30% -> 3000
	}
	r1, _, e1 = procSetInfoJobObject.Call(
		uintptr(job),
		uintptr(jobObjectCPURateControlInformation),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r1 == 0 {
		_ = syscall.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", e1)
	}

	// Assign the launched process. Need a handle with
	// PROCESS_SET_QUOTAS | PROCESS_TERMINATE access.
	procH, err := openProcessForJobAssignment(pid)
	if err != nil {
		_ = syscall.CloseHandle(job)
		return 0, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(procH)

	r1, _, e1 = procAssignProcToJobObject.Call(uintptr(job), uintptr(procH))
	if r1 == 0 {
		_ = syscall.CloseHandle(job)
		return 0, fmt.Errorf("AssignProcessToJobObject: %w", e1)
	}
	return job, nil
}

const (
	processSetQuota = 0x0100
)

func openProcessForJobAssignment(pid int) (syscall.Handle, error) {
	r1, _, err := procOpenProcess.Call(
		uintptr(processSetQuota|processTerminate), 0, uintptr(pid))
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func parsePercent(s string) int {
	s = strings.TrimSpace(strings.TrimSuffix(s, "%"))
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
