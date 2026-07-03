//go:build windows

package engine

// WinDivert-backed real kill switch.
//
// netsh advfirewall (the v1 kill switch) operates at the WFP layer
// using per-binary rules. It can be defeated by:
//   - copying the binary to a different path before launch
//   - apps that bypass winsock and write to NDIS directly (rare)
//   - racy tunnel-down scenarios where the rule applies after a packet
//   - certain IPv6 edge cases (mitigated by our explicit -IPv6 rule)
//
// WinDivert installs an NDIS-level callout driver that intercepts
// packets in the kernel network stack BEFORE socket-level enforcement.
// We open a handle in WINDIVERT_FLAG_DROP mode with a filter
// expression that matches the launched app's outbound packets minus
// tunnel/loopback. Matching packets are silently dropped by the
// kernel — never even reach userspace. The handle is held open for
// the session lifetime and closed on Down().
//
// Distribution: WinDivert is NOT bundled. Users install it separately
// (download from https://reqrypt.org/windivert.html, copy WinDivert.dll
// + WinDivert64.sys to System32). If WinDivert isn't found we silently
// fall back to the netsh kill switch with a warning surfaced via
// Doctor. This keeps Veil's own installer simple — no kernel driver
// shipping or Microsoft attestation paperwork.
//
// Honest limitations of this v1 implementation:
//   - Filters by parent PID only. Chromium/Brave/Edge spawn child
//     processes that need their PIDs added to the filter — currently
//     not done. Most outbound network requests in modern browsers go
//     through a centralized network process which IS the parent for
//     network purposes, but not always. Future work: poll the Job
//     Object's child-PID list and recompile the filter.
//   - The filter is compiled to NFA/DFA at handle-open time and is
//     immutable; PID-list changes require close-and-reopen, which
//     drops packets for ~10 ms. Acceptable for kill switch (failing
//     closed during recompile is correct behavior).
//   - WinDivert.dll loading requires admin (the driver service must
//     be installable). Veil already requires admin for routing
//     changes; same prerequisite.

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

const (
	winDivertLayerNetwork = 0
	winDivertFlagDrop     = 0x0002
	invalidHandleValue    = ^uintptr(0)
)

var (
	winDivertOnce sync.Once
	winDivertErr  error

	modWinDivert *syscall.LazyDLL
	procOpen     *syscall.LazyProc
	procClose    *syscall.LazyProc
)

// killSwitchKernel is the per-session kernel-level kill switch state.
type killSwitchKernel struct {
	handle  syscall.Handle
	filter  string
	closed  atomic.Bool
}

// loadWinDivert resolves WinDivert.dll lazily. Errors mean the user
// hasn't installed WinDivert; caller falls back to netsh-only.
func loadWinDivert() error {
	winDivertOnce.Do(func() {
		dll := syscall.NewLazyDLL("WinDivert.dll")
		if err := dll.Load(); err != nil {
			winDivertErr = fmt.Errorf(
				"WinDivert.dll not found — install from https://reqrypt.org/windivert.html "+
					"(copy WinDivert.dll + WinDivert64.sys to %%SystemRoot%%\\System32): %w", err)
			return
		}
		modWinDivert = dll
		procOpen = dll.NewProc("WinDivertOpen")
		procClose = dll.NewProc("WinDivertClose")
	})
	return winDivertErr
}

// WinDivertAvailable reports whether WinDivert.dll could be loaded.
// Used by Doctor to surface the kernel-kill-switch capability.
func WinDivertAvailable() bool {
	return loadWinDivert() == nil
}

// installKernelKillSwitch opens a WinDivert handle with a filter that
// matches all outbound packets from the given PID except those going
// over an allowed interface (tunnel) or to loopback. Dropping happens
// in the kernel via WINDIVERT_FLAG_DROP — no userspace recv loop
// needed; the handle just sits open and the kernel filters.
//
// Returns ErrWinDivertUnavailable if WinDivert isn't installed; caller
// is expected to fall back to the netsh-only kill switch and log a
// warning.
func (e *winEngine) installKernelKillSwitch(st *winState, pid int) (*killSwitchKernel, error) {
	if err := loadWinDivert(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWinDivertUnavailable, err)
	}

	// Compose the filter expression. WinDivert filter language:
	//   - "outbound" matches packets being sent
	//   - "processId == N" matches by PID
	//   - "ifIdx != N" matches anything not on interface index N
	//   - "not loopback" excludes 127.0.0.0/8
	//
	// The filter is two-clause: either (a) the launched app trying
	// to egress on a non-tunnel interface, or (b) any packet from the
	// launched app to a known leaky port (DNS/LLMNR/NetBIOS/mDNS/
	// WS-Discovery) regardless of interface — those aren't allowed at
	// all because the system-hardening layer routes legitimate DNS
	// through the tunnel via netsh DNS pinning. Belt-and-suspenders.
	parts := []string{
		fmt.Sprintf("outbound and processId == %d", pid),
		"not loopback",
	}
	for _, alias := range st.tunnelInterfaces {
		idx, err := getInterfaceIndex(alias)
		if err != nil || idx == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("ifIdx != %d", idx))
	}
	mainClause := "(" + strings.Join(parts, " and ") + ")"
	// Always-drop ports for the launched PID, even on tunnel:
	//   53   DNS plaintext (force browser DoH instead)
	//   137-138  NetBIOS UDP
	//   139  NetBIOS-SSN TCP
	//   3702 WS-Discovery (UPnP/printer)
	//   5353 mDNS / Bonjour
	//   5355 LLMNR
	leakPorts := fmt.Sprintf(
		"(processId == %d and outbound and ("+
			"udp.DstPort == 53 or tcp.DstPort == 53 or "+
			"udp.DstPort == 137 or udp.DstPort == 138 or tcp.DstPort == 139 or "+
			"udp.DstPort == 3702 or udp.DstPort == 5353 or udp.DstPort == 5355))",
		pid)
	filter := mainClause + " or " + leakPorts

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("encode filter: %w", err)
	}
	r1, _, callErr := procOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		0, // priority — single Veil filter, ordering doesn't matter
		uintptr(winDivertFlagDrop),
	)
	if r1 == invalidHandleValue {
		return nil, fmt.Errorf("WinDivertOpen failed (filter=%q): %w", filter, callErr)
	}
	return &killSwitchKernel{
		handle: syscall.Handle(r1),
		filter: filter,
	}, nil
}

// Close releases the kernel kill switch. Idempotent.
func (k *killSwitchKernel) Close() {
	if k == nil || k.closed.Swap(true) {
		return
	}
	if procClose != nil && k.handle != 0 {
		_, _, _ = procClose.Call(uintptr(k.handle))
	}
}

// ErrWinDivertUnavailable is returned when WinDivert.dll can't be
// loaded — typically because the user hasn't installed WinDivert.
// Caller falls back to netsh-only kill switch.
var ErrWinDivertUnavailable = errors.New("WinDivert unavailable")

// getInterfaceIndex resolves a Windows interface alias (e.g. "Wintun")
// to its IfIndex. Uses Get-NetAdapter via PowerShell — slower than
// raw Win32 but avoids importing golang.org/x/sys/windows/iphlpapi
// for one lookup. Called once per session at kill-switch install.
func getInterfaceIndex(alias string) (uint32, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-NetAdapter -Name '%s' -ErrorAction SilentlyContinue).IfIndex", strings.ReplaceAll(alias, "'", "''"))).Output()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, fmt.Errorf("interface %q not found", alias)
	}
	idx, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse ifIdx %q: %w", s, err)
	}
	return uint32(idx), nil
}
