// Package tcpfp rewrites outgoing TCP SYN packets so the option set,
// option ordering, and per-OS quirks (window scale value, MSS,
// timestamp presence) match a target operating system rather than
// Linux's defaults. Closes the residual stack-fingerprint leaks that
// `iptables -t mangle TTL/MSS` doesn't cover.
//
// The rewriting algorithm is a Veil Pro feature. This file holds only
// the shared type and constant definitions referenced by code outside
// the package; the real implementation lives in the Pro build
// (//go:build pro) and is replaced by no-op stubs in the free build.
package tcpfp

// TCP option kinds we care about.
const (
	OptEnd         = 0
	OptNop         = 1
	OptMSS         = 2
	OptWindowScale = 3
	OptSackPerm    = 4
	OptSack        = 5
	OptTimestamp   = 8
)

// Option is a parsed TCP option.
type Option struct {
	Kind byte
	Data []byte // for kinds with payload
}

// Persona is the target SYN option signature for an OS.
type Persona struct {
	Name string
	// Order is the ordered list of option kinds (with NOP fillers
	// where the OS uses them) that should appear in SYN packets.
	Order []byte
	// WindowScale is the WS shift count to advertise (Linux 7-10,
	// Windows 8, macOS 6, iOS 6).
	WindowScale byte
	// MSS to advertise.
	MSS uint16
	// IncludeTimestamp: whether TS option should be present in SYN.
	IncludeTimestamp bool
	// TSOffset is added to every outgoing TCP timestamp value, making
	// each profile's timestamp clock independent of the host kernel's.
	// Per-profile randomization here breaks cross-profile correlation
	// via shared TS counter inheritance.
	TSOffset uint32
	// InitialTTL is the IPv4 TTL the OS sends on outgoing packets.
	// p0f uses this as the primary OS discriminator: Windows=128,
	// Linux/Android/macOS/iOS=64, BSD/old=32. Without it, every
	// rewritten packet leaves with the HOST's TTL (Parrot=64), so
	// a Windows persona running on Linux looks like Linux to any
	// passive-OS-fingerprint sniffer no matter how perfect the TCP
	// options are.
	InitialTTL byte
}
