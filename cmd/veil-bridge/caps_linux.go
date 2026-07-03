//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// raiseAmbientCapNetAdmin makes CAP_NET_ADMIN inheritable + ambient
// so exec'd child processes (notably iptables) inherit it.
//
// File capabilities (cap_net_admin+ep on this binary) only populate
// the permitted + effective sets of the binary that holds them.
// They do NOT propagate across exec unless the cap is also in the
// AMBIENT set, AND in the inheritable set. We add it to inheritable
// via capset, then raise it into ambient via prctl. Idempotent.
//
// References: capabilities(7), prctl(2) PR_CAP_AMBIENT_RAISE.
func raiseAmbientCapNetAdmin() error {
	const linuxCapV3 = 0x20080522

	hdr := unix.CapUserHeader{
		Version: linuxCapV3,
		Pid:     0, // self
	}
	// Linux v3 caps span two 32-bit words (caps 0-31 in word 0,
	// 32-63 in word 1). CAP_NET_ADMIN = 12, so word 0.
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}

	const capNetAdmin = unix.CAP_NET_ADMIN // = 12
	bit := uint32(1) << capNetAdmin
	if data[0].Inheritable&bit == 0 {
		data[0].Inheritable |= bit
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			return fmt.Errorf("capset (add inheritable): %w", err)
		}
	}

	if err := unix.Prctl(
		unix.PR_CAP_AMBIENT,
		unix.PR_CAP_AMBIENT_RAISE,
		uintptr(capNetAdmin),
		0, 0,
	); err != nil {
		return fmt.Errorf("prctl PR_CAP_AMBIENT_RAISE: %w", err)
	}
	return nil
}
