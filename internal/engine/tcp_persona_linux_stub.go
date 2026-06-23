//go:build linux && !pro

package engine

import "github.com/mstampfli/veil/internal/profile"

// installTCPPersona is a no-op in the free edition. TCP/IP-stack
// fingerprint shaping (per-OS TTL/MSS/timestamps/window-scale) is a Pro
// anti-detect capability; its implementation lives only in the Pro build
// (tcp_persona_linux_pro.go) so it stays out of the public open-core repo.
func installTCPPersona(ns, persona string) error { return nil }

// deriveTCPFromPersona returns "" in the free edition (no persona-driven
// TCP-persona derivation without the Pro anti-detect stack).
func deriveTCPFromPersona(p *profile.Profile) string { return "" }
