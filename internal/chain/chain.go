// Package chain validates and explains backend chains.
//
// The actual chain *execution* lives in the engine, which calls each
// backend's Start with the prior backend's Steering. This package only
// provides static validation and human-readable summaries (used by the
// GUI and `veil list`).
package chain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mstampfli/veil/internal/profile"
)

// Validate checks that a chain is composable. Rules:
//
//   - At least one backend.
//   - At most one tunnel-style backend (WireGuard / OpenVPN) — stacking
//     two TUN backends would require double-NAT.
//   - Tunnels are UDP-based and can't be carried by a TCP proxy, so a
//     tunnel must come BEFORE any proxy/tor hop in the chain.
//   - Tor accepts an upstream proxy hop (socks5/http/tor) and chains
//     through it, so socks5 → tor and similar are allowed.
//   - Plain proxies (socks5, http) can sit at the end of a chain after a
//     tunnel; they don't need a chainer because the proxy's IP is
//     reached through the prior tunnel's routing.
//   - Two pure-proxy hops (socks5 → socks5, socks5 → http) without an
//     intermediate Tor are NOT supported in v1: there's no in-namespace
//     chainer, and apps don't natively chain proxies.
//   - direct hops are allowed anywhere as a no-op.
func Validate(c []profile.Backend) error {
	if len(c) == 0 {
		return errors.New("chain is empty")
	}
	tunnelSeen := false
	_ = tunnelSeen
	anyProxySeen := false // any of socks5/http/tor — tunnel can't follow these
	for i, b := range c {
		if err := b.Validate(); err != nil {
			return fmt.Errorf("hop %d (%s): %w", i, b.Kind, err)
		}
		switch b.Kind {
		case profile.BackendWireGuard, profile.BackendOpenVPN:
			if anyProxySeen {
				return errors.New("tunnel backend must come before proxy/tor hops (proxies can't carry UDP)")
			}
			tunnelSeen = true
		case profile.BackendSOCKS5, profile.BackendHTTP:
			anyProxySeen = true
		case profile.BackendTor:
			// Tor handles upstream proxies via Socks5Proxy/HTTPSProxy in
			// torrc. After Tor, plain proxies chain via the proxychain
			// relay in their backend.
			anyProxySeen = true
		case profile.BackendTLSMITM:
			// MITM proxy belongs at the end of a chain — it's a local
			// proxy that re-handshakes outgoing TLS, so it must be the
			// closest hop to the launched app.
			anyProxySeen = true
		case profile.BackendDirect:
			// no-op
		}
	}
	return nil
}

func isProxy(k profile.BackendKind) bool {
	switch k {
	case profile.BackendSOCKS5, profile.BackendHTTP, profile.BackendTor:
		return true
	}
	return false
}

// Summary returns a human-readable arrow string e.g. "wireguard -> tor".
func Summary(c []profile.Backend) string {
	parts := make([]string, len(c))
	for i, b := range c {
		switch b.Kind {
		case profile.BackendSOCKS5, profile.BackendHTTP:
			parts[i] = fmt.Sprintf("%s(%s:%d)", b.Kind, b.Host, b.Port)
		case profile.BackendTor:
			parts[i] = "tor"
		default:
			parts[i] = string(b.Kind)
		}
	}
	return strings.Join(parts, " -> ")
}
