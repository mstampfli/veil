# Veil — cross-platform feature matrix

Snapshot of which spoofing layers work where today and the porting plan
for the others. **Linux is the reference platform**; Windows and macOS
have partial support and a clear path to parity.

| Layer | Linux | Windows | macOS | Cross-platform port plan |
|---|---|---|---|---|
| Per-app network namespace | ✓ | ✗ (single global tunnel) | ✗ (single global tunnel) | Windows: WFP per-PID filter (Mullvad's split-tunnel driver pattern). macOS: PF rules + Network Extension framework (requires Apple-signed system extension). |
| WireGuard tunnel | ✓ | ✓ (Wintun) | ✓ (utun via wireguard-go) | Already cross-platform. |
| OpenVPN tunnel | ✓ | ✓ | ✓ | Already cross-platform via openvpn binary. |
| SOCKS5 / HTTP proxy backends | ✓ | ✓ | ✓ | Already cross-platform. |
| Tor (system) | ✓ | ✓ | ✓ | Already cross-platform. |
| Tor (managed, transparent mode) | ✓ | partial | partial | Transparent redirect uses Linux iptables nat. Windows: WFP redirector. macOS: PF rdr-anchor. |
| Kill switch | ✓ (iptables in netns) | ✓ (netsh + per-program) | ✓ (pf anchor) | Already cross-platform. |
| TLS-MITM proxy + uTLS | ✓ | ✓ | ✓ | Pure Go, already cross-platform. CA install differs by trust store. |
| HTTP/2 mediator | ✓ | ✓ | ✓ | Pure Go, already cross-platform. |
| TCP TTL/MSS rewrite | ✓ (iptables mangle) | ✗ | ✗ | Windows: WFP packet rewrite. macOS: PF scrub directive. |
| TCP options NFQUEUE rewrite (window scale, options order, TS offset) | ✓ | ✗ | ✗ | Windows: WFP callout driver. macOS: NetworkExtension content-filter. Both substantial. |
| Per-namespace source port range | ✓ | ✗ | ✗ | Windows: per-process via SetWinsockPortRange (registry). macOS: net.inet.ip.portrange.first/last per service. |
| CPU throttle (cgroup v2) | ✓ | ✗ | ✗ | Windows: Job Object CPU rate. macOS: nice + taskpolicy (coarse). |
| Time namespace | ✓ (CLONE_NEWTIME) | ✗ | ✗ | Windows: no equivalent (clock is global). macOS: SIP-protected, no userspace fix. Mitigated only by browser RFP. |
| Browser config (user.js / --proxy-server) | ✓ | ✓ | ✓ | Already cross-platform. |
| Persona (UA / locale / TZ / screen) | ✓ | ✓ | ✓ | Already cross-platform. |
| Anti-fingerprint (RFP / Chromium flags) | ✓ | ✓ | ✓ | Already cross-platform. |
| Behavioral jitter (input timing) | ✓ (uinput) | planned | planned | Windows: SetWindowsHookEx WH_KEYBOARD_LL + SendInput. macOS: CGEventTapCreate at session level + CGEventPost. |
| Reroll (chain re-randomize on schedule) | ✓ | ✓ | ✓ | Already cross-platform. |
| Tor control (NEWNYM / circuit-status) | ✓ | ✓ | ✓ | Already cross-platform. |
| Tor bridges + obfs4 | ✓ | ✓ | ✓ | Already cross-platform (bundles obfs4proxy when available). |
| Provider helpers (Mullvad/Proton/IVPN) | ✓ | ✓ | ✓ | Already cross-platform. |
| GUI (Wails) | ✓ | ✓ | ✓ | Already cross-platform. |

## Porting priority order

When extending to Windows / macOS, suggested order:

1. **Per-app firewall isolation** (kill switch is already there; this is
   isolating *network egress* per launched app rather than per profile).
2. **TCP TTL/MSS rewrite** — easiest layer-3 spoof on those platforms.
3. **Behavioral jitter** — input event hooks.
4. **TCP options + window-scale rewrite** — biggest piece of work,
   essentially a port of NFQUEUE → WFP/PF custom filter.
5. **Time namespace equivalent** — research-tier on macOS/Windows; may
   never be fully implementable without kernel work.

## What's permanently Linux-only

The following architectural choices are too tightly coupled to Linux
kernel features to ever be fully equivalent on Win/Mac without root-
level kernel additions:

- **Per-app network namespace** — Linux's `ip netns` is unique. The
  closest Win/Mac equivalents are global tunnels with per-app firewall
  filtering, which provides similar threat coverage but isn't the same
  primitive.
- **NFQUEUE userspace packet rewriter** — needs WFP callout (Windows)
  or NetworkExtension content filter (macOS) which are kernel-mode and
  require code-signing.
- **CLONE_NEWTIME (time namespace)** — clock is global on other OSes.

For those layers, Veil documents the limitation honestly and falls
back to "best effort" cross-platform behavior.
