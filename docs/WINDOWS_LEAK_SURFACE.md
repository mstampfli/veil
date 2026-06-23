# Windows leak surface — what's covered, what isn't, and why

This document is the honest, exhaustive list of leak channels Veil
addresses (or doesn't) on Windows. Read it before relying on Veil for
any threat model where mistakes have real-world consequences.

The summary, up front:

- **Veil-Linux is the platform that gives you everything.** Per-app
  network namespaces, NFQUEUE-based TCP rewrite, time namespaces, the
  full anti-detect stack — they all rely on Linux kernel features that
  Windows simply does not have.
- **Veil-Windows v1 is leak-safe at the network layer for cohort
  blending (anti-fingerprint mode).** The IP-side guarantees are
  solid; multicast/LAN/DNS leaks are closed.
- **Two persona signals — TCP option-stack reorder and time-namespace
  clock skew — are not yet covered on Windows.** TTL is, via
  WinDivert. The rest of TCP options is roadmap. Time-namespace skew
  has no Windows equivalent at all.
- **For users who need everything**: install WSL2 and run Linux Veil
  inside it. The Linux engine works in the WSL2 kernel out of the box
  (netns, NFQUEUE, time namespaces are all present), and Linux-side
  apps run with Windows desktop integration via WSLg.

---

## What's covered on Windows

### Kill switch (network-layer enforcement)

| Layer | Mechanism | Status |
|---|---|---|
| Per-binary firewall block + allow-tunnel/loopback | `netsh advfirewall` | ✅ |
| IPv6 deny for the launched binary | `netsh advfirewall remoteip=::/0` | ✅ |
| Per-PID kernel-level drop | WinDivert NDIS callout in `WINDIVERT_FLAG_DROP` mode | ✅ (when WinDivert installed) |
| Defense-in-depth blocks for DNS / LLMNR / NetBIOS / mDNS / WS-Discovery | WinDivert filter ports 53, 137-139, 3702, 5353, 5355 | ✅ |
| Pre-launch race window | `CREATE_SUSPENDED` flag + filter installed before `ResumeThread` | ✅ |
| Mid-session tunnel drop | Watchdog terminates the launched app on tunnel-interface state ≠ Up | ✅ |
| Stale state from crashed runs | `cleanupKillSwitchRules` at install + PowerShell `Get-NetFirewallRule -DisplayName 'Veil-*'` orphan sweep at engine startup | ✅ |
| Anti-fingerprint without enforceable kill switch | Profile validation refuses to save; runtime fail-closed if enforcement can't be installed | ✅ |

### DNS / name-resolution leaks

| Layer | Mechanism | Status |
|---|---|---|
| App-direct DNS (port 53) | WinDivert per-PID filter drops it | ✅ |
| `Windows DNS Client` service (svchost) — handles DNS for all apps | `netsh interface ipv4 set dnsservers ... validate=no` pins every active IPv4 interface to the tunnel-pushed DNS resolver. Saved values restored on Down. | ✅ |
| LLMNR (Link-Local Multicast Name Resolution) | Group Policy `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient → EnableMulticast=0`. Restored on Down. | ✅ |
| NetBIOS over TCP/IP | Per-adapter `HKLM\System\CurrentControlSet\Services\NetBT\Parameters\Interfaces\<id> → NetbiosOptions=2`. Restored on Down. | ✅ |
| mDNS / Bonjour | Per-PID block on UDP 5353 | ✅ for the launched app; OS itself may still emit (host-level Function Discovery service) |
| WS-Discovery | Per-PID block on UDP 3702 | ✅ for the launched app |
| WPAD (Web Proxy Auto-Discovery) | `HKCU\...\Internet Settings → AutoDetect=0` + `netsh winhttp reset proxy`. AutoDetect restored on Down. | ✅ |

### TCP/L4 fingerprint

| Signal | Mechanism | Status |
|---|---|---|
| IPv4 TTL on outbound SYN | WinDivert `MODIFY` mode rewrites byte 8; `WinDivertHelperCalcChecksums` recomputes IP/TCP checksums | ✅ |
| TCP options ordering (window scale, NOP placement, timestamp option) | — | ❌ **roadmap** |
| Initial Window Size override | — | ❌ **roadmap** |
| DontFragment bit | (already set on all modern OSes — not a discriminating signal) | n/a |

### CPU / system fingerprint

| Signal | Mechanism | Status |
|---|---|---|
| `performance.now()` JS benchmark fingerprinting | Job Object `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` with hard cap (mirrors Linux cgroup-v2 cpu.max) | ✅ |
| Per-profile time skew (`performance.now()` offset between profiles) | — | ❌ **Linux-kernel only**; CPU throttle alone defeats most JS perf-benchmark attacks but doesn't decorrelate two profiles' clocks |
| Hardware concurrency / device memory / screen / GPU strings | Browser-level via `--veil-persona` flag (Chromium fork) and Firefox `user.js` | ✅ (cross-platform, persona-driven) |

### Browser-level anti-fingerprint

| Layer | Mechanism | Status |
|---|---|---|
| Cohort blending (Mozilla RFP / Chromium uniform-canvas) | Browser flags + `user.js` written by `launcher.ApplyProxyConfig` | ✅ (cross-platform) |
| WebRTC IP leak | `media.peerconnection.enabled=false` (Firefox), `--disable-webrtc-encryption` + WebRTC-handling-policy (Chromium) | ✅ (cross-platform) |
| Persona signals (UA, locale, screen, WebGL, ClientHints) | Same path as Linux | ✅ |
| Browser-driven IP probe (CDP) | `--remote-debugging-port=<random>`, Veil opens new tab via Chrome DevTools Protocol, reads response. Wire signature is the persona's browser, not curl/Veil. | ✅ |

---

## What's NOT covered on Windows, exactly and why

### TCP options reorder

**The gap**: `p0f` and similar passive fingerprinters look at TCP options
ordering as the highest-weight L4 signal — *MSS, NOP, Window-Scale, NOP,
NOP, SACK-permitted* identifies Windows; *MSS, SACK-permitted, Timestamps,
NOP, Window-Scale* identifies Linux. Even with TTL rewritten to match the
persona, the option-stack still reads as the host OS.

**Why not yet**: WinDivert can rewrite packets in flight, but extending or
reshuffling TCP options changes the TCP header length, which means
recomputing data-offset, total-length, and the surrounding checksums —
plus careful handling of fragmented-vs-unfragmented edge cases. We'd
rather ship this with real-Windows packet-capture validation than push an
untested rewrite path that could subtly break tunnels.

**Workaround today**: run the profile in WSL2 with the Linux engine. The
NFQUEUE-based TCP rewrite path on Linux already covers full options.

**Status**: roadmap, focused implementation round.

### Time-namespace clock skew (per-profile)

**The gap**: on Linux 5.6+, every profile's `performance.now()` /
`Date.now()` / `clock_gettime(CLOCK_MONOTONIC)` returns values offset by a
random amount per profile, defeating cross-profile timing correlation
attacks (e.g. "this 50 ms latency burst on profile A and this 50 ms burst
on profile B happened at exactly the same monotonic offset").

**Why not at all**: Windows has no `time` namespace equivalent. The
kernel exposes one global `QueryPerformanceCounter` (and friends) that
all processes read from. Faking this per-process would require a custom
kernel driver intercepting the syscall, or a userspace DLL injection
that hooks `KERNEL32.QueryPerformanceCounter` — both out of scope for
"no-driver Veil-Windows v1".

**Workaround today**: WSL2 with the Linux engine. The WSL2 Linux kernel
supports time namespaces. Inside WSL2, every Veil profile gets its own
clock-domain offset.

**Status**: Linux-only. Realistically not coming to Windows v1 ever
without a kernel driver.

### True per-app network namespaces

**The gap**: on Linux, each profile gets its own network namespace —
its own routing table, ARP table, sockets, interfaces. The launched app
literally cannot see anything outside its netns. Two profiles running
simultaneously have completely independent networking, and no traffic
from one can ever leak into the other.

**Why not**: Windows has no kernel concept analogous to Linux netns.
The `Win32 silo` feature (Windows containers) is too heavy and requires
Hyper-V; raw NDIS LWF drivers don't help (per-interface, not per-app);
WFP is the closest thing, and it filters by binary path, not by
process. We use WFP via netsh + WinDivert to approximate per-PID
isolation, but it's still all on the host's shared network stack.

**Practical impact for Veil v1**: tunnel backends affect host-wide
traffic for the duration of the session. The user's other apps (browser
opened normally outside Veil, email, Slack) all route through the
tunnel while a Veil profile is active. This is acceptable for the
"single profile at a time" use case but doesn't support
"two profiles, different exits, simultaneously" — that needs WSL2.

**Workaround today**: WSL2 with Linux Veil. Each WSL2 Veil profile
gets its own real netns inside the Linux kernel that WSL2 runs.

**Status**: architectural ceiling on Windows v1. Three real escape
paths: WSL2 (Veil-Windows could be made to launch profiles via WSL2 —
roadmap item), a custom NDIS LWF / WFP callout driver (months of work,
EV cert + Microsoft attestation, ongoing maintenance), or full Hyper-V
container (way too heavy).

### Per-app DNS (vs host-wide pinning)

**The gap**: Veil-Windows currently pins host-wide DNS to the tunnel
resolver. That's leak-safe (the user's other apps' DNS goes through the
tunnel too) but it's not *per-app*. Two profiles can't have different
DNS resolvers simultaneously on Windows.

**Why**: same reason as above — Windows has no per-app netns. The
`Windows DNS Client` (svchost.exe) is a single shared service.

**Practical impact**: minor. Most users running Veil have one profile
active at a time, and the tunnel's DNS being host-wide is fine.

**Workaround**: WSL2 + Linux Veil for true per-app DNS isolation.

### Function Discovery / mDNS at the OS level

**The gap**: Windows 10's "Discovery Provider Host" service emits
multicast queries for printers, network media, etc. Our per-PID
WinDivert filter blocks the launched app's mDNS, but the host's
service continues to emit unrelated mDNS traffic.

**Why**: that's the host OS, not the launched app. Out of scope for
"Veil app-isolation" — the user's host has its own behavior we don't
modify.

**Workaround**: disable the service via `Stop-Service fdPHost` if you
care about all-mDNS-silence. Not Veil's job.

**Status**: out of scope. Document and move on.

### IPv6 routing leaks (host-level)

**Status**: covered for the launched app via WinDivert + netsh `-IPv6`
deny rule. Covered for the host's other apps depends on whether the
user has IPv6 disabled globally (registry `HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters → DisabledComponents=0xFF`).
Veil's Doctor warns when host has an IPv6 default route present.

---

## Threat-model recommendation

| You need... | Use |
|---|---|
| Privacy from neighbors / coffee-shop adversaries | Veil-Windows v1, default `kill_switch=true`, `anti_fingerprint=true` |
| Investigation-grade opsec / journalism / research | Veil in WSL2 (Linux engine) — full netns, NFQUEUE TCP rewrite, time namespaces |
| Anything in-between | Veil-Windows v1; install WinDivert for kernel-level kill switch and TCP-TTL persona |

---

## Roadmap

**Next focused round**: TCP options reorder via WinDivert MODIFY. ~300 LOC,
needs careful header-length and checksum handling, wants real-Windows
packet-capture validation before merge.

**Medium term**: WSL2 launcher integration — Veil-Windows can detect
WSL availability and offer "Run this profile in WSL" as a launch mode.
Spawn the Linux engine inside the distro, route per-profile via the
existing Linux netns code. ~250 LOC of glue + setup wizard.

**Long term**: custom NDIS LWF / WFP callout driver. Real per-app
isolation on Windows. Months of work, EV cert + Microsoft attestation
pipeline, ongoing maintenance burden. Only worth doing if Veil scales
to enterprise distribution where the WSL2 fallback isn't acceptable.

---

## Reference: features-by-platform matrix

Generated from the engine code as of this writing. Any cell marked ❌
means the feature is genuinely not available on that platform — not
that it's missing because we forgot.

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| Per-app network namespace | ✅ | ❌ (architectural) | ❌ (architectural) |
| Per-app firewall enforcement | ✅ (iptables) | ✅ (netsh + WinDivert) | partial (pf) |
| Kernel-level kill switch | ✅ (netns boundary) | ✅ (WinDivert) | partial (pf rules) |
| IPv6 leak prevention | ✅ | ✅ | partial |
| DNS pinning to tunnel | ✅ | ✅ | not yet |
| Browser-driven IP probe (CDP) | ✅ | ✅ | not yet |
| Per-binary CPU throttle | ✅ (cgroup) | ✅ (Job Object) | not yet |
| TCP TTL persona | ✅ | ✅ (WinDivert MODIFY) | ❌ |
| TCP options reorder persona | ✅ (NFQUEUE) | ❌ (roadmap) | ❌ |
| Time-namespace clock skew | ✅ | ❌ (architectural) | ❌ (architectural) |
| Input jitter (keystroke + mouse) | ✅ | ❌ (could add via low-level keyboard hook) | ❌ |
| Persona injection (UA, screen, WebGL, etc.) | ✅ | ✅ | ✅ (cross-platform browser flags) |
| Stale-state cleanup on engine start | ✅ (veth) | ✅ (firewall rules) | not yet |
| Graceful shutdown on signal | ✅ | ✅ | ✅ |

If you read this entire document and have questions about a specific
gap, file an issue at the project tracker — every "missing" item here
has a real reason and (usually) a real workaround.
