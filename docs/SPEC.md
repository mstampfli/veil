# veil — feature specification

veil routes any application through any tunnel chain (WireGuard, OpenVPN,
SOCKS5, HTTP, Tor) inside its own Linux network namespace, with a per-profile
kill switch and isolated state. The **Pro** edition layers fingerprint
impersonation on top.

This document specifies the **free** edition in detail and summarizes the
**Pro** edition at a high level. For the licensing terms see `LICENSE`
(free edition: PolyForm Noncommercial 1.0.0) and `THIRD_PARTY_NOTICES`.

---

## Free edition (source-available)

### Profiles
- Create / edit / delete profiles via GUI and CLI.
- Each profile stores: name, backend chain, app binary + args, isolated data
  directory, and optional env overrides (`TZ`, `LANG`, `LC_ALL`).
- Stored as YAML in `~/.config/veil/profiles/<name>.yaml`.
- Import / export profile bundles (encrypted with a user passphrase).

### Network backends
| Backend | Notes |
|---|---|
| Direct | Namespaced but no tunnel — isolation only |
| SOCKS5 | host / port / auth |
| HTTP / HTTPS proxy | host / port / auth |
| WireGuard | import `.conf` or paste config |
| OpenVPN | import `.ovpn` |
| Tor | per-profile Tor instance, isolated `DataDirectory` + `SocksPort` |

### Backend chaining (multi-hop)
Profiles chain backends; traffic flows through them in order. Examples:
`vpn → tor` (Tor-over-VPN), `tor → socks5`, `vpn → socks5`, `socks5 → socks5`.
Single-hop is a chain of length 1.

### Isolation
- Each launched app runs in its own Linux network namespace.
- Per-namespace `resolv.conf` (no DNS leaks) and routing (no host-route leaks).
- **Per-profile kill switch** — if the tunnel drops, the namespace fails closed
  (no fallback to the host's default route).
- Separate data directory per profile (cookies, sessions, cache are scoped).

### Zero-capability uplink
- The engine runs **unprivileged** (no `cap_net_admin`, `CapEff=0`) using user
  namespaces + a userspace uplink (pasta). A privileged `veil-bridge` exists
  only as a fallback when pasta is unavailable.
- `install.sh` builds a known-good pasta from source so the uplink works
  consistently across distributions (Debian, Ubuntu, Fedora, Arch, …).

### App launcher
- Launch any binary in the profile's namespace.
- Presets: Firefox, Chromium, Chrome, Brave, Librewolf, Thunderbird, Signal
  Desktop, Telegram, Element, curl, shell.
- Custom binaries with arbitrary args; per-profile timezone / locale overrides.

### GUI + CLI
- GUI: profile list with status, one-click launch, per-profile external IP +
  geo (checked through the profile's own network), dark mode.
- CLI: `veil list | run <p> [-- cmd] | shell <p> | status | ip <p> | stop <p> |
  selftest <p> | doctor`.

### Deployment
- Native install via `install.sh` (auto-installs dependencies per distro).
- Docker: a hardened container image (capless by default; an optional
  browser variant for headful isolated browsing). See `packaging/docker/`.

### Provider helpers (optional)
Raw WireGuard / OpenVPN configs always work; importers for Mullvad, ProtonVPN,
and IVPN bundles make setup nicer.

### No telemetry
- **Free edition: zero network calls from veil itself.** No update checks, no
  analytics, no phone-home, ever.
- **Pro edition** validates the license fully offline (Ed25519 signature, no
  network). It has exactly two network features, both opt-in-by-action and both
  carrying no usage data:
  - **Updates** happen only when you run `veil update`. Nothing updates on a
    launch, a timer, or in the background.
  - **Activation** sends ONE logging ping on `veil license install` so the
    seller can see how widely a license is used (a courtesy against quiet
    redistribution). It sends your license token, the version, and a per-machine
    id that is a **one-way hash** of your system machine-id (not hardware, MAC,
    hostname, or user; not reversible). It is **visibility only**: it never gates
    Pro, never enforces a device limit, and Pro keeps working offline, airgapped,
    or firewalled regardless. Remove a machine from the record with
    `veil license deactivate`.

---

## Pro edition (commercial)

The Pro edition adds a layered **anti-detect** stack on top of the free
isolation engine. Summarized at a high level (implementation is proprietary):

- **Fingerprint impersonation** — aligns transport and browser fingerprints
  (TCP, TLS, HTTP/2, and browser-level identity) with a chosen persona, to
  defeat passive and active fingerprinting.
- **Persona system** — a coherent identity (user agent, locale, timezone,
  hardware, GPU, client hints, …) kept consistent across every layer.
- **Persona forge** — deterministic, realistic, unique identities per profile.
- **Locked endpoint / schedule guard / drift detection** — refuse to launch if
  the exit IP / geo / ASN or the time-of-day drifts from the persona.
- **Behavioral jitter** — defeats keystroke- and mouse-dynamics fingerprinting.
- **Advanced Tor controls** — new-circuit on demand, exit-country selection,
  bridges / pluggable transports.
- **TLS inspection proxy + CA management.**
- **veil-browser** — a hardened browser build with persona pinning, delivered
  with signed binary updates.
- **Email support.**

Pro is delivered as a licensed, signed binary; a valid license is verified
offline (Ed25519). Use it on your own machines. There is no device cap: on
install it sends one logging ping (see **No telemetry** above) so the seller can
spot a license being shared publicly, but nothing is ever blocked. See the
project website for how to obtain a license.

---

## Threat model (honest)

**Protects against:** per-app DNS leaks; IP correlation across profiles on one
machine; cookie / session bleed between identities; apps that ignore system
proxy settings; tunnel drops exposing traffic (kill switch fails closed);
casual work/personal correlation.

**Does NOT protect against:** application-level browser fingerprinting unless
the anti-fingerprint features are enabled (deep timing side channels remain);
global-passive-adversary timing correlation; malware already on the host;
logging into a real-name account inside an "anonymous" profile (the biggest
footgun); a compromised VPN / proxy / Tor exit; OS-level leaks outside the
namespace (clipboard, filesystem).

**Tor specifically:** anonymity requires separate identities — the moment you
log into a real-name account in a Tor profile, anonymity is gone for that
session. veil surfaces this at profile-creation time, not buried in docs.

**Disclaimer.** veil is provided "as is", with no warranty. The authors accept
no liability for any damages — including an IP/DNS leak, a kill switch that
fails to contain traffic, deanonymization, or data loss — arising from its use.
Verify your setup (`veil doctor`, `veil selftest`) and use at your own risk.
See `LICENSE`.

---

Found a bug? Run `veil bug-report` (CLI) or use **Report a bug** in the GUI, or
open an issue at https://github.com/mstampfli/veil/issues. Reports are welcome.
