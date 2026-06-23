# Veil

**Per-app tunnel isolation + anti-detect identity engine.**

Veil routes any application through any tunnel chain (WireGuard, OpenVPN, SOCKS5, HTTP proxy, Tor) inside its own network namespace, then layers fingerprint impersonation on top: TCP / TLS / HTTP-2 / browser identity all consistent with a chosen persona.

Local-first. No telemetry. Source-available (free edition: PolyForm Noncommercial).

---

## What you get

| Layer | What it does |
|---|---|
| **Network namespace per profile** | Each profile is a fully isolated network stack. Apps in profile A literally cannot see profile B's traffic. |
| **Chain composability** | Stack hops freely: VPN → Tor → SOCKS5, Tor with bridges, multi-hop WireGuard, etc. |
| **Kill switch (verified)** | iptables rules drop everything outside the tunnel. Veil reads back the rules at launch and refuses to start if they didn't install correctly. Fail-closed verified, not assumed. |
| **TCP fingerprint spoofing** *(Pro)* | NFQUEUE rewrites SYN options + window scale + TTL + MSS to match a chosen OS persona. Defeats p0f-style passive OS detection. |
| **TLS impersonation** *(Pro)* | uTLS-pinned ClientHello matches Chrome / Firefox / Safari byte-for-byte. JA3/JA4 signatures align with the persona's claimed browser. |
| **HTTP/2 mediator** *(Pro)* | SETTINGS frame, WINDOW_UPDATE pacing, HPACK header order all rewritten to match the target browser. |
| **Persona system** *(Pro)* | UA, locale, timezone, screen, hardware concurrency, GPU strings, Client Hints, all consistent across every layer. |
| **Persona forge** *(Pro)* | Generate a deterministic, realistic, unique identity per profile (`veil persona forge work-twitter`). Same name → same persona forever. Different profiles → different real-looking people. |
| **Locked endpoint** *(Pro)* | Profile refuses to launch if exit IP / city / ASN drifts from claimed persona. Auto-captures on first run. |
| **Schedule guard** *(Pro)* | Refuses to launch outside the persona's plausible hours (HH:MM-HH:MM in persona TZ). |
| **Behavioral jitter** *(Pro)* | uinput keyboard + mouse jitter defeats keystroke-dynamics + mouse-curvature fingerprinting. |
| **Audit log + crash reports** | JSON-lines security events at `~/.config/veil/audit.log`. Critical failures snapshot full state to `~/.config/veil/crashes/`. |
| **veil-browser** *(Pro)* | A Brave-derived Chromium fork with 85 anti-detect patches: persona-pinned at the C++ layer, including engine spoofing (gecko/webkit) so a single binary impersonates any browser on any OS. Build instructions at `veil-browser/BUILD.md`. |

## Free vs Pro

| | Free | Pro |
|---|---|---|
| Per-app netns isolation | ✓ | ✓ |
| All chain backends (WG/OVPN/Tor/SOCKS5/HTTP) | ✓ | ✓ |
| Kill switch | ✓ | ✓ |
| GUI + CLI + bulk import (Mullvad/Proton/IVPN configs) | ✓ | ✓ |
| Tor (basic) | ✓ | ✓ |
| Anti-detect stack (TCP/TLS/HTTP-2 spoofing) | ✗ | ✓ |
| Persona system + forge | ✗ | ✓ |
| Locked endpoint + schedule guard + drift detection | ✗ | ✓ |
| Behavioral jitter + CPU throttle | ✗ | ✓ |
| Tor advanced (NEWNYM, ExitCountry, bridges/obfs4) | ✗ | ✓ |
| TLS-MITM proxy + CA management | ✗ | ✓ |
| veil-browser binary updates | ✗ | ✓ |
| Email support | ✗ | ✓ |

The Free tier is **vopono-equivalent + a GUI**. Use it if you just want per-app VPN/Tor with kill switch.

The Pro tier is the anti-detect stack on top: layered fingerprint impersonation across the whole transport+browser surface.

## Install

### Linux (Debian/Parrot/Ubuntu)

```bash
sudo apt install -y wireguard openvpn tor curl iptables
make build
sudo cp bin/veil bin/veil-gui /usr/local/bin/
sudo veil setup     # one-time: ip_forward, sudoers entry
veil-gui            # GUI; or: veil --help
```

### Linux (Fedora / Arch)

Same flow, different package manager. See `docs/CROSS_PLATFORM.md` for full requirements.

### macOS / Windows

Partial support today. macOS uses `pf` instead of iptables; Windows uses Wintun. Some pro features (TCP-options rewrite, time namespace) are Linux-only, see `docs/CROSS_PLATFORM.md` for the feature matrix.

## Quickstart: free tier (per-app VPN)

```bash
veil profile import-mullvad ~/Downloads/mullvad-wg/      # → one profile per server
veil run mullvad-de-fra-wg-001 -- firefox
```

Or via GUI: **Profiles → New → Network chain → Add hop → WireGuard → save → Launch.**

## Quickstart: Pro tier (anti-detect)

```bash
# Forge a unique persona for this profile (Pro)
veil persona forge work-twitter
# → "Windows Chrome 134, Intel UHD, 1920×1080, 4 cores, US/Pacific, ..."

# Create a profile that pins this persona, locks the endpoint, blocks
# launches outside business hours
cat > ~/.config/veil/profiles/work-twitter.yaml <<EOF
name: work-twitter
chain:
  - kind: wireguard
    config_path: /home/me/wg/mullvad-de-fra.conf
forge_persona: true
locked_endpoint: true
schedule_window: "08:00-22:00"
behavioral_jitter: true
mouse_jitter: true
app:
  preset: veil-browser
EOF

veil run work-twitter
veil profile drift work-twitter   # confirm exit matches persona claims
veil profile probe work-twitter   # DNS/IPv6/listening-socket leak tests
```

## veil-browser

> Note: the veil-browser patch tree is large and is maintained as a separate project; it is not included in this repository.

The Pro tier includes a custom Chromium fork (`veil-browser/`) with 85 patches that pin every fingerprint-relevant value at the C++ layer:

- navigator.* identity (UA, platform, vendor, hardwareConcurrency, deviceMemory, …)
- Engine globals (`InstallTrigger` for gecko personas, `webkitURL` for webkit, etc.)
- Function.prototype.toString format per engine
- V8 error message text per engine
- Canvas / WebGL / audio / font readback (deterministic per persona)
- Client Hints (sec-ch-ua-platform, -version, -arch, -bitness, …)
- Timezone + locale at engine level
- Window Management API (getScreenDetails)
- Storage quota, MediaCapabilities, RTC capabilities, font enumeration, system colors
- JIT compile-timing fuzz, GC pause normalization, Float32 NaN canonicalization

Build with: `cd veil-browser/scripts && ./fetch.sh && ./apply-patches.sh && ./build.sh` (4-8h first build, ~30 GB source, ~60 GB output).

## Development

```bash
make build          # CLI + GUI
make test           # all tests
make vet
make verify-reproducible   # build twice, byte-compare
```

Project layout:
- `cmd/veil/`, CLI entry point
- `cmd/veil-gui/`, Wails GUI
- `internal/engine/`, namespace + chain lifecycle
- `internal/backends/`, wireguard, openvpn, tor, socks5, http, tlsmitm
- `internal/persona/`, persona model + forge + bundled defaults
- `internal/launcher/`, app launch + persona application
- `internal/audit/`, security event log + crash reports
- `internal/validate/`, input validation
- `internal/osutil/`, atomic file writes
- `veil-browser/`, Chromium fork patches + build scripts

## Disclaimer

veil is provided **"as is", with no warranty of any kind**, and is a privacy
tool — not a guarantee. **The authors accept no liability for any damages** —
including, without limitation, an IP or DNS leak, a kill switch that fails to
contain traffic, deanonymization, or data loss — arising from use of veil.
Verify your own setup (`veil doctor`, `veil selftest <profile>`), understand the
threat model (`docs/SPEC.md`), and use at your own risk. See `LICENSE` for the
full terms.

Found a bug? Please report it — `veil bug-report`, or open an issue at
https://github.com/mstampfli/veil/issues. Bug reports genuinely help.

## License

Veil free edition: **PolyForm Noncommercial 1.0.0** (source-available — use, modify, and contribute for noncommercial purposes; commercial use requires a separate license). See `LICENSE`. veil-browser patches: MPL-2.0 (matching upstream Brave/Chromium MPL files). Third-party notices: `THIRD_PARTY_NOTICES`.

## Trademarks

Veil is not affiliated with, endorsed by, or related to Mozilla, Brave Software, The Tor Project, Mullvad, or Google. "Tor", "Brave", "Firefox", "Chrome", and other names referenced are trademarks of their respective owners.
