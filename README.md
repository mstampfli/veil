# Veil

> [!CAUTION]
> ## Veil is unmaintained, and it is NOT secure.
>
> Veil is no longer developed. It has had no security review that its current code would pass,
> known and unknown leaks may exist, and nothing in it is kept up to date with the tools it
> drives (WireGuard, OpenVPN, Tor, iptables). Do not rely on it to hide your traffic or your
> identity. Read it as a learning project, not as a privacy tool.
>
> Nothing here comes with any guarantee. Treat every "works" in this repository as "worked on the
> author's machine at the time".

Veil routes an application through a tunnel chain (WireGuard, OpenVPN, SOCKS5, HTTP proxy, Tor)
inside its own network namespace, one namespace per profile, with an iptables kill switch that is
read back at launch. This repository is the free edition (PolyForm Noncommercial).

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

Partial support. macOS uses `pf` instead of iptables; Windows uses Wintun. See
`docs/CROSS_PLATFORM.md` for the feature matrix.

## Quickstart (per-app VPN)

```bash
veil profile import-mullvad ~/Downloads/mullvad-wg/      # one profile per server
veil run mullvad-de-fra-wg-001 -- firefox
```

Or via GUI: **Profiles > New > Network chain > Add hop > WireGuard > save > Launch.**

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

## Disclaimer

veil is provided **"as is", with no warranty of any kind**. **The authors accept no liability for
any damages**, including, without limitation, an IP or DNS leak, a kill switch that fails to
contain traffic, deanonymization, or data loss, arising from use of veil. See `LICENSE` for the
full terms.

## License

Veil free edition: **PolyForm Noncommercial 1.0.0** (source-available: use, modify, and contribute
for noncommercial purposes). See `LICENSE`. Third-party notices: `THIRD_PARTY_NOTICES`.

## Trademarks

Veil is not affiliated with, endorsed by, or related to Mozilla, Brave Software, The Tor Project,
Mullvad, or Google. "Tor", "Brave", "Firefox", "Chrome", and other names referenced are trademarks
of their respective owners.
