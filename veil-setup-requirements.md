# Veil — System Setup & Prerequisites

*Host-side configuration required for Veil to function*

**Version:** 0.1
**Purpose:** Document everything Veil needs from the host system, so the installer / docs can handle it automatically or instruct the user clearly.

---

## 1. Why this document exists

Veil creates Linux network namespaces and routes their traffic through the host. This requires several kernel features to be available and several system-level settings to be configured. On many distros these are off by default — especially security-focused ones like Parrot, Kali, Qubes, and hardened Debian/Ubuntu setups.

This spec lists every dependency, why it's needed, how to detect it, and how to configure it. The installer should do this automatically with user consent; the docs should explain each step so power users can do it manually and audit what's being changed.

---

## 2. Required kernel features

All of these must be compiled into the kernel or available as modules. They are present in every mainstream distro kernel from ~2014 onward, but worth checking.

| Feature | Check command | Notes |
|---|---|---|
| Network namespaces | `grep CONFIG_NET_NS /boot/config-$(uname -r)` → should be `=y` | Core requirement |
| veth driver | `lsmod \| grep veth` or `modprobe veth` | Usually auto-loaded on first use |
| iptables / nftables | `command -v iptables` or `command -v nft` | At least one must be present |
| NAT (netfilter) | `lsmod \| grep nf_nat` | Auto-loaded on first MASQUERADE rule |
| WireGuard (v1) | `lsmod \| grep wireguard` or `modprobe wireguard` | Kernel 5.6+ has it built in; older kernels need `wireguard-dkms` |

**Installer behavior:** on first run, verify each with a short preflight check. If any are missing, print a specific actionable message ("Your kernel does not support network namespaces. You likely need a standard kernel — are you on a minimal/container kernel?").

---

## 3. Required userspace tools

Veil shells out to these for namespace and tunnel setup. The Go code uses `vishvananda/netlink` where possible to avoid shelling out, but some operations (OpenVPN, optional WireGuard wrapper) need binaries.

| Tool | Package (Debian/Ubuntu/Parrot) | Package (Fedora/RHEL) | Package (Arch) | Required for |
|---|---|---|---|---|
| `ip` (iproute2) | `iproute2` | `iproute` | `iproute2` | Namespaces, interfaces, routing |
| `iptables` | `iptables` | `iptables-services` | `iptables` | NAT, forwarding rules |
| `dbus-launch` | `dbus-x11` | `dbus-x11` | `dbus` | Silences Firefox/Chromium warnings in namespace |
| `tor` (optional) | `tor` | `tor` | `tor` | Tor backend (Level 1 uses system tor) |
| `openvpn` (optional) | `openvpn` | `openvpn` | `openvpn` | OpenVPN backend |
| `wireguard-tools` (optional) | `wireguard-tools` | `wireguard-tools` | `wireguard-tools` | Only if using `wg-quick` fallback instead of userspace |

**Installer behavior:** check with `command -v`. If missing, offer to run the appropriate install command (behind a confirmation prompt). Don't install silently.

---

## 4. Required kernel parameters (sysctl)

These are runtime settings. They persist until reboot unless written to `/etc/sysctl.d/`.

### 4.1 IP forwarding — **required**

Enables the kernel to route packets between interfaces. Without this, packets from the namespace can't leave the host.

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

For IPv6 (if using IPv6 tunnels):
```bash
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

**Persistent:** write to `/etc/sysctl.d/99-veil.conf`:
```
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
```

**Security consideration:** this enables forwarding system-wide, not just for Veil. On a typical desktop this is harmless (no other traffic is being asked to forward). Document this clearly so the security-conscious audience understands.

### 4.2 Reverse path filtering — **may need loosening**

`rp_filter` causes the kernel to drop packets whose source address doesn't match the expected route. Strict mode (value `1`) can drop Veil's namespace traffic in some configurations.

```bash
# Check current values
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
```

If either is `1` and Veil's traffic is being dropped, set to `2` (loose mode) for the veth interface specifically:

```bash
sudo sysctl -w net.ipv4.conf.veth0.rp_filter=2
```

**Detection:** only needed if ping from namespace to internet fails despite FORWARD rules being correct. Most users won't hit this.

---

## 5. Firewall rules — **THIS IS THE MAIN STUMBLING BLOCK**

Most distros ship with a FORWARD policy of DROP (good security default). Veil needs explicit rules to allow forwarding for its namespace subnet.

### 5.1 iptables (legacy but still widely used)

```bash
# Allow forwarding for Veil's subnet (replace 10.200.0.0/24 with Veil's configured subnet)
sudo iptables -I FORWARD 1 -s 10.200.0.0/24 -j ACCEPT
sudo iptables -I FORWARD 2 -d 10.200.0.0/24 -j ACCEPT

# NAT (masquerade) for traffic leaving the host
sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -j MASQUERADE
```

**Important:** use `-I FORWARD 1` (insert at top) not `-A FORWARD` (append). On systems with Docker installed, Docker's rules come first and will intercept / drop traffic before Veil's rules get a chance.

### 5.2 nftables (modern default on newer distros)

```bash
# Create Veil table and chains
sudo nft add table inet veil
sudo nft 'add chain inet veil forward { type filter hook forward priority -10 ; }'
sudo nft 'add chain inet veil postrouting { type nat hook postrouting priority 100 ; }'

# Forward rules
sudo nft add rule inet veil forward ip saddr 10.200.0.0/24 accept
sudo nft add rule inet veil forward ip daddr 10.200.0.0/24 accept

# NAT (masquerade)
sudo nft add rule inet veil postrouting ip saddr 10.200.0.0/24 masquerade
```

**Detection logic in installer:**
- If `iptables-nft` is the actual backend (Debian 11+, Parrot 6+), rules written via `iptables` command still work but are stored as nft rules underneath
- `nft list ruleset` is the source of truth on modern systems
- Safest: detect which is in use by running `iptables --version` (will say `nf_tables` if backed by nft), and if unclear, use both commands (nft rules will be ignored if legacy is active and vice versa)

### 5.3 UFW (Ubuntu default)

UFW is a frontend for iptables. On systems using UFW, editing iptables directly can conflict. The correct way:

```bash
# Edit /etc/ufw/before.rules and add BEFORE the "*filter" line:
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.200.0.0/24 -o <WAN_INTERFACE> -j MASQUERADE
COMMIT

# Edit /etc/default/ufw and set:
DEFAULT_FORWARD_POLICY="ACCEPT"

# Reload
sudo ufw reload
```

Where `<WAN_INTERFACE>` is typically `eth0`, `wlan0`, `wlp3s0`, etc. — detect with `ip route show default`.

### 5.4 firewalld (Fedora/RHEL default)

```bash
# Enable masquerading on the external zone
sudo firewall-cmd --permanent --zone=public --add-masquerade

# Allow forwarding (firewalld permits by default in most zones, but verify)
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s 10.200.0.0/24 -j ACCEPT
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -d 10.200.0.0/24 -j ACCEPT

sudo firewall-cmd --reload
```

### 5.5 Docker interference — **common issue, document prominently**

If Docker is installed, it manipulates iptables aggressively:
- Creates its own `DOCKER`, `DOCKER-USER`, `DOCKER-FORWARD` chains
- Sets FORWARD policy to DROP
- Inserts its rules at the top of FORWARD

**Symptom:** Veil worked before Docker was installed/started, or works until Docker is restarted.

**Fix:** always use `-I FORWARD 1` to insert Veil rules above Docker's. Veil's installer should detect Docker's presence (`command -v docker`) and warn if the user has Docker running, explaining that Docker restarts may clobber rules and that persistent rules via `iptables-persistent` or a systemd unit are recommended.

---

## 6. DNS configuration per namespace

Each namespace can have its own `resolv.conf` at `/etc/netns/<namespace>/resolv.conf`. This file is bind-mounted over `/etc/resolv.conf` automatically when a process runs in the namespace.

```bash
sudo mkdir -p /etc/netns/veil-<profile>
echo "nameserver 1.1.1.1" | sudo tee /etc/netns/veil-<profile>/resolv.conf
echo "nameserver 9.9.9.9" | sudo tee -a /etc/netns/veil-<profile>/resolv.conf
```

**Why this matters:** without a per-namespace resolv.conf, DNS queries will try the host's default DNS, which may bypass the tunnel and leak. This is the DNS leak issue Veil explicitly protects against.

**Installer behavior:**
- Create the directory on profile creation
- Default to 1.1.1.1 + 9.9.9.9 but let user configure
- When using Tor backend, set resolv.conf to a dummy value and route DNS through Tor (SOCKS proxy mode) — raw DNS over Tor is a known leak vector; use `tor` + `dnscrypt-proxy` pattern or rely on application-level DNS-over-SOCKS

---

## 7. GUI app launching — environment passthrough

Network namespaces isolate networking only, **not** filesystems or IPC sockets. GUI apps inside the namespace can still reach Wayland/X11 sockets on the host filesystem, but only if the right environment variables are passed through.

### 7.1 Required env vars for GUI apps

| Variable | Example value | Purpose |
|---|---|---|
| `DISPLAY` | `:0` | X11 display server (even if mainly using Wayland, XWayland fallback uses this) |
| `WAYLAND_DISPLAY` | `wayland-0` | Wayland compositor socket name |
| `XDG_RUNTIME_DIR` | `/run/user/1000` | Base dir for runtime sockets (Wayland, dbus, pulse, etc.) |
| `DBUS_SESSION_BUS_ADDRESS` | `unix:path=/run/user/1000/bus` | User's session dbus (needed by many GUI apps) |
| `HOME` | `/home/username` | sudo sometimes wipes this; apps expect it set |
| `USER` | `username` | Same |
| `XAUTHORITY` | `/home/username/.Xauthority` | X11 auth cookie (if using X11) |
| `PULSE_SERVER` | (optional) | Audio — only needed if app plays sound |

### 7.2 The critical `sudo` gotcha

`sudo` strips environment by default. When launching a process as the user inside a namespace, explicit env passthrough is required:

```bash
sudo ip netns exec veil-<profile> sudo -u <user> env \
  DISPLAY="$DISPLAY" \
  WAYLAND_DISPLAY="$WAYLAND_DISPLAY" \
  XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
  DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" \
  HOME="/home/<user>" \
  <command>
```

Veil's launcher should capture these from the user's environment at launch time, not hardcode them.

### 7.3 Firefox / Chromium specifics

- Always launch with `--no-remote` (or `--user-data-dir=<path>` for Chromium). Otherwise the browser detects an existing instance and hands off, bypassing the namespace entirely. **This is the #1 silent failure mode.**
- Use `--profile <path>` (Firefox) or `--user-data-dir <path>` (Chromium) for per-profile isolation
- For Wayland: set `MOZ_ENABLE_WAYLAND=1` for Firefox to use Wayland natively (optional, but better rendering on Wayland systems)

---

## 8. Permissions model

Veil needs root for: namespace creation, veth setup, iptables/nftables rules, routing changes, writing `/etc/netns/*/resolv.conf`.

Veil does NOT need root for: launching the user app inside the namespace (uses `sudo -u <user>` to drop privileges).

### 8.1 Options for the installer

1. **Setuid binary** — simplest, but security-sensitive. Not recommended for a privacy tool.
2. **Polkit rules** — grant specific commands to the user. Cleaner but distro-specific.
3. **Privileged helper daemon** — Veil daemon runs as root, GUI/CLI talks to it over a Unix socket with permission checks. Most robust, more complex.
4. **sudo wrapper** — require the user to run `sudo veil` or configure sudoers. Simplest, acceptable for v1.

**v1 recommendation:** sudo wrapper. Document a `sudoers.d/veil` file for users who want passwordless Veil:
```
%veilusers ALL=(root) NOPASSWD: /usr/bin/veil
```

**v2:** privileged helper daemon pattern (option 3).

---

## 9. Systemd / session integration

### 9.1 No systemd required for core function

Veil works on systemd-less systems (Artix, Devuan, Void, Alpine). Namespaces are a kernel feature, not a systemd feature.

### 9.2 Optional systemd integration for auto-connect

Pro tier feature "auto-connect on boot" uses systemd user units:

```ini
# ~/.config/systemd/user/veil-<profile>.service
[Unit]
Description=Veil profile: <profile>
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/veil run <profile> --daemon
Restart=on-failure

[Install]
WantedBy=default.target
```

Non-systemd users: document manual startup script approach.

---

## 10. Uninstall & cleanup

**Critical:** Veil must leave no trace on uninstall. Privacy audience will audit this.

### 10.1 What Veil creates
- `/etc/netns/veil-*/` directories
- `~/.config/veil/` (user configs)
- iptables/nftables rules (runtime)
- sysctl settings (runtime, or persistent in `/etc/sysctl.d/99-veil.conf`)
- veth interfaces (runtime, auto-destroyed with namespace)
- Network namespaces (runtime, `veil-*`)
- Optional: `/etc/sudoers.d/veil`
- Optional: systemd user units

### 10.2 Clean uninstall command

`veil uninstall` must:
1. Stop all running profiles
2. Tear down all veil-* namespaces and veth pairs
3. Remove all Veil iptables/nftables rules (matched by 10.200.0.0/24 or whatever subnet is configured)
4. Remove `/etc/netns/veil-*/` directories
5. Remove `/etc/sysctl.d/99-veil.conf` (if created)
6. Remove `/etc/sudoers.d/veil` (if created)
7. Leave `~/.config/veil/` unless `--purge` is specified
8. Not touch `net.ipv4.ip_forward` current value (user may have set it for other reasons)

Print a summary of what was removed.

---

## 11. Preflight check — what `veil doctor` should verify

A diagnostic command that users run when something's not working. Output should be actionable.

```
$ veil doctor

Checking kernel features...
  ✓ Network namespaces (CONFIG_NET_NS=y)
  ✓ veth driver available
  ✓ iptables backend: nftables
  ✓ WireGuard kernel module loaded

Checking userspace tools...
  ✓ ip (iproute2 6.1.0)
  ✓ iptables (1.8.9)
  ✓ dbus-launch
  ✗ tor (not installed) — Tor backend will be unavailable
  ✗ openvpn (not installed) — OpenVPN backend will be unavailable

Checking kernel parameters...
  ✓ net.ipv4.ip_forward = 1

Checking firewall...
  ✓ FORWARD policy: DROP (correct, with Veil rules inserted)
  ✓ Veil FORWARD rules present (2 rules for 10.200.0.0/24)
  ✓ NAT POSTROUTING rule present
  ⚠ Docker detected — FORWARD rules must be at top of chain (currently at position 1, OK)

Checking session environment...
  ✓ DISPLAY=:0
  ✓ WAYLAND_DISPLAY=wayland-0
  ✓ XDG_RUNTIME_DIR=/run/user/1000
  ✓ Running as UID 1000 (parrot)

Checking permissions...
  ✓ sudo access confirmed
  ⚠ Passwordless sudo for veil not configured — you'll be prompted each launch
    (Install /etc/sudoers.d/veil with `veil setup sudoers`)

Overall status: READY
2 optional backends unavailable (tor, openvpn). Install if needed.
```

---

## 12. Known distro-specific quirks

| Distro | Quirk |
|---|---|
| **Parrot OS** | FORWARD policy DROP by default + Docker often pre-installed → requires `-I FORWARD 1` insertion. Uses nftables backend. |
| **Kali Linux** | Similar to Parrot; FORWARD may be ACCEPT depending on install. |
| **Qubes OS** | Each VM is already isolated; Veil inside a VM works but is redundant with Qubes' own compartmentalization. |
| **NixOS** | iptables rules don't persist normally; must be declared in `configuration.nix` via `networking.firewall`. Document the NixOS snippet. |
| **Ubuntu (UFW)** | UFW overrides raw iptables on reload; see section 5.3 for correct configuration. |
| **Fedora (firewalld)** | See section 5.4. |
| **Arch / Manjaro** | Minimal base; `iptables-nft` is default. Usually no FORWARD issues. |
| **SystemD-Resolved systems** | `/etc/resolv.conf` is a symlink to a stub; per-namespace resolv.conf still works because it's a separate file. |
| **Immutable distros (Silverblue, openSUSE MicroOS)** | `/etc/netns/` may be read-only; requires different setup. Defer support. |
| **Flatpak-only distros** | Veil needs system-level access; won't work as a Flatpak with full sandbox. Must be installed as native binary. |

---

## 13. Installer flow — recommended UX

First-run `veil setup` should:

1. Print what it's about to do, in plain language
2. Ask for confirmation for each privileged change
3. Run `veil doctor` at the end
4. Show a success summary with the first command to try (`veil run <example>`)

```
$ sudo veil setup

Veil setup assistant

This will configure your system to run Veil. You'll be shown each change
and asked before anything is modified.

[1/6] Enable IP forwarding (sysctl net.ipv4.ip_forward=1)
      This is required for Veil to route namespace traffic to the internet.
      It has no effect on your normal traffic.
      [y/N]: y
      ✓ Enabled (also written to /etc/sysctl.d/99-veil.conf for persistence)

[2/6] Configure firewall rules
      Detected backend: nftables
      Will insert FORWARD ACCEPT rules for Veil's subnet (10.200.0.0/24)
      and a NAT MASQUERADE rule for outgoing traffic.
      [y/N]: y
      ✓ Rules installed

[3/6] Install optional dependencies
      Recommended: dbus-x11 (silences dbus warnings when launching GUI apps)
      Optional: tor (for Tor backend), openvpn (for OpenVPN backend)
      [y/N]: y
      ✓ Installed

[4/6] Configure passwordless sudo for Veil
      This avoids password prompts on every `veil run`.
      Adds a rule to /etc/sudoers.d/veil for your user only.
      [y/N]: n
      → Skipped. You'll be prompted for password on each run.

[5/6] Create default profiles directory
      ✓ Created ~/.config/veil/profiles/

[6/6] Run preflight check
      ✓ All required features present
      ✓ Network configuration correct
      ✓ GUI environment detected

Setup complete. Try: veil run --example firefox-direct
```

---

## 14. Pre-launch checklist for users (docs)

For the landing page / README. A simple checklist a user can eyeball before installing:

- [ ] Linux kernel 5.6 or newer (or WireGuard DKMS installed)
- [ ] iptables or nftables available
- [ ] You're running a graphical session (Wayland or X11)
- [ ] You have sudo access
- [ ] You're NOT in a container/chroot (namespaces inside containers require extra privileges)
- [ ] If you have Docker: understand that restarting Docker may clobber firewall rules (Veil will warn)

If all above are true: `curl -sSL veil.ch/install.sh | sh` (or your preferred install method).

---

*End of setup requirements spec.*
