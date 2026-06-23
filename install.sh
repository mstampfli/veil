#!/bin/bash
# Veil — single end-to-end install script.
#
# Run from the project root:
#
#     sudo ./install.sh
#
# What it does (in order; every step is idempotent so re-running is
# safe):
#
#   1. Builds bin/veil, bin/veil-gui, bin/veil-bridge from source.
#   2. Installs all three binaries to /usr/local/bin and
#      /usr/local/libexec.
#   3. Grants veil-bridge cap_net_admin via setcap.
#   4. Creates the `veil` system group and adds the invoking user
#      to it.
#   5. Writes udev rules so the `veil` group can open /dev/net/tun
#      and /dev/uinput. Reloads + triggers udev.
#   6. Creates /run/netns and /etc/netns as bind-mount targets the
#      user-ns engine path needs.
#   7. Installs the .desktop entry with VEIL_USERNS_ENGINE=1 baked
#      in (no password prompt at launch).
#   8. Installs the polkit policy + icon.
#   9. Installs the veil-gui-launcher script.
#  10. Refreshes the desktop database.
#  11. Prints exactly what the user has to do next (newgrp / re-login
#      so the veil group is active in their session).
#
# To uninstall everything: sudo ./install.sh --uninstall

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
LIBEXEC_DIR="$PREFIX/libexec"
ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
APP_DIR="/usr/share/applications"
POLKIT_DIR="/usr/share/polkit-1/actions"
UDEV_DIR="/etc/udev/rules.d"

REQUIRE_ROOT() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This installer needs root: sudo ./install.sh"
    exit 1
  fi
}

uninstall() {
  REQUIRE_ROOT
  echo "Uninstalling Veil..."
  rm -f "$BIN_DIR/veil" "$BIN_DIR/veil-gui" "$BIN_DIR/veil-gui-launcher"
  rm -f "$LIBEXEC_DIR/veil-bridge"
  rm -f "$ICON_DIR/veil.svg"
  rm -f "$APP_DIR/veil.desktop"
  rm -f "$POLKIT_DIR/com.veil.gui.policy"
  rm -f "$UDEV_DIR/70-veil-tun.rules"
  rm -f "$UDEV_DIR/71-veil-uinput.rules"
  rm -f /etc/sysctl.d/99-veil.conf
  command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "/usr/share/icons/hicolor" || true
  command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" || true
  command -v udevadm >/dev/null && udevadm control --reload-rules || true
  echo "Uninstall complete. The 'veil' group and ~/.config/veil are left intact."
  echo "  - To remove the group:    sudo groupdel veil"
  echo "  - To remove user config:  rm -rf ~/.config/veil"
  exit 0
}

case "${1:-}" in
  --uninstall|uninstall) uninstall ;;
esac

REQUIRE_ROOT
cd "$PROJECT_ROOT"

step() { echo; echo "==> $*"; }
ok()   { echo "    ✓ $*"; }
warn() { echo "    ⚠ $*"; }

# ----------------------------------------------------------------- build
step "Checking build dependencies"
if ! command -v go >/dev/null 2>&1; then
  echo "Go toolchain not found. Install Go 1.22+ and retry."
  exit 1
fi
# The GUI (veil-gui) is a CGo/Wails app and needs pkg-config plus the GTK3
# and WebKit2GTK-4.1 development libraries — none of which ship on a clean
# server install. Without this preflight `make build` dies at `make gui`
# with a bare "pkg-config: executable file not found", which is opaque.
# Detect what's missing, try to install it via the platform package manager
# (opt out with VEIL_NO_BUILDDEP_INSTALL=1), then re-check and fail loudly.
build_deps_missing() {
  local miss=()
  command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || miss+=("a C compiler")
  command -v pkg-config >/dev/null 2>&1 || command -v pkgconf >/dev/null 2>&1 || miss+=("pkg-config")
  if command -v pkg-config >/dev/null 2>&1; then
    pkg-config --exists gtk+-3.0 2>/dev/null || miss+=("gtk+-3.0 dev")
    pkg-config --exists webkit2gtk-4.1 2>/dev/null || miss+=("webkit2gtk-4.1 dev")
  fi
  printf '%s\n' "${miss[@]}"
}
missing_bd="$(build_deps_missing)"
if [ -n "$missing_bd" ] && [ "${VEIL_NO_BUILDDEP_INSTALL:-0}" != "1" ]; then
  echo "  missing GUI build deps:"; echo "$missing_bd" | sed 's/^/    - /'
  step "Installing GUI build dependencies"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev \
      || { apt-get update && apt-get install -y build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev; } || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm base-devel pkgconf gtk3 webkit2gtk-4.1 || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y gcc pkg-config gtk3-devel webkit2gtk3-soup2-devel || true
  fi
fi
missing_bd="$(build_deps_missing)"
if [ -n "$missing_bd" ]; then
  echo "ERROR: cannot build the GUI — still missing:"; echo "$missing_bd" | sed 's/^/  - /'
  echo "Install the GTK3 + WebKit2GTK-4.1 dev packages and pkg-config, then re-run."
  echo "  Debian/Ubuntu: sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev"
  echo "  Fedora:        sudo dnf install gcc pkgconf-pkg-config gtk3-devel webkit2gtk4.1-devel"
  echo "  Arch:          sudo pacman -S base-devel pkgconf gtk3 webkit2gtk-4.1"
  exit 1
fi
ok "build deps present (pkg-config, gtk+-3.0, webkit2gtk-4.1, C compiler)"

step "Building binaries"
build_log="$(mktemp)"
if ! sudo -u "${SUDO_USER:-$(whoami)}" -H --preserve-env=PATH,GOTOOLCHAIN,GOFLAGS,GOCACHE,GOPATH,GOMODCACHE \
     bash -c "cd '$PROJECT_ROOT' && make build" >"$build_log" 2>&1; then
  echo "Build failed:"; tail -25 "$build_log" | sed 's/^/  /'; rm -f "$build_log"; exit 1
fi
rm -f "$build_log"
for f in bin/veil bin/veil-gui bin/veil-bridge; do
  if [ ! -x "$f" ]; then
    echo "Build failed: missing $f"
    exit 1
  fi
done
ok "built veil, veil-gui, veil-bridge"

# ---------------------------------------------------------------- binaries
step "Installing binaries to $BIN_DIR and $LIBEXEC_DIR"
install -d "$BIN_DIR" "$LIBEXEC_DIR"
install -m 0755 bin/veil          "$BIN_DIR/veil"
install -m 0755 bin/veil-gui      "$BIN_DIR/veil-gui"
install -m 0755 packaging/veil-gui-launcher "$BIN_DIR/veil-gui-launcher"
install -m 0755 bin/veil-bridge   "$LIBEXEC_DIR/veil-bridge"
ok "veil          → $BIN_DIR/veil"
ok "veil-gui      → $BIN_DIR/veil-gui"
ok "veil-gui-launcher → $BIN_DIR/veil-gui-launcher"
ok "veil-bridge   → $LIBEXEC_DIR/veil-bridge"

# --------------------------------------------------------------- uplink
# The user-ns engine needs pasta (userspace) for the netns uplink — NO host
# capability. Distro passt packages vary too much to rely on for this: too old
# on Debian 12 (cannot attach to the user-ns child), and Arch's build fails the
# attach even at a current version. So by DEFAULT veil builds a known-good pasta
# from source and installs it where the engine prefers it
# ($LIBEXEC_DIR/veil/pasta) — identical behavior on every distro, and outside
# /usr/bin it also dodges the distro's passt AppArmor profile.
#   VEIL_NO_PASTA_BUILD=1  -> skip the build, use the distro passt instead
#                            (we then patch its AppArmor profile on Debian/Ubuntu)
# Only if no usable pasta results at all do we fall back to the cap_net_admin
# veil-bridge.
PASST_REF="${PASST_REF:-587980c}"
pasta_ok=0   # 0 none, 1 built ours, 2 distro pasta on PATH

ensure_tools() { # ensure the named tools exist, installing via the platform pkg mgr
  local need=() t
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || need+=("$t"); done
  [ ${#need[@]} -eq 0 ] && return 0
  if   command -v apt-get >/dev/null 2>&1; then apt-get install -y "${need[@]}" || { apt-get update && apt-get install -y "${need[@]}"; } || true
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y "${need[@]}" || true
  elif command -v pacman  >/dev/null 2>&1; then pacman -Sy --noconfirm "${need[@]}" || true
  elif command -v zypper  >/dev/null 2>&1; then zypper install -y "${need[@]}" || true
  fi
}

if [ "${VEIL_NO_PASTA_BUILD:-0}" != "1" ]; then
  step "Uplink: building pasta from source ($PASST_REF) for the zero-capability path"
  ensure_tools git make gcc
  if command -v git >/dev/null 2>&1 && command -v make >/dev/null 2>&1; then
    ptmp="$(mktemp -d)"
    if git clone -q https://passt.top/passt "$ptmp/passt" \
       && ( cd "$ptmp/passt" && git checkout -q "$PASST_REF" && make -s ) \
       && [ -x "$ptmp/passt/pasta" ]; then
      install -d "$LIBEXEC_DIR/veil"
      install -m 0755 "$ptmp/passt/pasta" "$LIBEXEC_DIR/veil/pasta"
      [ -f "$ptmp/passt/pasta.avx2" ] && install -m 0755 "$ptmp/passt/pasta.avx2" "$LIBEXEC_DIR/veil/pasta.avx2"
      pasta_ok=1
      ok "pasta built -> $LIBEXEC_DIR/veil/pasta (engine prefers this)"
    else
      warn "pasta build failed; falling back to the distro package"
    fi
    rm -rf "$ptmp"
  else
    warn "git/make unavailable; falling back to the distro passt package"
  fi
fi

# Fallback: distro passt if we didn't build one.
if [ "$pasta_ok" -ne 1 ] && ! command -v pasta >/dev/null 2>&1; then
  step "Uplink: installing distro passt"
  ensure_tools passt
fi
if [ "$pasta_ok" -ne 1 ] && command -v pasta >/dev/null 2>&1; then
  pasta_ok=2
  # AppArmor matters only for the distro passt at /usr/bin (our built copy is at
  # $LIBEXEC_DIR and isn't covered by the profile). Debian 12's profile lacks
  # the `ptrace (read)` rule pasta needs to attach to the user-ns child; add it
  # via a local override + reload. Idempotent; opt out VEIL_NO_APPARMOR_FIX=1.
  prof="/etc/apparmor.d/usr.bin.passt"
  if [ "${VEIL_NO_APPARMOR_FIX:-0}" != "1" ] && [ -f "$prof" ] && command -v apparmor_parser >/dev/null 2>&1; then
    if ! grep -rqs 'ptrace' "$prof" /etc/apparmor.d/local/usr.bin.passt 2>/dev/null; then
      step "Patching passt AppArmor profile (add ptrace read for the netns child)"
      install -d /etc/apparmor.d/local
      printf '  ptrace (read) peer=unconfined,\n' > /etc/apparmor.d/local/usr.bin.passt
      grep -q 'local/usr.bin.passt' "$prof" || sed -i '${s|^}|  include if exists <local/usr.bin.passt>\n}|}' "$prof"
      apparmor_parser -r "$prof" 2>/dev/null && ok "passt AppArmor profile patched + reloaded" \
        || warn "could not reload passt AppArmor profile; if pasta is denied, run: apparmor_parser -r $prof"
    fi
  fi
fi

if [ "$pasta_ok" -ge 1 ]; then
  ok "zero-capability uplink ready (pasta); no cap_net_admin granted; veil-bridge kept as fallback only"
else
  step "Granting cap_net_admin to veil-bridge (no usable pasta)"
  echo "  tip: allow the pasta build (need git+make, unset VEIL_NO_PASTA_BUILD) for the zero-capability path."
  if ! command -v setcap >/dev/null 2>&1; then
    echo "ERROR: setcap not installed (apt: libcap2-bin / dnf: libcap)."
    echo "Either get a working pasta, or install libcap and re-run."
    exit 1
  fi
  setcap cap_net_admin+ep "$LIBEXEC_DIR/veil-bridge"
  ok "cap_net_admin+ep applied (bridge fallback)"
fi

# ---------------------------------------------------------- runtime deps
# Auto-install the tools the engine shells out to (best-effort; opt out with
# VEIL_NO_DEP_INSTALL=1). Package names differ per distro; the check below is
# the source of truth and errors if anything is still missing afterwards.
if [ "${VEIL_NO_DEP_INSTALL:-0}" != "1" ]; then
  step "Installing runtime deps"
  if   command -v apt-get >/dev/null 2>&1; then
    apt-get install -y iptables iproute2 util-linux procps libnss3-tools tor ca-certificates \
      || { apt-get update && apt-get install -y iptables iproute2 util-linux procps libnss3-tools tor ca-certificates; } || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iptables iproute util-linux procps-ng nss-tools tor ca-certificates || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed iptables-nft iproute2 util-linux procps-ng nss tor ca-certificates || true
  elif command -v zypper >/dev/null 2>&1; then
    zypper install -y iptables iproute2 util-linux procps mozilla-nss-tools tor ca-certificates || true
  fi
fi

step "Verifying runtime deps (iptables, certutil, etc.)"
missing=()
command -v iptables-nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 || missing+=("iptables")
command -v certutil    >/dev/null 2>&1 || missing+=("libnss3-tools (provides certutil)")
command -v ip          >/dev/null 2>&1 || missing+=("iproute2 (provides ip)")
command -v unshare     >/dev/null 2>&1 || missing+=("util-linux (provides unshare)")
command -v sysctl      >/dev/null 2>&1 || missing+=("procps/procps-ng (provides sysctl)")
if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: missing runtime dependencies:"
  for m in "${missing[@]}"; do echo "  - $m"; done
  if command -v apt-get >/dev/null 2>&1; then
    echo
    echo "Install on Debian/Ubuntu/Parrot:"
    echo "  sudo apt install iptables iproute2 util-linux libnss3-tools libcap2-bin procps"
  elif command -v dnf >/dev/null 2>&1; then
    echo
    echo "Install on Fedora/RHEL:"
    echo "  sudo dnf install iptables iproute util-linux nss-tools libcap procps-ng"
  elif command -v pacman >/dev/null 2>&1; then
    echo
    echo "Install on Arch:"
    echo "  sudo pacman -S iptables-nft iproute2 util-linux nss libcap procps-ng"
  fi
  exit 1
fi
ok "all runtime deps present"

# ---------------------------------------------------------------- group
step "Creating 'veil' group + adding invoking user"
if ! getent group veil >/dev/null 2>&1; then
  groupadd --system veil
  ok "created group 'veil'"
else
  ok "group 'veil' already exists"
fi
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
  if id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx veil; then
    ok "user $TARGET_USER already in 'veil'"
  else
    usermod -aG veil "$TARGET_USER"
    ok "added $TARGET_USER to 'veil'"
    NEEDS_RELOGIN=1
  fi
fi

# ----------------------------------------------------------------- udev
step "Installing udev rules"
install -d "$UDEV_DIR"
cat > "$UDEV_DIR/70-veil-tun.rules" <<'EOF'
# /dev/net/tun must be accessible to the user running veil-gui so
# wireguard-go can open it from inside an unprivileged user namespace.
KERNEL=="tun", GROUP="veil", MODE="0660"
EOF
cat > "$UDEV_DIR/71-veil-uinput.rules" <<'EOF'
# /dev/uinput + /dev/input/event* are required for behavioral_jitter
# and mouse_jitter to grab the real keyboard/mouse and synthesize
# jittered events. Mode 0660 because EVIOCGRAB and writes both
# need group-rw.
KERNEL=="uinput", GROUP="veil", MODE="0660"
KERNEL=="event*", SUBSYSTEM=="input", GROUP="veil", MODE="0660"
KERNEL=="mice", SUBSYSTEM=="input", GROUP="veil", MODE="0660"
EOF
ok "70-veil-tun.rules + 71-veil-uinput.rules"
if command -v udevadm >/dev/null 2>&1; then
  # All best-effort: udev may not be running (containers, minimal systems) and
  # the rules only affect /dev/net/tun group access + jitter input devices, not
  # the capless tor/pasta path. A failed reload must NOT abort the install.
  udevadm control --reload-rules 2>/dev/null || true
  # Trigger every device the rules might match — re-runs the rules and re-chowns
  # existing nodes so devices created before our rule pick up GROUP=veil.
  udevadm trigger /dev/net/tun 2>/dev/null || true
  udevadm trigger /dev/uinput 2>/dev/null || true
  udevadm trigger --subsystem-match=input 2>/dev/null || true
  ok "udev rules installed (reload/trigger best-effort)"
fi

# --------------------------------------------------------------- bind dirs
step "Creating bind-mount target directories"
mkdir -p /run/netns /etc/netns
ok "/run/netns + /etc/netns ready"

# ----------------------------------------------------------------- sysctl
# Enable persistent ip_forward. The user-ns engine writes a per-netns
# version on launch, but enabling it host-wide also covers the legacy
# pkexec fallback path (and is harmless for user-ns mode).
step "Configuring sysctl (ip_forward)"
cat > /etc/sysctl.d/99-veil.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p /etc/sysctl.d/99-veil.conf >/dev/null 2>&1 || true
ok "/etc/sysctl.d/99-veil.conf written"

# ---------------------------------------------------------------- icon
step "Installing icon"
install -d "$ICON_DIR"
install -m 0644 packaging/veil.svg "$ICON_DIR/veil.svg"
ok "$ICON_DIR/veil.svg"

# ---------------------------------------------------------- desktop entry
step "Installing .desktop entry (with VEIL_USERNS_ENGINE=1 baked in)"
install -d "$APP_DIR"
install -m 0644 packaging/veil.desktop "$APP_DIR/veil.desktop"
# Force the env-var Exec line in case the source template drifts.
sed -i 's|^Exec=.*|Exec=env VEIL_USERNS_ENGINE=1 /usr/local/bin/veil-gui-launcher|' "$APP_DIR/veil.desktop"
ok "$APP_DIR/veil.desktop"

# ---------------------------------------------------------------- polkit
step "Installing polkit policy (legacy fallback path uses pkexec)"
install -d "$POLKIT_DIR"
install -m 0644 packaging/com.veil.gui.policy "$POLKIT_DIR/com.veil.gui.policy"
ok "$POLKIT_DIR/com.veil.gui.policy"

# --------------------------------------------------------------- desktop db
step "Refreshing desktop + icon caches"
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "/usr/share/icons/hicolor" || true
command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" || true
ok "caches refreshed"

# ---------------------------------------------------------- self-test
step "Verifying install"
"$LIBEXEC_DIR/veil-bridge" doctor >/dev/null 2>&1 && ok "veil-bridge doctor: pass" || warn "veil-bridge doctor: failed (see: $LIBEXEC_DIR/veil-bridge doctor)"
[ -r /run/netns ] && ok "/run/netns readable"
[ -r /etc/netns ] && ok "/etc/netns readable"
[ -c /dev/net/tun ] && ok "/dev/net/tun present" || warn "/dev/net/tun missing (try: sudo modprobe tun)"
# Run engine doctor as the invoking user (NOT root) so the checks
# reflect the runtime path. Skip if no SUDO_USER (e.g. running install
# as actual root via su).
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  if sudo -u "$SUDO_USER" -H "$BIN_DIR/veil" doctor >/tmp/veil-doctor.out 2>&1; then
    if grep -q "✗" /tmp/veil-doctor.out; then
      warn "veil doctor: some checks failed"
      grep "✗\|⚠" /tmp/veil-doctor.out | sed 's/^/      /'
    else
      ok "veil doctor: all checks pass"
    fi
  fi
  rm -f /tmp/veil-doctor.out
fi

# ---------------------------------------------------------- final notes
echo
echo "============================================================"
echo "Install complete."
echo "============================================================"
echo
if [ "${NEEDS_RELOGIN:-0}" = "1" ]; then
  echo "ONE STEP REMAINING:"
  echo
  echo "  Your shell session does not yet have the 'veil' group active."
  echo "  Pick ONE of the two:"
  echo
  echo "    a) Log out and log back in (cleanest)"
  echo "    b) Run:   newgrp veil"
  echo "       (only affects the shell where you ran it)"
  echo
  echo "  Then launch Veil from the application menu, or:"
  echo
  echo "    veil-gui-launcher"
  echo
else
  echo "All done. Launch Veil from the application menu, or:"
  echo
  echo "    veil-gui-launcher"
  echo
fi
echo "Uninstall with: sudo ./install.sh --uninstall"
