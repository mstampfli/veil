#!/bin/sh
# Veil container entrypoint.
#
# Two tiny setup steps need to run as the container's root BEFORE veil itself
# runs unprivileged:
#   - /dev/net/tun arrives (via --device) owned root:root mode 0600; pasta,
#     running as the unprivileged veil user, needs to open it. Widen it.
#   - the iproute2 netns state dirs must exist as bind-mount targets.
# Neither step grants a Linux capability — the veil process still runs with
# CapEff=0 on the zero-capability user-ns + pasta path.
set -e

if [ -e /dev/net/tun ]; then
  chmod 0666 /dev/net/tun 2>/dev/null || true
fi
mkdir -p /run/netns /etc/netns

# Binary selection: launch the desktop GUI when invoked as `gui` (requires the
# WITH_GUI=1 image plus a forwarded display, see veil-docker --x11/--wayland),
# otherwise the veil CLI. Everything after `gui` is passed through to veil-gui.
BIN=veil
if [ "${1:-}" = "gui" ]; then
  if ! command -v veil-gui >/dev/null 2>&1; then
    echo "veil-entrypoint: 'gui' needs the WITH_GUI=1 image (veil-gui not installed)" >&2
    echo "  build it: docker build -f packaging/docker/Dockerfile --build-arg WITH_GUI=1 -t veil-gui ." >&2
    exit 1
  fi
  BIN=veil-gui
  shift
fi

# Engine selection:
#   VEIL_USERNS_ENGINE=1 (default) -> capless path: drop to the unprivileged
#     'veil' user and let the engine use user namespaces + pasta (CapEff=0).
#   VEIL_USERNS_ENGINE=0           -> root-engine fallback: run as the
#     container's root (needs --cap-add NET_ADMIN,SYS_ADMIN or --privileged).
# setpriv (util-linux) is already present in the base image.
# Privilege drop: when the container starts as root (rootful engine), drop to
# the unprivileged 'veil' user so veil runs with CapEff=0 and can use the
# unprivileged user-namespace engine path. When we're already non-root (rootless
# podman with --userns=keep-id runs us as the veil user, uid 1000, directly)
# there's nothing to drop -- just run.
if [ "$(id -u)" = "0" ] && [ "${VEIL_USERNS_ENGINE:-1}" = "1" ]; then
  exec setpriv --reuid veil --regid veil --init-groups \
    env HOME=/home/veil VEIL_USERNS_ENGINE=1 "$BIN" "$@"
fi
# Already non-root: ensure HOME points at the profiles/config location.
exec env HOME="${HOME:-/home/veil}" "$BIN" "$@"
