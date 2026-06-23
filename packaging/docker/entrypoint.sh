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

# Engine selection:
#   VEIL_USERNS_ENGINE=1 (default) -> capless path: drop to the unprivileged
#     'veil' user and let the engine use user namespaces + pasta (CapEff=0).
#   VEIL_USERNS_ENGINE=0           -> root-engine fallback: run as the
#     container's root (needs --cap-add NET_ADMIN,SYS_ADMIN or --privileged).
# setpriv (util-linux) is already present in the base image.
if [ "$(id -u)" = "0" ] && [ "${VEIL_USERNS_ENGINE:-1}" = "1" ]; then
  exec setpriv --reuid veil --regid veil --init-groups \
    env HOME=/home/veil VEIL_USERNS_ENGINE=1 veil "$@"
fi
exec veil "$@"
