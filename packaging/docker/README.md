# Veil in Docker

Two ways to run veil in a container. The **capless** path is the default and
matches veil's design: no Linux capabilities, the engine builds its own
isolation with unprivileged user namespaces + pasta. The **root-engine** path
is a fallback for hosts/bases where the capless prerequisites aren't met.

## Quick shortcut (no long command each time)

`veil-docker` wraps the full hardened `docker run` so you just pass veil args:

```sh
# one-time: put it on PATH (symlink, so it still finds Dockerfile/seccomp.json)
sudo ln -s "$PWD/packaging/docker/veil-docker" /usr/local/bin/veil-docker

veil-docker build                      # build the image once
veil-docker selftest freetor           # any veil subcommand
veil-docker run myprofile -- curl ...  # run an app through a profile
veil-docker --x11 run myprofile -- firefox   # headful browser (shares host X11)
```

It applies the capless hardening (cap-drop, custom seccomp, tun device) and
mounts `~/.config/veil/profiles` automatically. Or use compose:
`docker compose -f packaging/docker/docker-compose.yml run --rm veil`.

For a clickable app-menu entry, install `veil-docker.desktop` (a documented
template for launching an isolated browser through the container):
`cp packaging/docker/veil-docker.desktop ~/.local/share/applications/`.

## Build (manual)

```sh
docker build -f packaging/docker/Dockerfile -t veil .
```

This builds the CLI only (the veil GUI is not built for containers).

## Headful browser (turnkey)

Build the browser variant — it bundles Firefox and a ready-made `browser`
profile (tor chain), so an isolated browser works out of the box:

```sh
docker build -f packaging/docker/Dockerfile --build-arg WITH_BROWSER=1 -t veil-browser .
xhost +local:        # once per session: let the container reach your X display
VEIL_DOCKER_IMAGE=veil-browser veil-docker --x11 run browser -- firefox
```

Firefox launches **inside veil's netns** (traffic routed through the chain,
over tor here) and renders on your host display via the X11 unix socket (which
crosses the netns, so display and network are cleanly separated). The
`veil-docker.desktop` launcher wires this up for the app menu. Validated:
Firefox loads a live network page inside the netns (headless render confirmed);
the only addition for a visible window is the X11 socket above.

Notes: the image sets `MOZ_DISABLE_CONTENT_SANDBOX=1` — Firefox's *internal*
content sandbox uses nested user namespaces that don't nest cleanly here; veil
still provides the network isolation. Browsers also need a roomy `/dev/shm`
(`veil-docker --x11` adds `--shm-size=512m`). For GPU acceleration add
`--device /dev/dri` (software rendering works without).

## Capless (recommended) — zero Linux capabilities

```sh
docker run --rm \
  --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt seccomp=packaging/docker/seccomp.json \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  --device /dev/net/tun \
  veil selftest freetor
```

`seccomp.json` is Docker's default profile plus **only** the six namespace/mount
syscalls veil needs (`unshare`, `clone`, `setns`, `mount`, `umount2`,
`pivot_root`) — everything else Docker denies stays denied, so it's far tighter
than `seccomp=unconfined`. `--cap-drop ALL` keeps only the three caps the
entrypoint uses to drop to the unprivileged user; veil runs with `CapEff=0`.

Verify it really is capless: `... veil sh -c 'grep CapEff /proc/self/status'`
prints `CapEff: 0000000000000000`.

Run your own app through a profile by mounting a profiles dir and changing the
command (e.g. `... veil run <profile> -- <your command>` with
`-v "$PWD/profiles:/home/veil/.config/veil/profiles"`).

Or just use the compose file (already hardened): `docker compose -f
packaging/docker/docker-compose.yml run --rm veil`.

### Why these opts (and how tight each can be)

Each maps to one thing veil must do that strict Docker blocks by design. None
grants a Linux capability — veil runs with `CapEff=0` either way:

- **seccomp** — Docker's default profile blocks the nested unprivileged
  `unshare(CLONE_NEWUSER)` the engine needs (tested: it fails, veil falls back
  to "needs root"). Rather than `seccomp=unconfined`, ship `seccomp.json`:
  Docker's default profile **plus only** `unshare`, `clone`, `setns`, `mount`,
  `umount2`, `pivot_root` (the last for pasta's own self-sandbox). Everything
  else Docker denies stays denied. Refresh it by re-merging those names into a
  newer upstream `moby/profiles/seccomp/default.json`.
- **`apparmor=unconfined`** — Docker's default AppArmor profile denies the
  bind-mounts the engine does for its private netns state. (Replaceable with a
  custom AppArmor profile that allows `mount`; not shipped — fiddlier, less
  marginal benefit.)
- **`systempaths=unconfined`** — Docker mounts `/proc/sys` read-only; the engine
  writes `net.ipv4.ip_forward` for its inner netns routing. Hard to drop:
  remounting `/proc` inside the child is itself refused (Docker's masked `/proc`
  submounts are "locked" in a user namespace).

- **capabilities** — `--cap-drop ALL` and add back only `SETUID`/`SETGID`/
  `SETPCAP`, used solely by the entrypoint to drop to the unprivileged `veil`
  user. veil itself ends at `CapEff=0`.

`apparmor` and `systempaths` are the irreducible remainder — the inherent cost
of running a namespace-creating tool *inside* another sandbox (rootless Podman
in Docker needs the same). `--device /dev/net/tun` passes the tun device pasta
uses for its tap (a device node, not a capability); the entrypoint widens its
mode for the unprivileged user. A read-only rootfs is not compatible as-is —
the engine writes per-ns state under `/run` and `/etc/netns`.

### passt version (why the image builds it from source)

The capless uplink needs a **recent passt**. Debian 12's packaged passt
(`0.0~git20230309`) is too old — in a container it cannot attach to the
engine's user-ns child and exits with "Couldn't open user namespace:
Permission denied". Rather than depend on the base distro, this image (Debian
12 based) **builds a recent pasta from source** (pinned `PASST_REF`) into
`/usr/local/libexec/veil/pasta` and points veil at it with `VEIL_PASTA`. That
makes the image work capless on Debian 12 and keeps it base-agnostic.

`VEIL_PASTA=/path/to/pasta` is a general override: on any host whose packaged
passt is too old (or AppArmor-confined), install a recent pasta at a veil-owned
path and set `VEIL_PASTA` — a binary outside `/usr/bin` also sidesteps the
distro's path-scoped passt AppArmor profile.

## Root-engine fallback

If the capless prerequisites can't be met, run veil's legacy engine as the
container's root by setting `VEIL_USERNS_ENGINE=0` (the entrypoint then skips
the drop to the unprivileged user). Simplest:

```sh
docker run --rm --privileged -e VEIL_USERNS_ENGINE=0 veil selftest freetor
```

Narrower than `--privileged` (looser than capless, but no full privilege):

```sh
docker run --rm -e VEIL_USERNS_ENGINE=0 \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  --device /dev/net/tun \
  veil selftest freetor
```

`NET_ADMIN`+`SYS_ADMIN` are needed for the engine's veth/iptables work and the
`ip netns` mount operations; `apparmor`/`systempaths` unconfined unblock those
mounts and the read-only `/proc/sys`.

## Notes

- A container that loosens its own sandbox (the three `unconfined` opts) is the
  inherent trade-off of running an isolation tool *inside* another sandbox. The
  capabilities veil would otherwise need on the host are still avoided.
- Tor in the demo profile logs a "running as root" warning on the root-engine
  path; it's harmless. The capless path runs everything as the `veil` user.
