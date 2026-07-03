# Veil in Docker — zero-capability (capless) deployment, Debian 12 base.
#
# The container holds NO Linux capabilities (CapEff=0); veil builds its own
# per-app isolation with unprivileged user namespaces + pasta as a non-root
# user. Debian 12's *packaged* passt (0.0~git20230309) is too old to attach to
# the engine's user-ns child, so we build a recent pasta from source (pinned)
# and veil uses it via VEIL_PASTA. That also makes the image base-agnostic.
#
# Build (from the repo root):
#   docker build -f packaging/docker/Dockerfile -t veil .
#
# Run — see packaging/docker/README.md. Capless needs three security-opts that
# LOOSEN the container's own sandbox (they add no capabilities) plus the tun
# device:
#   docker run --rm \
#     --security-opt seccomp=unconfined \
#     --security-opt apparmor=unconfined \
#     --security-opt systempaths=unconfined \
#     --device /dev/net/tun \
#     veil selftest freetor

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
# Static CLI (no cgo).
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/veil ./cmd/veil
# Optional desktop GUI (Wails + WebKitGTK), built ONLY when WITH_GUI=1. Needs
# cgo + the webkit/gtk dev headers (and pkg-config); same build tags as
# `make gui`. The frontend is embedded (//go:embed dist), so no Node/wails CLI
# is needed. When disabled, emit a 0-byte placeholder so the runtime stage's
# `COPY --from=build /out/veil-gui` always resolves (a conditional COPY can't).
ARG WITH_GUI=0
RUN if [ "$WITH_GUI" = "1" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends \
           pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev \
      && rm -rf /var/lib/apt/lists/* \
      && CGO_ENABLED=1 go build -trimpath -tags "desktop production webkit2_41" \
           -ldflags '-s -w' -o /out/veil-gui ./cmd/veil-gui ; \
    else \
      : > /out/veil-gui ; \
    fi
# Recent pasta from source. golang:1.24-bookworm is glibc 2.36 like the
# debian:12 runtime, so the dynamically-linked build is ABI-compatible there.
# Pinned to a known-good commit; bump PASST_REF (and re-test) to update.
ARG PASST_REF=587980c
RUN git clone https://passt.top/passt /tmp/passt \
 && cd /tmp/passt && git checkout "$PASST_REF" && make \
 && cp pasta /out/pasta && cp pasta.avx2 /out/pasta.avx2

FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tor iproute2 iptables procps ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 veil \
 && mkdir -p /run/netns /etc/netns /root/.config/veil/profiles
COPY --from=build /out/veil /usr/local/bin/veil
# Our recent pasta (named so its basename contains "pasta" -> pasta mode).
COPY --from=build /out/pasta /usr/local/libexec/veil/pasta
COPY --from=build /out/pasta.avx2 /usr/local/libexec/veil/pasta.avx2
# Staged GUI binary (real iff built with WITH_GUI=1, else 0-byte; the WITH_GUI
# layer below installs it to /usr/local/bin or removes the placeholder).
COPY --from=build /out/veil-gui /tmp/veil-gui
COPY packaging/docker/entrypoint.sh /usr/local/bin/veil-entrypoint
# Ready-made profiles: 'freetor' (curl healthcheck) + 'browser' (tor chain for
# an isolated browser). Shipped for both the capless (veil user) and root paths.
COPY packaging/docker/freetor.yaml /home/veil/.config/veil/profiles/freetor.yaml
COPY packaging/docker/freetor.yaml /root/.config/veil/profiles/freetor.yaml
COPY packaging/docker/browser.yaml /home/veil/.config/veil/profiles/browser.yaml
COPY packaging/docker/browser.yaml /root/.config/veil/profiles/browser.yaml
RUN chmod 0755 /usr/local/bin/veil-entrypoint /usr/local/libexec/veil/pasta \
 && chown -R veil:veil /home/veil/.config

# Runtime libs a host-mounted Chrome/Brave needs beyond what WebKit/Firefox
# already pull in (mainly the NSS set). Small; installed only into the
# browser/GUI variants below so a bind-mounted host browser can run.
ARG BROWSER_LIBS="libnss3 libasound2 libcups2 libgbm1 libxkbcommon0 libxdamage1 libxshmfence1"

# Optional browser layer for turnkey headful browsing:
#   docker build -f packaging/docker/Dockerfile --build-arg WITH_BROWSER=1 -t veil-firefox .
# Firefox launches inside veil's netns (traffic isolated); display goes over the
# host X11 socket (see README / veil-docker --x11). Needs a roomy /dev/shm at
# run time (--shm-size=512m; veil-docker adds this with --x11).
ARG WITH_BROWSER=0
RUN if [ "$WITH_BROWSER" = "1" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends firefox-esr fonts-liberation libgl1 libegl1 \
           $BROWSER_LIBS \
      && rm -rf /var/lib/apt/lists/* ; \
    fi

# Optional desktop GUI layer: WebKitGTK runtime libs + the veil-gui binary built
# in the build stage. Launch with `veil-docker --x11 gui` (or --wayland).
#   docker build -f packaging/docker/Dockerfile --build-arg WITH_GUI=1 -t veil-gui .
# The $BROWSER_LIBS (Chrome/Brave runtime deps that WebKit doesn't already pull,
# mainly NSS) let a HOST-installed browser bind-mounted in with
# `veil-docker --browser <name>` actually run -- no need to bundle the browser.
# They're glibc-correct for this image, so only the browser's own binary matters
# (Chrome/Brave target old glibc and work; host Firefox needs newer -> use the
# bundled firefox-esr in the WITH_BROWSER image).
ARG WITH_GUI=0
RUN if [ "$WITH_GUI" = "1" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends \
           libwebkit2gtk-4.1-0 libgtk-3-0 libgl1 libegl1 fonts-liberation dbus-x11 \
           $BROWSER_LIBS \
      && rm -rf /var/lib/apt/lists/* \
      && install -m0755 /tmp/veil-gui /usr/local/bin/veil-gui ; \
    fi ; \
    rm -f /tmp/veil-gui

ENV VEIL_USERNS_ENGINE=1 \
    VEIL_PASTA=/usr/local/libexec/veil/pasta \
    MOZ_DISABLE_CONTENT_SANDBOX=1 \
    WEBKIT_DISABLE_COMPOSITING_MODE=1 \
    WEBKIT_DISABLE_DMABUF_RENDERER=1 \
    WEBKIT_DISABLE_SANDBOX=1
# MOZ_DISABLE_CONTENT_SANDBOX: Firefox's own content sandbox uses nested user
# namespaces, which don't nest cleanly inside veil's user-ns child + the
# container; without this Firefox fails to start its content processes. veil
# already provides the network isolation (the point); this only relaxes
# Firefox's INTERNAL process sandbox. Harmless for the non-browser image.
# WEBKIT_DISABLE_COMPOSITING_MODE / WEBKIT_DISABLE_DMABUF_RENDERER: only the
# veil-gui (WebKitGTK) image reads these; they force WebKit's software render
# path so the GUI renders on a container with no GPU/DMABUF instead of crashing.
# WEBKIT_DISABLE_SANDBOX: WebKit's web-content process uses a bubblewrap sandbox
# (nested user namespaces) that fails to start when the GUI runs as container
# uid 0 -- which is the rootless-engine case (container root == your host uid, so
# it can reach your display). Disabling it lets the renderer come up; it costs no
# real safety here since veil-gui only loads its own embedded local content (no
# untrusted web pages), and veil still provides the network isolation.
# All inert for the CLI and browser images (Firefox ignores them).
ENTRYPOINT ["/usr/local/bin/veil-entrypoint"]
CMD ["selftest", "freetor"]
