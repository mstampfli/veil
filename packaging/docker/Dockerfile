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
# Static CLI (no cgo) — the GUI is intentionally NOT built for containers.
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/veil ./cmd/veil
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
COPY packaging/docker/entrypoint.sh /usr/local/bin/veil-entrypoint
# Ready-made profiles: 'freetor' (curl healthcheck) + 'browser' (tor chain for
# an isolated browser). Shipped for both the capless (veil user) and root paths.
COPY packaging/docker/freetor.yaml /home/veil/.config/veil/profiles/freetor.yaml
COPY packaging/docker/freetor.yaml /root/.config/veil/profiles/freetor.yaml
COPY packaging/docker/browser.yaml /home/veil/.config/veil/profiles/browser.yaml
COPY packaging/docker/browser.yaml /root/.config/veil/profiles/browser.yaml
RUN chmod 0755 /usr/local/bin/veil-entrypoint /usr/local/libexec/veil/pasta \
 && chown -R veil:veil /home/veil/.config

# Optional browser layer for turnkey headful browsing:
#   docker build -f packaging/docker/Dockerfile --build-arg WITH_BROWSER=1 -t veil-browser .
# Firefox launches inside veil's netns (traffic isolated); display goes over the
# host X11 socket (see README / veil-docker --x11). Needs a roomy /dev/shm at
# run time (--shm-size=512m; veil-docker adds this with --x11).
ARG WITH_BROWSER=0
RUN if [ "$WITH_BROWSER" = "1" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends firefox-esr fonts-liberation libgl1 libegl1 \
      && rm -rf /var/lib/apt/lists/* ; \
    fi

ENV VEIL_USERNS_ENGINE=1 \
    VEIL_PASTA=/usr/local/libexec/veil/pasta \
    MOZ_DISABLE_CONTENT_SANDBOX=1
# MOZ_DISABLE_CONTENT_SANDBOX: Firefox's own content sandbox uses nested user
# namespaces, which don't nest cleanly inside veil's user-ns child + the
# container; without this Firefox fails to start its content processes. veil
# already provides the network isolation (the point); this only relaxes
# Firefox's INTERNAL process sandbox. Harmless for the non-browser image.
ENTRYPOINT ["/usr/local/bin/veil-entrypoint"]
CMD ["selftest", "freetor"]
