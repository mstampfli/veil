.PHONY: all build cli gui bridge linux windows macos clean test vet reproducible verify-reproducible hooks

VERSION ?= dev
# RELEASE_PUBKEY: base64 Ed25519 public key used by the self-updater to
# verify downloaded release assets. Leave empty for local/dev builds (the
# updater then refuses to apply). Release CI sets it.
RELEASE_PUBKEY ?=
# Reproducibility:
#   * -trimpath strips local file paths from the binary
#   * -buildvcs=false omits VCS info (commit hash) — CI passes it via VERSION
#   * -ldflags "-buildid=" zeroes the Go build ID
#   * SOURCE_DATE_EPOCH controls embedded timestamps (set to a fixed value
#     in CI to get byte-identical output)
LDFLAGS  = -X github.com/mstampfli/veil/internal/cli.Version=$(VERSION) -X github.com/mstampfli/veil/internal/updater.ReleasePubKey=$(RELEASE_PUBKEY) -buildid=
GOFLAGS  = -trimpath -buildvcs=false
GUI_TAGS = desktop production webkit2_41

all: build

build: cli gui bridge

cli:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil ./cmd/veil

gui:
	go build $(GOFLAGS) -tags "$(GUI_TAGS)" -ldflags "$(LDFLAGS)" -o bin/veil-gui ./cmd/veil-gui

# Privileged helper. Built without CGo / GUI flags — small, auditable.
# Install step (install-desktop.sh) sets cap_net_admin on the installed
# copy so it can do veth + iptables work without running as root.
bridge:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-bridge ./cmd/veil-bridge

# GUI with system-tray support. Requires libayatana-appindicator3-dev.
gui-tray:
	go build $(GOFLAGS) -tags "$(GUI_TAGS) tray" -ldflags "$(LDFLAGS)" -o bin/veil-gui ./cmd/veil-gui

linux:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-linux-amd64 ./cmd/veil
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-gui-linux-amd64 ./cmd/veil-gui
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-bridge-linux-amd64 ./cmd/veil-bridge

windows:
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil.exe ./cmd/veil
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS) -H windowsgui" -o bin/veil-gui.exe ./cmd/veil-gui

# macOS cross-compile (CGo for the GUI requires running on a Mac).
macos:
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-darwin-amd64 ./cmd/veil
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/veil-darwin-arm64 ./cmd/veil

# Reproducible build: pin SOURCE_DATE_EPOCH and produce sha256 of bins.
reproducible:
	SOURCE_DATE_EPOCH=$$(git log -1 --pretty=%ct 2>/dev/null || echo 0) \
		$(MAKE) cli gui
	sha256sum bin/veil bin/veil-gui

# Build twice, byte-compare. Fails if non-reproducible.
# NOTE: the second build must NOT run `clean` — clean removes _r1 (see the
# clean target), which is exactly where we stashed the first build, so a
# `clean` here would delete the comparison baseline and the cmp would
# always fail even when the binaries are byte-identical. Build straight
# into the (just-moved-away) bin/ instead.
verify-reproducible:
	$(MAKE) clean reproducible
	mv bin _r1
	$(MAKE) reproducible
	@if ! cmp -s _r1/veil bin/veil; then echo 'CLI not reproducible'; exit 1; fi
	@if ! cmp -s _r1/veil-gui bin/veil-gui; then echo 'GUI not reproducible'; exit 1; fi
	@echo 'Both binaries reproduce identically.'
	rm -rf _r1 bin

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf bin _r1

# Install the repo git hooks (pre-push guard that blocks Pro/anti-detect code
# from being pushed to the public free repo). Run once per clone. No-op in the
# public free edition, where scripts/ is not shipped.
hooks:
	@if [ -d scripts/githooks ]; then \
		git config core.hooksPath scripts/githooks && echo "git hooks installed (core.hooksPath=scripts/githooks)"; \
	else \
		echo "no scripts/githooks in this checkout (free edition); nothing to install"; \
	fi
