# Reproducible builds

Veil's CLI and GUI binaries are designed to build byte-identically
across machines and times. This matters for:

- Auditability — anyone can compile the source and verify that
  Veil's published binary contains exactly that source, no hidden
  modifications.
- Detection — if a deployed binary's hash differs from a fresh
  reproducible build, that's a tampering signal.
- Trust — open-source claims mean nothing if the published binary
  diverges from the public source.

## How it works

The Makefile passes the right flags to `go build`:

```
GOFLAGS = -trimpath -buildvcs=false
LDFLAGS = -X .../cli.Version=$(VERSION) -buildid=
```

- `-trimpath` strips local file paths from the binary so the output
  doesn't embed the builder's home directory.
- `-buildvcs=false` omits VCS revision metadata (CI passes `VERSION`
  via env instead).
- `-buildid=` zeroes the Go build ID, which would otherwise vary
  per build.
- `SOURCE_DATE_EPOCH` (set by `make reproducible`) controls embedded
  timestamps — `make` uses the latest commit's timestamp.

## Build + verify

```bash
make reproducible
# → builds bin/veil and bin/veil-gui
# → prints sha256sums

make verify-reproducible
# → builds twice, byte-compares, fails if non-identical
```

## What the verifier does

1. Cleans the output dir.
2. Builds with `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)`.
3. Saves binaries to `_r1/`.
4. Cleans + rebuilds with the same env.
5. `cmp -s` of both copies — fails if they differ.

If the verifier fails, the most common causes are:

- New code path uses `init()`-time map iteration (Go map order is
  randomized). Replace with an explicitly-sorted iteration.
- `time.Now()` baked into a string at compile time. Move to runtime.
- A dependency embeds a path or timestamp. Pin the dep version.
- New dependencies that themselves aren't reproducible. Audit + pin.

## CI flow

When you publish a binary, also publish:

- `bin/veil.sha256` — the sha256sum from the build.
- The exact `git rev-parse HEAD` of the source.
- The `SOURCE_DATE_EPOCH` value used.

Any user can then:

```bash
git clone <repo> && cd veil
git checkout <commit>
SOURCE_DATE_EPOCH=<epoch> make reproducible
sha256sum bin/veil      # must match published value
```

## Known caveats

- `cmd/veil-gui` builds with the `desktop production webkit2_41` tags
  on Linux. CGo links against the host's libwebkit2gtk; if the system
  lib version differs, the binary differs. Verifying GUI reproducibility
  thus requires the same Debian/Parrot package version.
- veil-browser is built separately and uses Brave's own build flow
  (which is reproducible at the source-patch level, not necessarily at
  the binary level — this is a Chromium-build constraint).
