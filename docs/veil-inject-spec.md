# `veil-inject.so` — Pro-tier native injection layer

Status: **specified, not implemented**. Free tier (extension + MITM) ships without this. The `.so` is the Pro-tier unlock that closes the residual gap and gives Veil capabilities Brave Shields cannot match (because Brave Shields only protects Brave; this works on any browser).

## What it is

A small shared library loaded into the launched browser via `LD_PRELOAD` (Linux). Hooks OS-level functions Brave's renderer reaches into at C++ level. Replaces the slow JS wraps in our extension for canvas/WebGL/audio/font with native-speed versions, and covers the contexts the extension cannot intercept (worker, service worker, WASM, OffscreenCanvas).

## Why we want it

Hard ceiling of the JS extension:

- Page service workers — extension content scripts don't run inside them
- WebAssembly direct buffer access (`getBufferSubData`, raw memory reads from WebGL textures)
- `OfflineAudioContext.startRendering` — produces deterministic AudioBuffer; our analyser-method wraps don't intercept this path
- Timing-side-channel detection — JS wraps are 5–10× slower than native; sophisticated detectors see the timing signature
- `Reflect.ownKeys` and prototype-chain inspection beyond what `toString` mock covers

LD_PRELOAD sits below V8 — catches all consumer contexts because they all eventually call `glReadPixels` / `FT_Load_Glyph` / `pa_stream_peek` / `getrandom`.

## What it is NOT

Not a Chromium fork. Not a renderer-process patch. Hooks only stable OS-library APIs that change on a yearly cadence with deprecation cycles. Maintenance burden: ~1–2 person-weeks/year, vs. tens of weeks per Chromium release for a fork.

## Architecture

```
cmd/veil-inject/                    # build target (compiles the .so)
internal/inject/
  inject.go                         # engine integration (LD_PRELOAD env wiring + config builder)
  inject_test.go
  c/
    Makefile                        # builds bin/libexec/veil/veil-inject.so
    veil_inject.c                   # constructor: read VEIL_INJECT_PROFILE, init farble state
    veil_inject.h                   # shared types: config struct, PRNG state
    farble.c                        # per-eTLD PRNG (xorshift32 seeded with FNV-1a hash) + noise primitives
    hooks_gl.c                      # glReadPixels, glGetTexImage, glGetString
    hooks_freetype.c                # FT_Load_Glyph, FT_Get_Advance
    hooks_audio.c                   # pa_stream_peek (PulseAudio), snd_pcm_readi (ALSA fallback)
    hooks_random.c                  # getrandom (glibc wrapper), RAND_bytes (when libcrypto is dynamic)
```

Build output: `bin/libexec/veil/veil-inject.so` alongside `veil-bridge`. Installed by `install.sh` to `/usr/lib/veil/veil-inject.so`.

## Activation

Engine appends to the launched browser's environment at fork time, in `cmd/veil-bridge` (so the .so loads inside the user-ns child where the browser actually runs):

```
LD_PRELOAD=/usr/lib/veil/veil-inject.so:$LD_PRELOAD
VEIL_INJECT_PROFILE=<base64 JSON>
VEIL_INJECT_DEBUG=1                   # optional — log to stderr
```

`VEIL_INJECT_PROFILE` is a small JSON the .so reads in its `__attribute__((constructor))`:

```json
{
  "etld_seed": "0xa3f29e74",
  "canvas_noise_pixels": 8,
  "webgl_renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL ES 3.2)",
  "webgl_vendor": "Google Inc. (Intel)",
  "audio_noise_dbfs": 0.0005,
  "font_metric_jitter_px": 0.025,
  "rng_etld_lock": true
}
```

The seed is per-profile, not per-tab. Per-tab seeding requires a socket-based companion in the extension (browser tab origin → .so). Initial implementation does per-profile only; per-tab is a v2 upgrade path.

## Hooks (initial scope)

| Hook | Library | Behavior |
|---|---|---|
| `glReadPixels(x, y, w, h, fmt, type, data)` | libGL.so / libangle | Call original. Walk RGBA stride. For 1 in `canvas_noise_pixels` pixels (default 8), apply ±1 channel nudge on a single channel from the per-eTLD PRNG. Cost ~5µs for 2MP. |
| `glGetTexImage` | libGL.so | Same noise application as glReadPixels — covers texture-readback fingerprinting paths. |
| `glGetString(GL_VENDOR)`, `glGetString(GL_RENDERER)` | libGL.so | Return persona-claimed strings from `webgl_vendor`/`webgl_renderer`. Catches WebGL `UNMASKED_VENDOR_WEBGL`/`UNMASKED_RENDERER_WEBGL` for ALL contexts (main + worker + WASM). |
| `FT_Load_Glyph(face, glyph_idx, flags)` | libfreetype.so | After original call, deterministic per-(eTLD, codepoint) jitter on `face->glyph->metrics.horiAdvance` and `width` by ±0.025px. Defeats font enumeration in OffscreenCanvas / SW canvas. |
| `pa_stream_peek(stream, **data, *nbytes)` | libpulse.so | After original, walk float32 sample buffer, apply ±0.0005 dBFS noise. Covers `OfflineAudioContext.startRendering` path our analyser wraps miss. |
| `getrandom(buf, n, flags)` | glibc | When `rng_etld_lock=true`, fill from xorshift seeded with `etld_seed` instead of kernel entropy. Affects V8/SpiderMonkey JS RNG initial seed. Defeats "use Math.random output to detect spoofing" attacks. |

Skipped initially (easy adds later):

- `glReadnPixels` (newer pixel-readback variant)
- `pa_stream_read` (older PulseAudio API, deprecated but still present in some builds)
- `clock_gettime` — vDSO bypasses LD_PRELOAD; not worth the complexity. Time namespace + `performance.now()` clamping in extension already handle absolute-time leaks. The relative-timing detection signal is best addressed by *making our wraps fast*, which is precisely what this layer does.
- DBus geolocation / GeoClue — extension already overrides Geolocation API surface

## Per-eTLD seeding

The .so does not have JS-level access to `location.hostname`. Two paths:

### v1 (initial): per-profile constant seed

Engine derives `etld_seed = FNV-1a(profile_name + persona_seed)` once at launch. Same seed for all tabs in this profile's browser. Trades per-site uniqueness within a session for simplicity.

Coverage: **defeats cross-PROFILE fingerprint correlation** ✓
Gap: same-profile cross-site fingerprint correlation is possible (a tracker on site A and site B in the same Brave window sees identical noise pattern).

### v2 (upgrade path): per-tab seed via Unix socket

`.so` opens `/run/user/$UID/veil-inject-$PROFILE.sock` in its constructor.

A thin extension-companion content script posts `{tab_id, etld}` on `webNavigation.onCommitted` to the engine, which forwards the seed to the .so socket. The .so maintains a TLS-thread-local seed indexed by renderer-process tab routing ID.

This is more work and adds a runtime dependency. v1 is shippable on its own.

## Engine integration

In `internal/engine/engine_linux.go`, where the browser exec env is built:

```go
if s.Profile.Pro && s.Profile.AntiFingerprint.IsOn() {
    injectSO := filepath.Join(libexecDir, "veil-inject.so")
    if _, err := os.Stat(injectSO); err != nil {
        return fmt.Errorf("veil-inject.so missing at %s — Pro tier requires native injection", injectSO)
    }
    cfg := buildInjectConfig(s.Profile, persona)
    env = setEnv(env, "LD_PRELOAD", prependPath(env, "LD_PRELOAD", injectSO))
    env = setEnv(env, "VEIL_INJECT_PROFILE", base64.StdEncoding.EncodeToString(cfg))
}
```

Hard-fail if Pro is on and the file is missing — same "no soft fail" rule the rest of the engine follows.

## Failure modes / things to watch

- **Snap/Flatpak browsers**: bind-mounted libs hide our .so. `veil-bridge doctor` checks: `ldd $(which brave-browser) | grep -E 'libGL|libfreetype'` should show non-snap paths. If snap, hard-fail with: "install via .deb instead, or use AppImage Brave with `BRAVE_DISABLE_SANDBOX=1`".
- **Symbol versioning**: `glReadPixels@@OPENGL_1.0` requires:
  ```c
  __asm__(".symver original_glReadPixels, glReadPixels@OPENGL_1.0");
  ```
  Standard LD_PRELOAD discipline — one line per symbol.
- **Chromium GPU process**: forks separately. With `--no-sandbox` it inherits LD_PRELOAD; with sandbox it doesn't. Engine already passes `--no-sandbox` in user-ns mode so we're fine.
- **Firefox content process**: fork+exec inherits env. ✓
- **Crash recovery**: any segfault in our hooks crashes the renderer. Each hook wraps the noise math in a guard — if `etld_seed == 0` (uninitialized) or original-symbol resolution failed, pass through unchanged.
- **Detectability**: `cat /proc/$BROWSERPID/maps | grep veil-inject` reveals presence to a process with proc access. Browsers don't expose this to web content. ✓

## Cross-platform

- **Linux**: as specified.
- **Windows**: separate code path. DLL injection via Microsoft Detours or manual IAT patching. Different .dll codebase. Same hook surfaces (`wglReadPixels` via `OPENGL32.DLL`, FreeType bundled in browser, `BCryptGenRandom` for entropy). Treat as separate Pro work item.
- **macOS**: `DYLD_INSERT_LIBRARIES` is the equivalent but Apple's hardened-runtime + SIP block it on Brave/Chrome by default. Pro tier is **Linux + Windows only initially**. macOS is a "Pro v3" item if there's market demand.

## What ships first

Not the lib. Free tier (extension + MITM) is shipping-grade now. The lib is documented and wired-in-spirit; implementation kicks off when the Pro tier business case lines up.

When implementation begins, build order:

1. `cmd/veil-inject` skeleton — empty .so with constructor/destructor, env-var-gated activation, hook-passthrough scaffolding
2. `glReadPixels` hook — highest leverage; covers all WebGL contexts
3. `glGetString` hook — moves WebGL UNMASKED_VENDOR/RENDERER from extension to lib (better coverage)
4. `FT_Load_Glyph` hook — font fingerprint
5. `getrandom` hook — entropy farbling
6. PulseAudio hook
7. Engine wiring with hard-fail on missing .so under Pro
8. Doctor check for snap/flatpak
9. Windows port (Detours)
