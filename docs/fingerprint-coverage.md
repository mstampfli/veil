# Veil fingerprint coverage matrix

What every browser/OS/network fingerprint vector is, where Veil mediates it, and any remaining leak. Updated when any layer changes.

## Quick taxonomy

Veil has four layers that mediate fingerprints:

1. **Engine (kernel)** — netns, NFQUEUE TCP rewriter, cgroup CPU throttle, time namespace, kill switch. Operates on packets and process-level resources before any application code runs.
2. **tls_mitm backend** — terminates browser TLS, re-handshakes upstream with uTLS-shaped fingerprint, mediates HTTP/1.1 and HTTP/2 framing per chosen browser.
3. **Persona extension** (`internal/launcher/persona-extension/_embed/`) — content script injected at `document_start` in the page's MAIN world. Overrides `navigator.*`, `screen.*`, WebGL, AudioContext, Intl, Battery, etc. Reads persona JSON written to the profile data dir.
4. **Brave Shields aggressive prefs** (Chromium-family only) — pre-populated `Preferences` JSON sets `brave-fingerprinting-v2 = 2`. Brave's C++ farbling layer randomizes canvas/audio/font output per-eTLD per-session at native speed.

## Coverage matrix

| Fingerprint surface | What real browsers do | Where Veil mediates | Status | Notes |
|---|---|---|---|---|
| **TLS handshake (JA3 / JA4)** | BoringSSL / NSS specific cipher + extension order | tls_mitm uTLS Hello (`fingerprint:` chrome/firefox/tor/safari/edge) | ✅ full | Per-fp template from refraction-networking/utls. |
| **TCP fingerprint (TTL / MSS / WS / DF)** | Kernel TCP stack | NFQUEUE rewriter (`tcp_persona:` linux/windows/macos/ios/android) | ✅ full | Linux only; Windows port via WinDivert. |
| **Time namespace** | OS-wide clock | `CLONE_NEWTIME` per profile (Linux 5.6+) | ✅ full | Per-profile monotonic offset breaks cross-profile correlation. |
| **DNS routing** | OS resolver | netns `/etc/netns/<name>/resolv.conf` + chain DNS | ✅ full | All DNS through chain; no host-resolver fallback. |
| **WebRTC local IP leak** | Real interface enumeration | netns isolation + `--disable-features=WebRtcHideLocalIpsWithMdns` | ✅ full | Local IPs inside netns are veil's veth, not host's wifi. |
| **HTTP/2 fingerprint (Akamai H2 hash)** | SETTINGS values + frame ordering + initial WU + PRIORITY | tls_mitm h2 mediator | ✅ full | Persistent HPACK decoder; CONTINUATION aggregation. |
| **HTTP/1.1 fingerprint (header order/casing)** | Browser-specific | tls_mitm h1 mediator | ✅ full | Strips browser-specific headers per fingerprint, force-sets target browser's headers. |
| **navigator.userAgent + appVersion + oscpu + platform + vendor** | OS+browser at compile time | extension override + `--user-agent` flag (Chromium) / `general.useragent.override` (Firefox) | ✅ full | Persona-driven. |
| **navigator.userAgentData (Client Hints)** | Chromium-only modern API | extension `getHighEntropyValues` override | ✅ full | brands+platform+platformVersion all mediated. |
| **navigator.languages / language** | OS locale | extension + `--accept-lang` flag | ✅ full | |
| **navigator.hardwareConcurrency** | CPU core count | extension override | ✅ full | |
| **navigator.deviceMemory** | RAM | extension override | ✅ full | |
| **navigator.maxTouchPoints** | Touchscreen capability | extension override | ✅ full | |
| **navigator.webdriver** | `true` when driven by automation | extension forces `false` | ✅ full | Veil drives via CDP/Marionette so this would otherwise be `true`. |
| **navigator.brave / brave.isBrave()** | Brave-only API | extension strips | ✅ full | Brave-on-Linux can claim to be Chrome. |
| **navigator.plugins / mimeTypes** | Browser-specific plugin list | extension synthesizes per persona family | ✅ full | Chrome PDF Viewer family or empty (Firefox). |
| **navigator.permissions.query** | Behavior differs Chrome vs Firefox | extension wraps `notifications` query | ⚠️ partial | Only `notifications` covered; other permissions pass through. |
| **navigator.connection (Network Info API)** | Chromium reports rtt/downlink/effectiveType | extension synthesizes for Chrome personas, hides for Firefox | ✅ full | |
| **navigator.cookieEnabled / pdfViewerEnabled** | Defaults vary | extension forces `true` for Chrome personas | ✅ full | |
| **navigator.mediaDevices.enumerateDevices** | Reports OS audio/video devices | extension synthesizes 1× audioinput + audiooutput + videoinput | ✅ full | Pre-permission-grant (deviceIds blank) — matches "user hasn't granted media permissions yet". |
| **window.chrome object hierarchy** | Chromium injects this | extension synthesizes for Chrome personas, deletes for Firefox personas | ⚠️ partial | Stub only — has csi/loadTimes; lacks chrome.runtime/app/webstore. |
| **screen.width/height/availW/availH** | Display | extension override | ✅ full | |
| **screen.colorDepth / pixelDepth** | Display | extension override | ✅ full | |
| **window.devicePixelRatio** | Display | extension override + `--force-device-scale-factor=1` | ✅ full | |
| **WebGL UNMASKED_VENDOR / UNMASKED_RENDERER** | GPU strings | extension WebGLRenderingContext.getParameter wrap | ✅ full | Per-persona GPU strings or generic Intel UHD 620. |
| **WebGL canvas pixel output (readPixels)** | Real GPU rendering | extension wraps `readPixels` with per-eTLD-seeded ±1 channel noise | ✅ full | Brave-independent — works on any Chromium-family. |
| **Canvas 2D toDataURL/getImageData/toBlob pixels** | Real rendering | extension wraps `getImageData` with per-eTLD seeded ±1 noise; `toDataURL`/`toBlob` route through it | ✅ full | Same farbling model as Brave Shields, in JS. |
| **AudioContext.sampleRate** | OS audio config | extension override | ✅ full | |
| **AudioContext analyser data (per-sample noise)** | Real audio rendering | extension wraps `getFloatFrequencyData`/`getByteFrequencyData`/`getFloatTimeDomainData`/`getByteTimeDomainData` | ✅ full | |
| **Intl.DateTimeFormat / Date.getTimezoneOffset** | OS timezone | extension override | ✅ full | |
| **Battery API** | Real battery | extension synthesizes desktop:plugged or mobile:partial | ✅ full | |
| **Speech synthesis voices** | OS TTS engine | extension synthesizes generic 5-voice list | ✅ full | |
| **performance.now() precision** | 1µs (raw) or clamp to 1ms (cross-origin-isolation off) | extension `Math.floor(performance.now())` | ✅ full | |
| **Font enumeration via measureText** | OS font list | extension wraps `measureText` with sub-pixel jitter | ✅ full | |
| **Geolocation API** | OS geolocation | extension overrides with persona-timezone-derived coords; permission-denied if no persona | ✅ full | |
| **Service Worker fingerprint** | Cache + SW lifecycle | nothing | ❌ residual | Sites can still detect SW-internal context if they ship one; rare. |
| **PDF viewer behavior** | Chromium internal viewer | navigator.pdfViewerEnabled forced; PDF.js internals untouched | ⚠️ partial | |
| **WebGPU (navigator.gpu)** | GPU adapter info | extension makes `requestAdapter` return null | ✅ full | Forces fallback to WebGL which IS mediated. |
| **WebRTC SDP host candidates** | Local interface IPs | extension scrubs `host` candidates from createOffer SDP + `--disable-features=WebRtcHideLocalIpsWithMdns` | ✅ full | |
| **navigator.storage.estimate (quota)** | Real disk quota | extension forces ~275 GiB | ✅ full | Defeats "headless = small quota" detection. |
| **Notification.permission** | Real permission | extension forces `"default"` | ✅ full | |
| **Gamepad / USB / Serial / HID / Bluetooth API presence** | Real device list | extension makes `getDevices` etc. return empty | ✅ full | API present (don't leak Tor Browser's stripping); device list empty. |

## What "full" vs "partial" vs "missing" mean

- **full** — the surface produces persona-shaped values for both Chromium-family and Firefox-family personas, and forwarding handlers preserve native-shape so extension overrides aren't trivially detectable via `.toString().includes("native code")` checks.
- **partial** — the surface is mediated but the override is incomplete (only some sub-cases covered, or no value-substitution per fingerprint).
- **residual** — no extension/MITM coverage; relies on the chain layer or accepts a small leak surface for an obscure detector.

Note: previously some surfaces were marked "Brave-only" (relying on Brave Shields' C++ farbling). Those are now all in the extension itself with per-eTLD seeded farbling, working on any Chromium-family or Firefox.

## Strict tier vs basic tier vs persona

| Tier / mode | TLS spoof (uTLS) | HTTP layer mediator | JS extension (generic) | JS extension (persona-specific) | Brave Shields | TCP persona | Per-profile CA install |
|---|---|---|---|---|---|---|---|
| `anti_fingerprint: basic` | ❌ no | ❌ no | ✅ yes (generic blend) | ❌ no | ✅ aggressive (Brave only) | ✅ yes | ❌ no |
| `anti_fingerprint: strict` | ✅ yes | ✅ yes | ✅ yes (generic blend) | ❌ no | ✅ aggressive (Brave only) | ✅ yes | ✅ yes |
| `persona: <name>` | ✅ yes | ✅ yes | n/a | ✅ persona's specific values | ❌ off (persona has specific values; farbling would conflict) | ✅ yes | ✅ yes |
| `forge_persona: true` | ✅ yes | ✅ yes | n/a | ✅ forged-once-per-profile | ❌ off | ✅ yes | ✅ yes |
| `persona + anti_fingerprint: strict` | ✅ yes | ✅ yes | n/a | ✅ persona wins | ❌ off | ✅ yes | ✅ yes |

When persona and anti_fingerprint are both set, persona wins (specific values feed the extension instead of generic-blend), but the engine still does both modes' setup — TLS spoof, HTTP mediation, etc.

## Threat-model bottom line

For a typical anti-detect profile on Brave with `anti_fingerprint: strict + persona`:
- Sites running JA3/JA4 detection: **fingerprint matches the persona's claimed browser**.
- Sites running Akamai-style HTTP/2 detection: **fingerprint matches**.
- Sites running navigator.* JS detection: **fingerprint matches**.
- Sites running canvas/audio/font fingerprinting: **per-eTLD farbled values via Brave Shields**.
- Sites running TCP-layer passive OS detection (rare): **fingerprint matches the TCP persona**.
- Sites running HSTS-preload + cert-transparency checks: **may refuse the substituted cert** (banks, some Google services). Trade-off of per-profile CA.
- Sites running IP-reputation checks: **only as good as the chain's exit IP** — Tor exits flagged universally; residential VPN moderate; datacenter IP flagged.

Remaining detectable: cross-tab correlation if the user opens the same persona on multiple sites in the same session (cookie / localStorage state matches), and exotic behavioral fingerprints (mouse curves, keystroke dynamics — partially covered by mouse_jitter/behavioral_jitter when enabled).
