// Veil persona — background service worker / event page.
//
// CRITICAL responsibility: confirm to Veil that this extension
// loaded with the expected persona BEFORE any page in the browser
// reaches the network. Veil's launcher waits for this probe; if it
// doesn't arrive (or arrives with the wrong persona), Veil kills
// the browser before the user can click anywhere. Without this
// gate, a half-loaded extension could silently let the browser
// fingerprint as the host system.

(async () => {
  try {
    const url = chrome.runtime.getURL("persona.json");
    const resp = await fetch(url);
    if (!resp.ok) {
      console.error("[veil-bg] persona.json fetch failed:", resp.status);
      return;
    }
    const persona = await resp.json();
    // Stash for any future query.
    try { await chrome.storage.local.set({ persona }); } catch (_) {}

    // Phone home to Veil's per-session probe URL. The URL + token
    // come from persona.json — Veil writes them at install time.
    const probeURL = persona._veil_probe_url;
    const probeToken = persona._veil_probe_token;
    if (!probeURL || !probeToken) {
      console.warn("[veil-bg] no probe URL/token in persona.json — Veil's gate is disabled (insecure)");
      return;
    }
    // Send the persona blob back so Veil can verify it matches what
    // it wrote (detects tampering / truncation in transit).
    const r = await fetch(probeURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Veil-Probe-Token": probeToken,
      },
      body: JSON.stringify(persona),
    });
    if (!r.ok) {
      console.error("[veil-bg] persona probe rejected by Veil:", r.status, await r.text());
      // Veil will kill the browser on its end. We do nothing here.
      return;
    }
    console.debug("[veil-bg] persona probe accepted by Veil");
  } catch (e) {
    console.error("[veil-bg] persona probe failed:", e);
    // Veil's timeout fires; it kills the browser. No action here.
  }
})();
