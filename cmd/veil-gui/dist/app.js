// Veil GUI — talks to the Go backend via Wails bindings.
//
// All bound methods live under window.go.gui.App.* . If Wails isn't
// available (browser preview) we fall back to mock data so the UI is
// still navigable for layout work.

const W = (() => {
  if (window.go && window.go.gui && window.go.gui.App) return window.go.gui.App;
  console.warn("Wails bindings not found — using mock");
  return mockBackend();
})();

const Icon = (name, opts) => (window.Veil && window.Veil.icon) ? window.Veil.icon(name, opts) : "";
const Flag = (cc, opts) => (window.Veil && window.Veil.flagImg) ? window.Veil.flagImg(cc, opts) : "";

// Per-profile transient UI state ("starting" | "stopping"). Lets the
// row reflect "in-flight" actions so the user doesn't think a click
// did nothing during the seconds-long launch/teardown.
const transientState = new Map();

// Wrap an <input> in a flex row with a "Browse" button that calls
// the native file/directory picker. kind ∈ {"wg","ovpn","binary","dir",""}.
// Resolves the path back into the input on success.
function attachBrowse(input, kind) {
  if (!input || input.dataset.browseAttached) return;
  input.dataset.browseAttached = "1";
  const wrap = document.createElement("div");
  wrap.className = "input-row";
  const parent = input.parentNode;
  parent.insertBefore(wrap, input);
  wrap.appendChild(input);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn small browse";
  btn.textContent = "Browse…";
  btn.addEventListener("click", async () => {
    try {
      const cur = (input.value || "").trim();
      const defaultDir = cur ? cur.replace(/\/[^\/]*$/, "") : "";
      const path = (kind === "dir")
        ? await W.BrowseDirectory(defaultDir)
        : await W.BrowseFile(kind || "", defaultDir);
      if (path) input.value = path;
    } catch (e) {
      toast(String(e), "error");
    }
  });
  wrap.appendChild(btn);
}

// ---------- view routing ----------

const views = document.querySelectorAll(".view");
const navItems = document.querySelectorAll(".nav-item");

function show(viewName, opts = {}) {
  views.forEach(v => v.classList.toggle("active", v.id === "view-" + viewName));
  navItems.forEach(n => n.classList.toggle("active", n.dataset.view === viewName));
  // Reset scroll on view switch — otherwise scrolling on a long
  // view (e.g. profile editor) carries over to the next view and
  // makes it look already scrolled.
  const main = document.querySelector("main") || document.scrollingElement;
  if (main) main.scrollTop = 0;
  window.scrollTo(0, 0);
  if (viewName === "profiles") refreshProfiles();
  if (viewName === "doctor") runDoctor();
  if (viewName === "logs") refreshLogs();
  if (viewName === "tor")  refreshTorCircuits();
  if (viewName === "new" && !opts.skipReset) resetForm();
}

navItems.forEach(n => n.addEventListener("click", () => { if (n.dataset.view) show(n.dataset.view); }));

// "Report a bug" is an action, not a view — opens GitHub via the backend.
const _rb = document.getElementById("btn-report-bug");
if (_rb) _rb.addEventListener("click", () => { try { W.ReportBug && W.ReportBug(); } catch (e) { console.warn(e); } });

document.getElementById("btn-new").addEventListener("click", () => show("new"));
document.getElementById("btn-empty-new").addEventListener("click", () => show("new"));
document.getElementById("cancel-form").addEventListener("click", () => show("profiles"));

// ---------- bulk import ----------

(async () => {
  const sel = document.getElementById("bulk-preset");
  if (!sel) return;
  for (const p of await W.Presets()) {
    const opt = document.createElement("option");
    opt.value = p; opt.textContent = p;
    if (p === "firefox") opt.selected = true;
    sel.appendChild(opt);
  }
})();

document.getElementById("bulk-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(ev.target);
  const path = fd.get("path");
  const format = fd.get("format");
  const preset = fd.get("preset");
  const ks = !!fd.get("kill_switch");
  const out = document.getElementById("bulk-result");
  out.innerHTML = "<p class='muted'>Importing…</p>";
  try {
    const fn = format === "ovpn" ? W.BulkImportOVPN : W.BulkImportWG;
    const created = (await fn(path, preset, ks)) || [];
    if (created.length === 0) {
      out.innerHTML = `<p class="error">No new profiles created (no matching files, or all already imported).</p>`;
      return;
    }
    out.innerHTML = `<p style="color: var(--good)">Imported ${created.length} profile${created.length === 1 ? "" : "s"}:</p><ul style="margin: 6px 0 0; padding-left: 20px;">` +
      created.map(n => `<li class="mono">${escapeHtml(n)}</li>`).join("") + "</ul>";
    toast("Imported " + created.length + " profiles", "ok");
  } catch (e) {
    out.innerHTML = `<p class="error">${escapeHtml(String(e))}</p>`;
  }
});

// ---------- toasts ----------

function toast(msg, kind = "") {
  const stack = document.getElementById("toast-stack");
  if (!stack) return; // defensive — main DOM not ready yet
  const el = document.createElement("div");
  el.className = "toast " + kind;
  // Truncate long messages so the toast doesn't overflow off-screen.
  // Stack traces / multi-line errors get summarized; full content
  // is always in ~/.config/veil/logs/veil.log.
  const FULL = String(msg);
  const isLong = FULL.length > 200 || FULL.indexOf("\n") >= 0;
  if (isLong) {
    const head = FULL.split("\n")[0].slice(0, 180);
    el.textContent = head + (head.length < FULL.length ? "… " : " ");
    const note = document.createElement("span");
    note.style.opacity = "0.6";
    note.style.fontSize = "11px";
    note.style.display = "block";
    note.style.marginTop = "4px";
    note.textContent = "(see ~/.config/veil/logs/veil.log for full error)";
    el.appendChild(note);
    el.title = FULL; // hover shows everything
  } else {
    el.textContent = FULL;
  }
  stack.appendChild(el);
  setTimeout(() => el.remove(), 5500);
}

// ---------- custom confirmation modal ----------
//
// Replaces window.confirm() which renders the native dialog with the
// Wails titlebar ("JavaScript Wails …") and breaks the in-app theme.
// Returns a Promise<boolean>.
function confirmModal({ title, body, okLabel, okClass, cancelLabel } = {}) {
  return new Promise((resolve) => {
    const old = document.getElementById("confirm-modal");
    if (old) old.remove();
    const m = document.createElement("div");
    m.id = "confirm-modal";
    m.className = "modal-overlay";
    m.innerHTML = `
      <div class="modal-card" role="dialog" aria-modal="true">
        <header>
          <h2>${escapeHtml(title || "Confirm")}</h2>
        </header>
        <div class="modal-body">
          ${body ? `<p>${escapeHtml(body)}</p>` : ""}
        </div>
        <footer>
          <button class="btn ghost confirm-cancel">${escapeHtml(cancelLabel || "Cancel")}</button>
          <button class="btn ${okClass || "primary"} confirm-ok">${escapeHtml(okLabel || "OK")}</button>
        </footer>
      </div>
    `;
    document.body.appendChild(m);
    function close(value) {
      m.remove();
      document.removeEventListener("keydown", keyHandler);
      resolve(value);
    }
    function keyHandler(e) {
      if (e.key === "Escape") close(false);
      if (e.key === "Enter") close(true);
    }
    m.querySelector(".confirm-ok").addEventListener("click", () => close(true));
    m.querySelector(".confirm-cancel").addEventListener("click", () => close(false));
    m.addEventListener("click", (e) => { if (e.target === m) close(false); });
    document.addEventListener("keydown", keyHandler);
    // Focus the primary action by default.
    setTimeout(() => m.querySelector(".confirm-ok").focus(), 30);
  });
}

// ---------- chain helpers (used in profiles list) ----------

const HOP_ICON = {
  wireguard: "lock",
  openvpn:   "lock",
  socks5:    "network",
  http:      "globe",
  tor:       "onion",
  direct:    "arrow-right",
};
const HOP_LABEL = {
  wireguard: "WireGuard",
  openvpn:   "OpenVPN",
  socks5:    "SOCKS5",
  http:      "HTTP",
  tor:       "Tor",
  direct:    "Direct",
};

function renderChainPills(kinds) {
  if (!kinds || !kinds.length) return `<span class="muted" style="font-size:12px">no chain</span>`;
  return kinds.map((k, i) => {
    const arrow = i ? `<span class="chain-arrow">→</span>` : "";
    const ic = Icon(HOP_ICON[k] || "arrow-right");
    return arrow + `<span class="chain-hop">${ic}<span>${escapeHtml(HOP_LABEL[k] || k)}</span></span>`;
  }).join("");
}

// ---------- profiles list ----------

const list = document.getElementById("profile-list");
const empty = document.getElementById("profile-empty");

function showLockedEndpointError(profileName, msg) {
  const old = document.getElementById("err-modal");
  if (old) old.remove();
  // Backend has six distinct drift error shapes — try each in turn so
  // Required/Got fields actually populate. If none matches, we still
  // show the raw error in a Details row instead of "?/?".
  //   lock_country: peer country DE does not match required BE (...)
  //   lock_ip:      peer IP X.X.X.X does not match required Y.Y.Y.Y
  //   lock_asn:     peer ASN "X" does not match required "Y" (...)
  //   probe-once:   exit country DE != required BE (...)
  //   Tor verify:   exit country DE != required BE (...)
  //   peer-IP read: locked_endpoint: read peer IP from kernel: <reason>
  const patterns = [
    /peer (?:country|IP|ASN) "?(\S+?)"? does not match required "?(\S+?)"?(?:\s|$|—|,|\()/i,
    /exit (?:country|IP) "?(\S+?)"? != required "?(\S+?)"?(?:\s|$|—|,|\()/i,
  ];
  let got = "?", want = "?";
  for (const re of patterns) {
    const m = msg.match(re);
    if (m) { got = m[1]; want = m[2]; break; }
  }
  const ipMatch = msg.match(/peer_ip=([\d\.:]+)|ip=([\d\.:]+)/);
  const ip = ipMatch ? (ipMatch[1] || ipMatch[2]) : "";
  const modal = document.createElement("div");
  modal.id = "err-modal";
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card" style="max-width: 540px;">
      <header>
        <h2 style="display: flex; align-items: center; gap: 8px;">
          ${Icon("shield-x")}
          <span style="color: var(--bad);">Endpoint drift — refused to launch</span>
        </h2>
        <button class="btn small ghost" id="err-close">${Icon("x")}</button>
      </header>
      <p style="font-size: 13px; line-height: 1.6;">Profile <b>${escapeHtml(profileName)}</b> is locked. The actual exit doesn't match the locked-endpoint constraints, so launch was refused.</p>
      <table class="drift-table" style="margin: 14px 0 6px;">
        <tr><td style="color: var(--muted);">Required</td><td><b>${escapeHtml(want)}</b></td></tr>
        <tr><td style="color: var(--muted);">Got</td><td style="color: var(--bad);">${escapeHtml(got)}${ip ? `  <span class="muted">(${escapeHtml(ip)})</span>` : ""}</td></tr>
      </table>
      ${(want === "?" || got === "?") ? `<p class="muted" style="font-size: 11.5px; margin: 6px 0 0; word-break: break-word;">Details: <code>${escapeHtml(msg)}</code></p>` : ""}
      <p class="muted" style="font-size: 12px; margin-top: 10px;">Tighten or relax the constraint in profile settings, or pick a different upstream config.</p>
      <div class="form-actions" style="margin-top: 14px; padding: 0; border: 0;"><button class="btn primary" id="err-close-2">OK</button></div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
  document.getElementById("err-close").addEventListener("click", () => modal.remove());
  document.getElementById("err-close-2").addEventListener("click", () => modal.remove());
}

function showScheduleGuardError(profileName, msg) {
  const old = document.getElementById("err-modal");
  if (old) old.remove();
  const winMatch = msg.match(/schedule_window (\S+)/);
  const nowMatch = msg.match(/now=(\d+:\d+) in (\S+)/);
  const modal = document.createElement("div");
  modal.id = "err-modal";
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card" style="max-width: 480px;">
      <header>
        <h2 style="display: flex; align-items: center; gap: 8px;">
          ${Icon("timer")}
          <span style="color: var(--warn);">Outside schedule window</span>
        </h2>
        <button class="btn small ghost" id="err-close">${Icon("x")}</button>
      </header>
      <p style="font-size: 13.5px;">Profile <b>${escapeHtml(profileName)}</b> can't launch right now.</p>
      <table class="drift-table" style="margin: 14px 0;">
        <tr><td style="color: var(--muted);">Window</td><td><b>${escapeHtml(winMatch ? winMatch[1] : "?")}</b> (persona TZ)</td></tr>
        ${nowMatch ? `<tr><td style="color: var(--muted);">Now</td><td>${escapeHtml(nowMatch[1])} in ${escapeHtml(nowMatch[2])}</td></tr>` : ""}
      </table>
      <div class="form-actions" style="margin-top: 14px; padding: 0; border: 0;"><button class="btn primary" id="err-close-2">OK</button></div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
  document.getElementById("err-close").addEventListener("click", () => modal.remove());
  document.getElementById("err-close-2").addEventListener("click", () => modal.remove());
}

function showStrictConsentModal(profileName, info, onAccept) {
  const old = document.getElementById("strict-consent-modal");
  if (old) old.remove();
  const fp = info.ca_fingerprint_hex || "(CA not generated yet — will be created on accept)";
  const subj = info.ca_subject || "Veil Local TLS Interception CA";
  const path = info.ca_cert_path || (info.data_dir ? info.data_dir + "/veil-ca/root.crt" : "(none)");
  const ks = info.keystore_backed
    ? '<span style="color: var(--good);">OS keystore (libsecret / DPAPI)</span>'
    : '<span style="color: var(--warn);">on disk (install libsecret-tools for stronger protection)</span>';
  const modal = document.createElement("div");
  modal.id = "strict-consent-modal";
  modal.className = "modal-overlay";
  modal.innerHTML = `
    <div class="modal-card" style="max-width: 580px;">
      <header>
        <h2 style="display: flex; align-items: center; gap: 8px;">
          ${Icon("shield-check") || Icon("warn")}
          <span>Strict anti-fingerprint — TLS interception</span>
        </h2>
        <button class="btn small ghost" id="sc-close">${Icon("x")}</button>
      </header>
      <p style="font-size: 13.5px; line-height: 1.6;">
        Profile <b>${escapeHtml(profileName)}</b> uses
        <code>anti_fingerprint: strict</code>. This installs a Veil-issued root
        certificate <b>only into this profile's data directory</b> so Veil can
        re-emit TLS handshakes with a coherent persona fingerprint.
      </p>
      <div style="background: rgba(255,255,255,0.04); border-radius: 6px; padding: 10px 12px; font-size: 12.5px; line-height: 1.7; margin: 12px 0;">
        <div><b>Scope</b>: this profile's browser only. The system trust store and your other browsers are <b>not</b> modified.</div>
        <div><b>CA path</b>: <code>${escapeHtml(path)}</code></div>
        <div><b>Subject</b>: ${escapeHtml(subj)}</div>
        <div><b>Fingerprint</b>: <code style="word-break: break-all;">${escapeHtml(fp)}</code></div>
        <div><b>Private key storage</b>: ${ks}</div>
      </div>
      <p style="font-size: 12.5px; color: var(--muted); line-height: 1.6;">
        While this profile is running, Veil sees decrypted traffic for the
        sites it loads — that's how the TLS fingerprint is rewritten. Switch
        the profile to <code>anti_fingerprint: basic</code> if you don't want this.
      </p>
      <div class="form-actions" style="margin-top: 14px; padding: 0; border: 0; gap: 8px;">
        <button class="btn ghost" id="sc-cancel">Cancel</button>
        <button class="btn primary" id="sc-accept">Accept &amp; launch</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  const close = () => modal.remove();
  modal.addEventListener("click", (e) => { if (e.target === modal) close(); });
  document.getElementById("sc-close").addEventListener("click", close);
  document.getElementById("sc-cancel").addEventListener("click", close);
  document.getElementById("sc-accept").addEventListener("click", async () => {
    document.getElementById("sc-accept").disabled = true;
    try { await onAccept(); } finally { close(); }
  });
}

function showDriftModal(profileName, rows) {
  const old = document.getElementById("drift-modal");
  if (old) old.remove();
  const modal = document.createElement("div");
  modal.id = "drift-modal";
  modal.className = "modal-overlay";
  const driftCount = (rows || []).filter(r => r.match === "DRIFT").length;
  modal.innerHTML = `
    <div class="modal-card">
      <header>
        <h2>${escapeHtml(profileName)} — drift check</h2>
        <button class="btn small ghost" id="drift-close">${Icon("x")}</button>
      </header>
      ${driftCount > 0
        ? `<p class="error" style="margin: 6px 0 14px; display: flex; align-items: center; gap: 6px;">${Icon("warn")}<span>${driftCount} field${driftCount === 1 ? "" : "s"} drifted from claimed values.</span></p>`
        : `<p style="color: var(--good); margin: 6px 0 14px; display: flex; align-items: center; gap: 6px;">${Icon("check-circle")}<span>No drift detected — all claimed fields match observed exit.</span></p>`}
      <table class="drift-table">
        <thead><tr><th>Field</th><th>Claimed</th><th>Observed</th><th>Match</th></tr></thead>
        <tbody>
          ${(rows || []).map(r => {
            const cls = r.match === "DRIFT" ? "drift-row" : (r.match === "ok" ? "ok-row" : "");
            return `<tr class="${cls}"><td>${escapeHtml(r.field)}</td><td>${escapeHtml(r.claimed || "—")}</td><td>${escapeHtml(r.observed || "—")}</td><td>${escapeHtml(r.match)}</td></tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>
  `;
  document.body.appendChild(modal);
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
  document.getElementById("drift-close").addEventListener("click", () => modal.remove());
}

async function refreshProfiles() {
  let profs = [];
  try { profs = await W.ListProfiles() || []; }
  catch (e) { toast("List failed: " + e, "error"); return; }

  list.innerHTML = "";
  empty.classList.toggle("hidden", profs.length > 0);

  for (const p of profs) {
    const row = document.createElement("div");
    const trans = transientState.get(p.name);
    let dotClass = "";
    let statusLabel = "stopped";
    let rowMod = "";
    if (trans === "starting") {
      dotClass = "running"; statusLabel = "starting…"; rowMod = "is-starting";
    } else if (trans === "stopping") {
      dotClass = "running"; statusLabel = "stopping…"; rowMod = "is-stopping";
    } else if (p.running) {
      if (p.health === "degraded") {
        dotClass = "degraded"; statusLabel = "degraded"; rowMod = "is-running";
      } else if (p.health === "failed") {
        dotClass = "failed"; statusLabel = "failed"; rowMod = "is-failed";
      } else {
        dotClass = "running"; statusLabel = "running"; rowMod = "is-running";
      }
    }
    row.className = "profile-row " + rowMod;

    const ipTag = p.running && p.last_ip
      ? `<span class="ip-tag">${escapeHtml(p.last_ip)}</span>` : "";
    const presetPill = (p.preset || p.app)
      ? `<span class="preset-pill">${escapeHtml(p.preset || p.app)}</span>` : "";
    const desc = p.description
      ? `<span class="desc" title="${escapeAttr(p.description)}">${escapeHtml(p.description)}</span>`
      : `<span class="desc muted">no description</span>`;

    const torEnabled = (p.chain_kinds || []).includes("tor");

    const inFlight = !!trans;
    const launchDisabled = inFlight ? "disabled" : "";
    const auxDisabled = (p.running && !inFlight) ? "" : "disabled";
    const launchLabel = inFlight
      ? (trans === "starting" ? "Starting…" : "Stopping…")
      : (p.running ? "Stop" : "Launch");
    const launchIcon = inFlight ? Icon("refresh") : (p.running ? Icon("x") : Icon("play"));

    row.innerHTML = `
      <div class="status">
        <span class="dot ${dotClass}" title="${escapeAttr(p.health || statusLabel)}"></span>
        <span class="status-label">${escapeHtml(statusLabel)}</span>
      </div>
      <div class="ident">
        <div class="name">
          <span>${escapeHtml(p.name)}</span>
          ${ipTag}
        </div>
        <div class="meta-line">
          ${presetPill}
          ${desc}
        </div>
      </div>
      <div class="chain">${renderChainPills(p.chain_kinds || [])}</div>
      <div class="actions">
        <button class="btn small launch ${p.running && !inFlight ? "danger" : "primary"}" ${launchDisabled}>
          ${launchIcon}${launchLabel}
        </button>
        <button class="btn small icon-only ip" title="Show external IP" ${auxDisabled}>${Icon("globe")}</button>
        <button class="btn small icon-only stats" title="Traffic stats" ${auxDisabled}>${Icon("activity")}</button>
        <button class="btn small icon-only drift" title="Compare live exit vs persona's claim" ${auxDisabled}>${Icon("shield-check")}</button>
        <button class="btn small icon-only soft-reroll" title="Tor: new circuits without dropping connections" ${(p.running && torEnabled && !inFlight) ? "" : "disabled"}>${Icon("circuit")}</button>
        <button class="btn small icon-only reroll" title="Hard reroll: full restart, drops connections" ${auxDisabled}>${Icon("refresh")}</button>
        <button class="btn small icon-only edit" title="Edit profile" ${inFlight ? "disabled" : ""}>${Icon("edit")}</button>
        <button class="btn small icon-only danger del" title="Delete" ${inFlight ? "disabled" : ""}>${Icon("trash")}</button>
      </div>
      <div class="row-detail hidden"></div>
    `;
    const detail = row.querySelector(".row-detail");
    function setDetail(html, kind) {
      if (!html) {
        detail.classList.add("hidden");
        detail.innerHTML = "";
        return;
      }
      detail.className = "row-detail" + (kind ? " " + kind : "");
      detail.innerHTML = html + ' <button class="btn small ghost row-detail-close">${Icon("x")}</button>'.replace('${Icon("x")}', Icon("x"));
      const close = detail.querySelector(".row-detail-close");
      if (close) close.addEventListener("click", () => setDetail(""));
    }
    function setDetailLoading(label) {
      setDetail(`<span class="loading">${escapeHtml(label)}…</span>`, "loading");
    }
    row.querySelector(".launch").addEventListener("click", async () => {
      if (transientState.has(p.name)) return; // already in flight
      const wasRunning = p.running;
      transientState.set(p.name, wasRunning ? "stopping" : "starting");
      refreshProfiles(); // immediately reflect transient state
      try {
        if (wasRunning) {
          await W.StopProfile(p.name);
          toast(p.name + " stopped", "ok");
        } else {
          const r = await W.LaunchProfile(p.name);
          toast(p.name + " launched (pid " + r.pid + ")", "ok");
        }
      } catch (e) {
        const s = String(e);
        if (s.includes("locked_endpoint:")) {
          showLockedEndpointError(p.name, s);
        } else if (s.includes("schedule guard:")) {
          showScheduleGuardError(p.name, s);
        } else if (s.includes("strict-tier consent required")) {
          // Pop the per-profile consent dialog. After accept, retry the
          // launch automatically — the user's intent was "launch this",
          // not "let me think about it."
          try {
            const info = await W.StrictTierConsent(p.name);
            showStrictConsentModal(p.name, info, async () => {
              await W.AcceptStrictTier(p.name);
              const r = await W.LaunchProfile(p.name);
              toast(p.name + " launched (pid " + r.pid + ")", "ok");
              transientState.delete(p.name);
              refreshProfiles();
            });
          } catch (innerErr) {
            toast(String(innerErr), "error");
          }
        } else {
          toast(s, "error");
        }
      } finally {
        // Always clear transient + refresh, even on error, so the row
        // reflects the real backend state and the user can retry.
        transientState.delete(p.name);
        refreshProfiles();
      }
    });
    row.querySelector(".ip").addEventListener("click", async () => {
      setDetailLoading("Probing external IP via browser");
      try {
        const info = await W.ProfileExternalIPInfo(p.name);
        const ip = info.ip || "(unknown)";
        const loc = [info.city, info.region, info.country].filter(Boolean).join(", ");
        const org = info.org || "";
        const flag = info.country ? Flag(info.country, { size: 14 }) : "";
        setDetail(`
          <div class="kv-grid">
            <div><span class="muted">IP</span> <code>${escapeHtml(ip)}</code></div>
            ${loc ? `<div><span class="muted">Location</span> ${flag} ${escapeHtml(loc)}</div>` : ""}
            ${org ? `<div><span class="muted">ASN/Org</span> ${escapeHtml(org)}</div>` : ""}
          </div>
        `);
        toast(p.name + ":  " + ip + (loc ? "  •  " + loc : ""), "ok");
        // Notify dashboard so its IP card updates without waiting
        // for the next poll cycle.
        window.dispatchEvent(new CustomEvent("veil:profile-ip-updated", {
          detail: { profile: p.name, info },
        }));
      } catch (e) {
        setDetail(`<span class="error">IP probe failed: ${escapeHtml(String(e))}</span>`, "error");
        toast(String(e), "error");
      }
    });
    row.querySelector(".stats").addEventListener("click", async () => {
      setDetailLoading("Reading interface counters");
      try {
        const s = await W.ProfileStats(p.name);
        const tx = humanBytes(s.tx_bytes), rx = humanBytes(s.rx_bytes);
        const txp = (s.tx_packets || 0).toLocaleString();
        const rxp = (s.rx_packets || 0).toLocaleString();
        setDetail(`
          <div class="kv-grid">
            <div><span class="muted">Iface</span> <code>${escapeHtml(s.iface || "")}</code></div>
            <div><span class="muted">↑ Sent</span> ${tx} <span class="muted">(${txp} pkt)</span></div>
            <div><span class="muted">↓ Recv</span> ${rx} <span class="muted">(${rxp} pkt)</span></div>
          </div>
        `);
        toast(`${p.name} (${s.iface}): ↑ ${tx}  ↓ ${rx}`, "ok");
      } catch (e) {
        setDetail(`<span class="error">Stats failed: ${escapeHtml(String(e))}</span>`, "error");
        toast(String(e), "error");
      }
    });
    row.querySelector(".drift").addEventListener("click", async () => {
      setDetailLoading("Comparing claimed vs observed via browser");
      try {
        const rows = await W.ProfileDrift(p.name);
        setDetail("");
        showDriftModal(p.name, rows);
      } catch (e) {
        setDetail(`<span class="error">Drift check failed: ${escapeHtml(String(e))}</span>`, "error");
        toast(String(e), "error");
      }
    });
    row.querySelector(".soft-reroll").addEventListener("click", async () => {
      setDetailLoading("Signaling NEWNYM to Tor control");
      try {
        await W.SoftReroll(p.name);
        setDetail(`<span class="ok">${Icon("check-circle")} New Tor circuits signaled — existing connections kept on old circuits.</span>`, "ok");
        toast(p.name + ": new Tor circuits signaled (no drops)", "ok");
      } catch (e) {
        setDetail(`<span class="error">Soft reroll failed: ${escapeHtml(String(e))}</span>`, "error");
        toast(String(e), "error");
      }
    });
    row.querySelector(".reroll").addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Hard reroll " + p.name + "?",
        body: "Stops the profile and re-launches it. All open connections inside this profile will drop.",
        okLabel: "Reroll",
        okClass: "danger",
      });
      if (!ok) return;
      setDetailLoading("Restarting profile");
      try {
        await W.HardReroll(p.name);
        setDetail(`<span class="ok">${Icon("check-circle")} Rerolled.</span>`, "ok");
        toast(p.name + " rerolled", "ok");
        refreshProfiles();
      } catch (e) {
        setDetail(`<span class="error">Reroll failed: ${escapeHtml(String(e))}</span>`, "error");
        toast(String(e), "error");
      }
    });
    row.querySelector(".edit").addEventListener("click", async () => {
      try {
        const full = await W.GetProfile(p.name);
        show("new", { skipReset: true });
        loadIntoForm(full);
      } catch (e) { toast(String(e), "error"); }
    });
    row.querySelector(".del").addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Delete profile " + p.name + "?",
        body: "Removes the profile YAML, its data dir, and any forged persona. Cannot be undone.",
        okLabel: "Delete",
        okClass: "danger",
      });
      if (!ok) return;
      try {
        await W.DeleteProfile(p.name);
        toast("Deleted", "ok");
        refreshProfiles();
      } catch (e) { toast(String(e), "error"); }
    });
    list.appendChild(row);
  }
}

// ---------- profile form ----------

const form = document.getElementById("profile-form");
const hops = document.getElementById("chain-hops");
const presetSel = document.getElementById("preset-select");

(async () => {
  for (const p of await W.Presets()) {
    const opt = document.createElement("option");
    opt.value = p; opt.textContent = p;
    presetSel.appendChild(opt);
  }
})();

// Attach Browse… buttons next to path-style fields.
attachBrowse(form.elements.binary, "binary");
attachBrowse(form.elements.data_dir, "dir");
{
  const bulkPath = document.querySelector('#bulk-form input[name="path"]');
  if (bulkPath) attachBrowse(bulkPath, "dir");
}

// anti_fingerprint and persona are NOT mutually exclusive — the engine
// runs both setups; persona's specific values win over generic blend in
// the extension, while strict's TLS+HTTP mediator + per-profile CA still
// apply. Show a hint when both are set so the user knows persona wins.
function maybeShowComboHint() {
  const af = form.elements.anti_fingerprint;
  const fp = form.elements.forge_persona;
  const ps = form.elements.persona;
  if (!af) return;
  const afOn = af.value === "basic" || af.value === "strict";
  const personaActive = (fp && fp.checked) || (ps && ps.value !== "");
  const hintEl = document.getElementById("anti-persona-combo-hint");
  if (hintEl) hintEl.style.display = (afOn && personaActive) ? "" : "none";
}
{
  const af = form.elements.anti_fingerprint;
  const fp = form.elements.forge_persona;
  const ps = form.elements.persona;
  if (af) af.addEventListener("change", maybeShowComboHint);
  if (fp) fp.addEventListener("change", maybeShowComboHint);
  if (ps) ps.addEventListener("change", maybeShowComboHint);
}

// Re-roll counter mixed into persona seed so the same profile name
// produces a fresh persona each click. Reset when the form is loaded
// (so editing an existing profile doesn't accidentally accumulate
// re-roll seed across opens).
let forgeRerollCounter = 0;

// Cascading dropdown setup: form factor → OS → browser → country.
// Each select narrows the next; selecting "(any)" widens.
let forgeCatalog = null;

async function loadForgeCatalog() {
  if (forgeCatalog) return forgeCatalog;
  try {
    forgeCatalog = await W.ForgeCatalog();
  } catch (e) {
    console.warn("ForgeCatalog failed:", e);
    forgeCatalog = { form_factors: [], oses: [], oses_by_form: {}, browsers: [], browsers_by_os: {}, countries: [] };
  }
  return forgeCatalog;
}

function refillSelect(sel, items, placeholderLabel) {
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = "";
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = placeholderLabel;
  sel.appendChild(opt0);
  for (const it of items) {
    const opt = document.createElement("option");
    if (typeof it === "string") {
      opt.value = it;
      opt.textContent = it;
    } else {
      opt.value = it.code;
      opt.textContent = it.name + " (" + it.code + ")";
    }
    sel.appendChild(opt);
  }
  // Restore previous selection if still valid; else fall back to "any".
  const valid = Array.from(sel.options).some(o => o.value === cur);
  sel.value = valid ? cur : "";
}

async function setupForgeDropdowns() {
  const cat = await loadForgeCatalog();
  const formSel = document.getElementById("forge-form");
  const osSel = document.getElementById("forge-os");
  const browserSel = document.getElementById("forge-browser");
  const countrySel = document.getElementById("forge-country");
  if (!formSel || !osSel || !browserSel || !countrySel) return;

  // Country list is static.
  refillSelect(countrySel, cat.countries || [], "(auto)");

  function updateOSes() {
    const ff = formSel.value;
    const oses = ff ? (cat.oses_by_form[ff] || []) : (cat.oses || []);
    refillSelect(osSel, oses, "(auto from form factor)");
    updateBrowsers();
  }
  function updateBrowsers() {
    const os = osSel.value;
    const browsers = os ? (cat.browsers_by_os[os] || []) : [];
    refillSelect(browserSel, browsers, os ? "(auto from OS)" : "(pick OS first)");
  }

  formSel.addEventListener("change", updateOSes);
  osSel.addEventListener("change", updateBrowsers);

  updateOSes();
}
setupForgeDropdowns();

function readForgeOptions() {
  const formEl = document.getElementById("forge-form");
  const osEl = document.getElementById("forge-os");
  const brEl = document.getElementById("forge-browser");
  const cEl = document.getElementById("forge-country");
  return {
    form_factor: (formEl && formEl.value) || "",
    os: (osEl && osEl.value) || "",
    browser: (brEl && brEl.value) || "",
    country: (cEl && cEl.value) || "",
    seed: String(forgeRerollCounter),
  };
}

function showForgeError(msg) {
  const el = document.getElementById("forge-error");
  if (!el) return;
  if (!msg) {
    el.style.display = "none";
    el.textContent = "";
  } else {
    el.style.display = "";
    el.textContent = msg;
  }
}

async function runForgePreview() {
  const name = (form.elements.name && form.elements.name.value) || "";
  const out = document.getElementById("persona-preview-out");
  if (!name) {
    toast("Set a profile name first", "warn");
    return;
  }
  if (!out) return;
  showForgeError("");
  try {
    const opts = readForgeOptions();
    const p = await W.ForgePersonaWith(name, opts);
    const lines = [
      "name:        " + (p.name || ""),
      "user_agent:  " + (p.user_agent || ""),
      "platform:    " + (p.platform || "") + "  (" + (p.oscpu || "") + ")",
      "engine:      " + (p.engine || "blink"),
      "vendor:      " + (p.vendor || ""),
      "screen:      " + (p.screen_width || 0) + "x" + (p.screen_height || 0)
                     + " @" + (p.device_pixel_ratio || 1) + "x",
      "hardware:    " + (p.hardware_concurrency || 0) + " cores, "
                      + (p.device_memory || 0) + " GB",
      "locale:      " + (p.locale || "") + "   (tz=" + (p.timezone || "") + ", "
                      + (p.country || "") + ")",
      "webgl:       " + (p.webgl_unmasked_vendor || "") + " / "
                      + (p.webgl_unmasked_renderer || ""),
    ];
    out.textContent = lines.join("\n");
    out.classList.remove("hidden");
  } catch (err) {
    showForgeError(String(err));
    out.textContent = "preview failed: " + err;
    out.classList.remove("hidden");
  }
}

const previewBtn = document.getElementById("btn-persona-preview");
if (previewBtn) {
  previewBtn.addEventListener("click", async () => {
    await runForgePreview();
  });
}
const rerollBtn = document.getElementById("btn-persona-reroll");
if (rerollBtn) {
  rerollBtn.addEventListener("click", async () => {
    forgeRerollCounter++;
    await runForgePreview();
  });
}

(async () => {
  const sel = document.getElementById("persona-select");
  if (!sel) return;
  try {
    const personas = (await W.Personas()) || [];
    for (const p of personas) {
      const opt = document.createElement("option");
      opt.value = p.name;
      opt.textContent = p.name + (p.description ? " — " + p.description : "");
      sel.appendChild(opt);
    }
  } catch (e) { /* no personas yet */ }
})();

document.getElementById("add-hop").addEventListener("click", () => addHop());

function addHop(b = { kind: "direct" }) {
  const row = document.createElement("div");
  row.className = "hop";
  row.innerHTML = `
    <select class="hop-kind">
      ${["direct","socks5","http","wireguard","openvpn","tor"].map(k =>
        `<option value="${k}" ${k === b.kind ? "selected" : ""}>${k}</option>`).join("")}
    </select>
    <div class="hop-fields"></div>
    <div class="hop-flags" style="display: flex; gap: 8px; align-items: center; flex-basis: 100%; margin-top: 4px;">
      <label class="checkbox" style="font-size: 11.5px; margin: 0;"><input type="checkbox" class="f-mandatory" ${b.mandatory ? "checked" : ""}/> mandatory</label>
      <label class="checkbox" style="font-size: 11.5px; margin: 0;"><input type="checkbox" class="f-optional"  ${b.optional  ? "checked" : ""}/> optional</label>
    </div>
    <button type="button" class="btn small icon-only danger remove" title="Remove hop">${Icon("x")}</button>
  `;
  const fields = row.querySelector(".hop-fields");
  const kindSel = row.querySelector(".hop-kind");
  function render() {
    const k = kindSel.value;
    fields.innerHTML = "";
    if (k === "socks5" || k === "http") {
      const pool = (b.host_pool && b.host_pool.length) ? b.host_pool.join("\n") : "";
      fields.innerHTML = `
        <input class="f-host" placeholder="host (single fixed)" value="${escapeAttr(b.host || "")}" />
        <input class="f-port" placeholder="port" type="number" value="${b.port || ""}" />
        <input class="f-user" placeholder="user (optional)" value="${escapeAttr(b.username || "")}" />
        <input class="f-pass" placeholder="pass (optional)" type="password" value="${escapeAttr(b.password || "")}" />
        <textarea class="f-host-pool" placeholder="OR pool of host:port, one per line — random pick per launch" rows="2" style="flex-basis: 100%; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(pool)}</textarea>
      `;
    } else if (k === "wireguard" || k === "openvpn") {
      const pool = (b.config_paths && b.config_paths.length) ? b.config_paths.join("\n") : "";
      fields.innerHTML = `
        <input class="f-config" placeholder="config path (.conf / .ovpn)" value="${escapeAttr(b.config_path || "")}" style="flex: 2" />
        <textarea class="f-config-pool" placeholder="OR pool of paths, one per line — random pick per launch" rows="2" style="flex: 2; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(pool)}</textarea>
      `;
      const cfg = fields.querySelector(".f-config");
      if (cfg) attachBrowse(cfg, k === "wireguard" ? "wg" : "ovpn");
    } else if (k === "tor") {
      const transparentChecked = (b.transparent === undefined || b.transparent === null || b.transparent === true) ? "checked" : "";
      fields.innerHTML = `
        <input class="f-socks" placeholder="socks addr (default 127.0.0.1:9050)" value="${escapeAttr(b.socks_addr || "")}" />
        <input class="f-exit-country" placeholder="exit country (ISO 2-letter, empty = any)" value="${escapeAttr(b.tor_exit_country || "")}" maxlength="2" style="text-transform: lowercase;" />
        <label class="checkbox" style="font-size: 12px; gap: 6px; flex-basis: 100%; margin: 0;">
          <input type="checkbox" class="f-transparent" ${transparentChecked} />
          Transparent (force ALL TCP+DNS through Tor — recommended)
        </label>
      `;
    } else {
      fields.innerHTML = `<span class="muted" style="font-size: 12px;">No extra config</span>`;
    }
  }
  kindSel.addEventListener("change", render);
  row.querySelector(".remove").addEventListener("click", () => row.remove());
  render();
  hops.appendChild(row);
}

function readChain() {
  const out = [];
  for (const row of hops.querySelectorAll(".hop")) {
    const kind = row.querySelector(".hop-kind").value;
    const get = (cls) => {
      const el = row.querySelector("." + cls);
      return el ? el.value.trim() : "";
    };
    const hop = { kind };
    const mEl = row.querySelector(".f-mandatory");
    const oEl = row.querySelector(".f-optional");
    if (mEl && mEl.checked) hop.mandatory = true;
    if (oEl && oEl.checked) hop.optional = true;
    if (kind === "socks5" || kind === "http") {
      hop.host = get("f-host");
      const p = parseInt(get("f-port"), 10);
      if (p) hop.port = p;
      if (get("f-user")) hop.username = get("f-user");
      if (get("f-pass")) hop.password = get("f-pass");
      const pool = (row.querySelector(".f-host-pool")?.value || "")
        .split("\n").map(s => s.trim()).filter(Boolean);
      if (pool.length > 0) hop.host_pool = pool;
    } else if (kind === "wireguard" || kind === "openvpn") {
      const pool = (row.querySelector(".f-config-pool")?.value || "")
        .split("\n").map(s => s.trim()).filter(Boolean);
      if (pool.length > 0) hop.config_paths = pool;
      const single = get("f-config");
      if (single) hop.config_path = single;
    } else if (kind === "tor") {
      const s = get("f-socks");
      if (s) hop.socks_addr = s;
      const tEl = row.querySelector(".f-transparent");
      if (tEl) hop.transparent = tEl.checked;
      const cc = (row.querySelector(".f-exit-country")?.value || "").trim().toLowerCase();
      if (cc) hop.tor_exit_country = cc;
    }
    out.push(hop);
  }
  return out;
}

function resetForm(prof = null) {
  form.reset();
  hops.innerHTML = "";
  document.getElementById("form-error").classList.add("hidden");
  document.getElementById("form-title").textContent = prof ? "Edit profile" : "New profile";
  if (!prof) {
    addHop();
    return;
  }
  form.elements.name.value = prof.name || "";
  form.elements.description.value = prof.description || "";
  form.elements.preset.value = prof.app?.preset || "";
  form.elements.binary.value = prof.app?.binary || "";
  form.elements.args.value = (prof.app?.args || []).join("\n");
  form.elements.data_dir.value = prof.data_dir || "";
  form.elements.dns.value = (prof.dns || []).join(", ");
  form.elements.kill_switch.checked = prof.kill_switch !== false;
  // anti_fingerprint accepts the legacy boolean OR the new string enum.
  // Map both shapes onto the tri-state select: true → basic (compat),
  // false/empty → "", "basic"/"strict" → as-is.
  {
    let v = prof.anti_fingerprint;
    if (v === true) v = "basic";
    else if (v === false || v == null) v = "";
    form.elements.anti_fingerprint.value = (v === "basic" || v === "strict") ? v : "";
  }
  if (form.elements.randomize_chain) form.elements.randomize_chain.checked = !!prof.randomize_chain;
  if (form.elements.reroll_every) form.elements.reroll_every.value = prof.reroll_every || "";
  if (form.elements.tcp_persona) form.elements.tcp_persona.value = prof.tcp_persona || "";
  if (form.elements.cpu_throttle) form.elements.cpu_throttle.value = prof.cpu_throttle || "";
  if (form.elements.behavioral_jitter) form.elements.behavioral_jitter.checked = !!prof.behavioral_jitter;
  if (form.elements.persona) form.elements.persona.value = prof.persona || "";
  if (form.elements.forge_persona) form.elements.forge_persona.checked = !!prof.forge_persona;
  // Forge constraints — preserve so editing doesn't quietly drop them.
  // setupForgeDropdowns hasn't run yet on first load; defer cascade
  // population via setTimeout 0 so options are populated before we set.
  setTimeout(async () => {
    await setupForgeDropdowns();
    const ff = document.getElementById("forge-form");
    const os = document.getElementById("forge-os");
    const br = document.getElementById("forge-browser");
    const cc = document.getElementById("forge-country");
    if (ff && prof.forge_form_factor) {
      ff.value = prof.forge_form_factor;
      ff.dispatchEvent(new Event("change"));
    }
    if (os && prof.forge_os) {
      os.value = prof.forge_os;
      os.dispatchEvent(new Event("change"));
    }
    if (br && prof.forge_browser) br.value = prof.forge_browser;
    if (cc && prof.forge_country) cc.value = prof.forge_country;
  }, 0);
  const prev = document.getElementById("persona-preview-out");
  if (prev) { prev.classList.add("hidden"); prev.textContent = ""; }
  // Fresh re-roll counter per profile load so editing one doesn't
  // carry seed offset from the previous edit session. Existing
  // forge_seed from yaml stays in the saved profile until next
  // explicit re-roll click — preserves the user's previous identity.
  forgeRerollCounter = parseInt(prof.forge_seed || "0", 10) || 0;
  showForgeError("");
  try { maybeShowComboHint(); } catch (_) {}
  if (form.elements.locked_endpoint) form.elements.locked_endpoint.checked = !!prof.locked_endpoint;
  if (form.elements.lock_country) form.elements.lock_country.checked = !!prof.lock_country;
  if (form.elements.lock_asn) form.elements.lock_asn.checked = !!prof.lock_asn;
  if (form.elements.lock_ip) form.elements.lock_ip.checked = !!prof.lock_ip;
  if (form.elements.require_exit_country) form.elements.require_exit_country.value = prof.require_exit_country || "";
  if (form.elements.require_exit_city) form.elements.require_exit_city.value = prof.require_exit_city || "";
  if (form.elements.require_exit_asn) form.elements.require_exit_asn.value = prof.require_exit_asn || "";
  if (form.elements.require_exit_ip) form.elements.require_exit_ip.value = prof.require_exit_ip || "";
  if (form.elements.schedule_window) form.elements.schedule_window.value = prof.schedule_window || "";
  if (form.elements.dns_match_exit) form.elements.dns_match_exit.checked = !!prof.dns_match_exit;
  applyDoHEndpointToForm(prof.dns_match_endpoint || "");
  if (form.elements.dns_proxy) form.elements.dns_proxy.checked = !!prof.dns_proxy;
  if (form.elements.dns_proxy_upstream) form.elements.dns_proxy_upstream.value = prof.dns_proxy_upstream || "";
  if (form.elements.mouse_jitter) form.elements.mouse_jitter.checked = !!prof.mouse_jitter;
  if (form.elements.env_auto_from_exit) {
    form.elements.env_auto_from_exit.checked = !!(prof.env && prof.env.auto_from_exit);
  }
  for (const b of prof.chain || []) addHop(b);
  if (!hops.children.length) addHop();
  // Reset to "custom" mode on edit so every saved field is visible
  // and editable; switching presets afterward is opt-in.
  setProfileMode("custom", { applyDefaults: false });
  // After programmatic check-state changes, re-sync the
  // data-toggles → data-show-when conditional fields so the
  // require_* inputs reveal/hide to match the lock checkboxes.
  if (window.__veilRefreshConditional) window.__veilRefreshConditional();
}

// ---------- DoH resolver picker ----------

// applyDoHEndpointToForm drives the preset dropdown + custom text
// input from a saved dns_match_endpoint string. If the saved value
// matches one of the preset options, that option is selected and the
// custom input is hidden. Otherwise the dropdown shows "Custom" and
// the URL goes into the visible text input.
function applyDoHEndpointToForm(saved) {
  const sel = document.getElementById("dns_match_preset");
  const custom = document.getElementById("dns_match_custom_label");
  const input = form.elements.dns_match_endpoint;
  if (!sel || !custom || !input) return;
  const presets = Array.from(sel.options).map(o => o.value).filter(v => v !== "custom");
  if (saved === "" || presets.includes(saved)) {
    sel.value = saved || presets[0]; // empty → first preset (Mullvad)
    input.value = "";
    custom.style.display = "none";
  } else {
    sel.value = "custom";
    input.value = saved;
    custom.style.display = "";
  }
}

(function wireDoHPresetPicker() {
  const sel = document.getElementById("dns_match_preset");
  const custom = document.getElementById("dns_match_custom_label");
  const input = form && form.elements && form.elements.dns_match_endpoint;
  if (!sel || !custom || !input) return;
  sel.addEventListener("change", () => {
    if (sel.value === "custom") {
      custom.style.display = "";
      input.focus();
    } else {
      custom.style.display = "none";
      input.value = sel.value; // copy preset URL into the saved field
    }
  });
})();

// ---------- profile mode (Use case preset) ----------

// applyModeDefaults fills in fields that the picked preset implies.
// Skipped when applyDefaults=false (used when LOADING an existing
// profile so the user's saved choices aren't trampled).
function applyModeDefaults(mode) {
  const set = (name, value) => {
    const el = form.elements[name];
    if (!el) return;
    if (el.type === "checkbox") el.checked = !!value;
    else el.value = value;
  };
  switch (mode) {
    case "anonymity":
      set("kill_switch", true);
      set("anti_fingerprint", "strict");
      set("forge_persona", true);
      set("locked_endpoint", true);
      set("lock_country", true);
      set("lock_asn", false);
      set("lock_ip", false);
      set("dns_match_exit", true);
      set("env_auto_from_exit", false); // persona country drives TZ/lang
      set("randomize_chain", false);
      // Tor defaults the rest; clear single-IP fields that won't apply.
      set("require_exit_ip", "");
      set("require_exit_asn", "");
      set("require_exit_city", "");
      set("schedule_window", "");
      break;
    case "identity":
      set("kill_switch", true);
      set("anti_fingerprint", "strict");
      set("locked_endpoint", true);
      // Default: lock country only. User ticks ASN/IP if they have a
      // stable static endpoint.
      set("lock_country", true);
      set("lock_asn", false);
      set("lock_ip", false);
      set("dns_match_exit", true);
      set("env_auto_from_exit", false);
      set("randomize_chain", false);
      break;
    case "pool":
      set("kill_switch", true);
      set("anti_fingerprint", "basic");
      set("forge_persona", true);
      set("locked_endpoint", true);
      // Provider stays the same, IP rotates within ASN.
      set("lock_country", true);
      set("lock_asn", true);
      set("lock_ip", false);
      set("dns_match_exit", false);
      set("env_auto_from_exit", false);
      break;
    case "custom":
    default:
      // No defaults applied — Custom is "I know what I'm doing".
      break;
  }
}

// setProfileMode toggles the form's data-mode (drives CSS visibility)
// and optionally re-applies the preset's default values.
function setProfileMode(mode, opts = {}) {
  const applyDefaults = opts.applyDefaults !== false;
  form.dataset.mode = mode;
  const sel = document.getElementById("profile-mode");
  if (sel && sel.value !== mode) sel.value = mode;
  if (applyDefaults) {
    applyModeDefaults(mode);
    // Defaults flipped the lock_* checkboxes programmatically — sync
    // the data-show-when wrappers to match.
    if (window.__veilRefreshConditional) window.__veilRefreshConditional();
  }
}

(function wireProfileMode() {
  const sel = document.getElementById("profile-mode");
  if (!sel) return;
  sel.addEventListener("change", () => setProfileMode(sel.value));
  // Initial state matches the dropdown's selected option (Custom).
  form.dataset.mode = sel.value;
})();

// Wire data-toggles checkboxes to data-show-when wrappers. A checkbox
// with data-toggles="X" reveals every element with data-show-when="X"
// only while it's ticked. Used so the require_exit_* inputs only
// appear when the user actually opts into that lock dimension.
(function wireConditionalFields() {
  function refresh(box) {
    const key = box.dataset.toggles;
    if (!key) return;
    const on = !!box.checked;
    document.querySelectorAll(`[data-show-when="${key}"]`).forEach(el => {
      if (on) el.setAttribute("data-active", "1");
      else el.removeAttribute("data-active");
    });
  }
  document.querySelectorAll("input[type=checkbox][data-toggles]").forEach(box => {
    box.addEventListener("change", () => refresh(box));
    refresh(box);
  });
  // Re-sync after profile load (resetForm re-checks the boxes
  // programmatically without firing 'change'); call this from
  // loadIntoForm too.
  window.__veilRefreshConditional = () => {
    document.querySelectorAll("input[type=checkbox][data-toggles]").forEach(refresh);
  };
})();

function loadIntoForm(prof) { resetForm(prof); }

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(form);
  const args = (fd.get("args") || "").split("\n").map(s => s.trim()).filter(Boolean);
  const dns = (fd.get("dns") || "").split(",").map(s => s.trim()).filter(Boolean);
  const prof = {
    name: fd.get("name"),
    description: fd.get("description"),
    chain: readChain(),
    app: {
      preset: fd.get("preset") || "",
      binary: fd.get("binary") || "",
      args: args,
    },
    data_dir: fd.get("data_dir") || "",
    dns,
    kill_switch: !!fd.get("kill_switch"),
    // Tri-state: "" (off) | "basic" | "strict". Empty string preserved
    // so the YAML round-trips cleanly; backend's UnmarshalYAML maps it
    // to AFOff.
    anti_fingerprint: fd.get("anti_fingerprint") || "",
    randomize_chain: !!fd.get("randomize_chain"),
    persona: fd.get("persona") || "",
    forge_persona: !!fd.get("forge_persona"),
    forge_form_factor: fd.get("forge_form_factor") || "",
    forge_os: fd.get("forge_os") || "",
    forge_browser: fd.get("forge_browser") || "",
    forge_country: fd.get("forge_country") || "",
    forge_seed: String(forgeRerollCounter),
    locked_endpoint: !!fd.get("locked_endpoint"),
    lock_country: !!fd.get("lock_country"),
    lock_asn: !!fd.get("lock_asn"),
    lock_ip: !!fd.get("lock_ip"),
    require_exit_country: fd.get("require_exit_country") || "",
    require_exit_city: fd.get("require_exit_city") || "",
    require_exit_asn: fd.get("require_exit_asn") || "",
    require_exit_ip: fd.get("require_exit_ip") || "",
    schedule_window: fd.get("schedule_window") || "",
    dns_match_exit: !!fd.get("dns_match_exit"),
    dns_proxy: !!fd.get("dns_proxy"),
    dns_proxy_upstream: fd.get("dns_proxy_upstream") || "",
    dns_match_endpoint: fd.get("dns_match_endpoint") || "",
    mouse_jitter: !!fd.get("mouse_jitter"),
    reroll_every: fd.get("reroll_every") || "",
    tcp_persona: fd.get("tcp_persona") || "",
    cpu_throttle: fd.get("cpu_throttle") || "",
    behavioral_jitter: !!fd.get("behavioral_jitter"),
    env: { auto_from_exit: !!fd.get("env_auto_from_exit") },
  };
  try {
    await W.SaveProfile(prof);
    toast("Saved", "ok");
    show("profiles");
  } catch (e) {
    const err = document.getElementById("form-error");
    err.textContent = String(e);
    err.classList.remove("hidden");
  }
});

// ---------- doctor ----------

async function runDoctor() {
  const ul = document.getElementById("doctor-results");
  ul.innerHTML = `<li class="muted" style="border-left: 3px solid var(--line);">Checking…</li>`;
  try {
    const checks = await W.Doctor() || [];
    ul.innerHTML = "";
    for (const c of checks) {
      const li = document.createElement("li");
      const cls = c.OK ? "ok" : (c.Warning ? "warn" : "bad");
      const ic = c.OK ? "check-circle" : (c.Warning ? "warn" : "x-circle");
      li.className = cls;
      li.innerHTML = `${Icon(ic)}<span>${escapeHtml(c.Name)}</span>${c.Detail ? `<span class="doctor-detail">${escapeHtml(c.Detail)}</span>` : ""}`;
      ul.appendChild(li);
    }
  } catch (e) {
    ul.innerHTML = `<li class="bad">${Icon("x-circle")}<span>Doctor failed: ${escapeHtml(String(e))}</span></li>`;
  }
}
document.getElementById("btn-run-doctor").addEventListener("click", runDoctor);

// ---------- tor circuits ----------

async function refreshTorCircuits() {
  const out = document.getElementById("tor-circuits");
  const sel = document.getElementById("tor-profile-pick");
  const profs = (await W.ListProfiles()) || [];
  const torProfs = profs.filter(p => p.running && (p.chain_kinds || []).includes("tor"));
  const prev = sel.value;
  sel.innerHTML = torProfs.length === 0
    ? "<option value=''>(no running Tor profile)</option>"
    : torProfs.map(p => `<option value="${escapeAttr(p.name)}">${escapeHtml(p.name)}</option>`).join("");
  if (prev && torProfs.some(p => p.name === prev)) sel.value = prev;

  const name = sel.value;
  if (!name) {
    out.innerHTML = `<p class="muted" style="margin-top: 14px;">Launch a profile that includes Tor in its chain to see circuits here.</p>`;
    return;
  }
  out.innerHTML = `<p class="muted" style="margin-top: 14px;">Querying tor control port…</p>`;
  try {
    const data = await W.TorCircuits(name);
    const circs = (data && data.circuits) || [];
    if (circs.length === 0) {
      out.innerHTML = "<p>(no circuits — Tor may not be fully bootstrapped yet)</p>";
      return;
    }
    out.innerHTML = `
      <table class="tor-table">
        <thead><tr>
          <th>ID</th><th>Status</th><th>Path (guard → middle → exit)</th><th>Purpose</th>
        </tr></thead>
        <tbody>
          ${circs.map(c => `
            <tr>
              <td>${escapeHtml(c.id)}</td>
              <td style="color: ${c.status === "BUILT" ? "var(--good)" : "var(--warn)"}">${escapeHtml(c.status)}</td>
              <td>${(c.hops || []).map(h => escapeHtml(h.nickname || h.fingerprint.slice(0,10))).join(" → ")}</td>
              <td class="muted">${escapeHtml(c.purpose || "")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    out.innerHTML = `<p class="error">${escapeHtml(String(e))}</p>`;
  }
}

document.getElementById("btn-tor-refresh").addEventListener("click", refreshTorCircuits);
document.getElementById("tor-profile-pick").addEventListener("change", refreshTorCircuits);
document.getElementById("btn-tor-newcircuit").addEventListener("click", async () => {
  const name = document.getElementById("tor-profile-pick").value;
  if (!name) return;
  try {
    await W.TorNewCircuit(name);
    toast("New Tor circuit signal sent", "ok");
    setTimeout(refreshTorCircuits, 500);
  } catch (e) { toast(String(e), "error"); }
});

// ---------- license install ----------

document.getElementById("btn-license-install").addEventListener("click", async () => {
  const token = document.getElementById("license-input").value.trim();
  const out = document.getElementById("license-result");
  if (!token) {
    out.textContent = "Paste a token first.";
    return;
  }
  try {
    const lic = await W.InstallLicense(token);
    out.innerHTML = lic.valid
      ? `<span style="color: var(--good); display: flex; align-items: center; gap: 6px;">${Icon("check-circle")}<span>Installed: tier=${escapeHtml(lic.tier)}${lic.email ? " · " + escapeHtml(lic.email) : ""}</span></span>`
      : `<span style="color: var(--warn); display: flex; align-items: center; gap: 6px;">${Icon("warn")}<span>Saved but unverified: ${escapeHtml(lic.reason)}</span></span>`;
    renderLicenseAbout(lic);
    document.getElementById("license-input").value = "";
  } catch (e) {
    out.innerHTML = `<span class="error">${escapeHtml(String(e))}</span>`;
  }
});

// ---------- logs ----------

let logsAutoTimer = null;

async function refreshLogs() {
  try {
    const path = await W.LogPath();
    document.getElementById("log-path").textContent = "File: " + path;
    const text = await W.LogTail();
    const pre = document.getElementById("log-pre");
    pre.textContent = text || "(empty)";
    pre.scrollTop = pre.scrollHeight;
  } catch (e) {
    document.getElementById("log-pre").textContent = "logs unavailable: " + e;
  }
}
document.getElementById("btn-logs-refresh").addEventListener("click", refreshLogs);
document.getElementById("logs-auto").addEventListener("change", (ev) => {
  if (ev.target.checked) {
    refreshLogs();
    logsAutoTimer = setInterval(refreshLogs, 2000);
  } else if (logsAutoTimer) {
    clearInterval(logsAutoTimer);
    logsAutoTimer = null;
  }
});

// ---------- license + about page ----------

function renderLicenseAbout(lic) {
  const labelEl = document.getElementById("about-license");
  const detailEl = document.getElementById("about-license-detail");
  const upgradeBtn = document.getElementById("about-upgrade-link");
  const footer = document.getElementById("license-footer");
  if (!labelEl) return;

  const tier = (lic && lic.tier) || "free";
  labelEl.textContent = tier;
  labelEl.style.color = tier === "free" ? "var(--text-2)" : "var(--pro)";

  let detail = "";
  if (tier === "free") {
    detail = "Network isolation · GUI · CLI. Anti-detect requires Pro.";
  } else {
    detail = "All anti-detect, persona, locked-endpoint and behavioral features unlocked.";
    if (lic && lic.email) detail += "  ·  " + lic.email;
    if (lic && !lic.valid && lic.reason) detail += "  ·  unverified: " + lic.reason;
  }
  if (detailEl) detailEl.textContent = detail;

  if (upgradeBtn) {
    if (tier === "free") {
      upgradeBtn.style.display = "inline-flex";
      upgradeBtn.textContent = "Upgrade to Pro";
      upgradeBtn.href = "https://github.com/marcstampfli1/veil#free-vs-pro";
    } else {
      upgradeBtn.style.display = "inline-flex";
      upgradeBtn.textContent = "Manage subscription";
      upgradeBtn.href = "https://github.com/marcstampfli1/veil#manage";
    }
  }

  if (footer) {
    const dot = footer.querySelector(".lic-dot");
    const tierEl = footer.querySelector(".lic-tier");
    const spacer = footer.querySelector(".spacer");
    if (dot) {
      dot.classList.toggle("pro", tier !== "free");
    }
    if (tierEl) tierEl.textContent = tier;
    // Reset any prior unverified marker, then add if needed.
    footer.querySelectorAll(".lic-warn").forEach(n => n.remove());
    if (lic && lic.valid === false) {
      const warn = document.createElement("span");
      warn.className = "lic-warn";
      warn.textContent = "(unverified)";
      footer.appendChild(warn);
    }
  }
}

(async () => {
  try {
    const lic = await W.License();
    renderLicenseAbout(lic);
    if (W.Version) {
      try {
        const v = await W.Version();
        const ve = document.getElementById("about-version");
        if (ve && v) ve.textContent = v;
      } catch {}
    }
  } catch (e) {
    const f = document.getElementById("license-footer");
    if (f) {
      const t = f.querySelector(".lic-tier");
      if (t) t.textContent = "license error";
    }
  }
})();

// ---------- helpers ----------

function humanBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const units = ["KiB","MiB","GiB","TiB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
  return n.toFixed(2) + " " + units[i];
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function escapeAttr(s) { return escapeHtml(s); }

function mockBackend() {
  let store = [];
  return {
    ListProfiles: async () => store.map(p => ({
      name: p.name, description: p.description || "",
      chain: (p.chain || []).map(b => b.kind).join(" -> "),
      chain_kinds: (p.chain || []).map(b => b.kind),
      app: p.app?.binary || "", preset: p.app?.preset || "",
      kill_switch: !!p.kill_switch, running: false, pid: 0,
    })),
    GetProfile: async name => store.find(p => p.name === name),
    SaveProfile: async p => {
      store = store.filter(x => x.name !== p.name).concat([p]);
    },
    DeleteProfile: async name => { store = store.filter(p => p.name !== name); },
    LaunchProfile: async name => ({ pid: 12345 }),
    StrictTierConsent: async name => ({ profile_name: name, tier: "", needs_consent: false, data_dir: "", ca_cert_path: "", ca_fingerprint_hex: "", ca_subject: "", keystore_backed: false, accepted_at_unix: 0, human_scope_summary: "" }),
    AcceptStrictTier: async () => {},
    RevokeStrictTier: async () => {},
    StopProfile: async () => {},
    RerollProfile: async () => {},
    SoftReroll: async () => {},
    HardReroll: async () => {},
    ProfileExternalIP: async () => "203.0.113.42",
    ProfileExternalIPInfo: async () => ({ ip: "203.0.113.42", city: "Mock", country: "ZZ", org: "AS0 Mock" }),
    ProfileStats: async () => ({ iface: "veth", tx_bytes: 0, rx_bytes: 0, tx_packets: 0, rx_packets: 0 }),
    Doctor: async () => [{ Name: "mock", OK: true, Detail: "browser preview" }],
    License: async () => ({ tier: "free", email: "", valid: true, reason: "" }),
    InstallLicense: async (t) => ({ tier: "pro", email: "test@example.com", valid: true, reason: "" }),
    Personas: async () => [],
    SavePersona: async () => {},
    DeletePersona: async () => {},
    Presets: async () => ["firefox","chromium","brave","signal","telegram","shell","curl"],
    AvailableBackends: async () => ["direct","socks5","http","wireguard","openvpn","tor"],
    BulkImportWG: async () => [],
    BulkImportOVPN: async () => [],
    LogTail: async () => "(mock)",
    LogPath: async () => "/tmp/mock-veil.log",
    TorCircuits: async () => ({ circuits: [
      { id: "1", status: "BUILT", hops: [{nickname:"guard1"},{nickname:"mid"},{nickname:"exit-CH"}], purpose: "GENERAL" },
    ]}),
    TorNewCircuit: async () => null,
    TorHopsTrace: async () => ({ hops: [
      { nickname: "guard1", loc: "52.3667,4.9000", country: "NL" },
      { nickname: "mid",    loc: "50.1100,8.6800", country: "DE" },
      { nickname: "exit",   loc: "47.3667,8.5500", country: "CH" },
    ]}),
    ChainTrace: async () => ({
      hops: [
        { nickname: "wireguard #1", loc: "47.3667,8.5500", country: "CH" },
        { nickname: "guard1",       loc: "52.3667,4.9000", country: "NL" },
        { nickname: "mid",          loc: "50.1100,8.6800", country: "DE" },
      ],
      exit: { nickname: "exit", loc: "59.3293,18.0686", country: "SE" },
    }),
  };
}

// Quit button — calls the bound RequestShutdown method which
// tears down sessions + exits the process. Works regardless of
// whether veil-gui was launched directly, via sudo, or via pkexec.
{
  const qBtn = document.getElementById("btn-quit");
  if (qBtn && W.RequestShutdown) {
    qBtn.addEventListener("click", async () => {
      const ok = await confirmModal({
        title: "Quit Veil?",
        body: "All running profiles will be stopped before the process exits.",
        okLabel: "Quit",
        okClass: "danger",
      });
      if (!ok) return;
      try { await W.RequestShutdown(); }
      catch (e) { /* process is exiting; expected */ }
    });
  }
}

// initial render
show("profiles");
