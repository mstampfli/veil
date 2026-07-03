// Dashboard view: live IP/geo, traffic graph, hop path, world map.
// Wires to App.ProfileExternalIPInfo / ProfileStats / TorCircuits.
//
// All polling happens via the profile's own network for IP/geo (so no
// telemetry on the host) and via local /sys reads for traffic.

(() => {
  const W = window.go && window.go.gui && window.go.gui.App;

  const Icon = (name, opts) => (window.Veil && window.Veil.icon) ? window.Veil.icon(name, opts) : "";
  const FlagImg = (cc, opts) => (window.Veil && window.Veil.flagImg) ? window.Veil.flagImg(cc, opts) : "";

  // Hop kind → icon name (matches profile-list pills).
  const HOP_ICON = {
    wireguard: "lock", openvpn: "lock",
    socks5: "network", http: "globe",
    tor: "onion", direct: "arrow-right",
  };
  const HOP_LABEL = {
    wireguard: "WireGuard", openvpn: "OpenVPN",
    socks5: "SOCKS5", http: "HTTP",
    tor: "Tor", direct: "Direct",
  };

  // ---- traffic graph ----
  const traffic = {
    canvas: null,
    samples: [], // {t: Date.now(), txBps, rxBps}
    lastTx: 0, lastRx: 0, lastT: 0,
    max: 1024 * 100, // dynamic, min 100KB/s
  };

  function pushTraffic(s) {
    const now = Date.now();
    let txBps = 0, rxBps = 0;
    if (traffic.lastT && now > traffic.lastT) {
      const dt = (now - traffic.lastT) / 1000;
      txBps = Math.max(0, (s.tx_bytes - traffic.lastTx) / dt);
      rxBps = Math.max(0, (s.rx_bytes - traffic.lastRx) / dt);
    }
    traffic.lastTx = s.tx_bytes; traffic.lastRx = s.rx_bytes; traffic.lastT = now;
    traffic.samples.push({ t: now, txBps, rxBps });
    while (traffic.samples.length > 60) traffic.samples.shift();
    drawTraffic();
    const rate = document.getElementById("dash-rate-now");
    if (rate) rate.textContent = `↓ ${humanBps(rxBps)}   ↑ ${humanBps(txBps)}`;
    renderRate(rxBps, txBps);
  }

  function humanBps(n) {
    if (!isFinite(n) || n < 0) return "0 B/s";
    if (n < 1024) return n.toFixed(0) + " B/s";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB/s";
    return (n / 1048576).toFixed(2) + " MiB/s";
  }

  function drawTraffic() {
    const c = traffic.canvas;
    if (!c) return;
    const ctx = c.getContext("2d");
    const W = c.width, H = c.height;
    ctx.fillStyle = getCSS("--ink-1");
    ctx.fillRect(0, 0, W, H);

    // Gridlines
    ctx.strokeStyle = getCSS("--rule");
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 1; i < 4; i++) {
      const y = (H * i) / 4;
      ctx.moveTo(0, y); ctx.lineTo(W, y);
    }
    ctx.stroke();

    if (traffic.samples.length < 2) return;

    // Auto-scale: max of last samples.
    let max = traffic.max;
    for (const s of traffic.samples) {
      if (s.txBps > max) max = s.txBps;
      if (s.rxBps > max) max = s.rxBps;
    }
    traffic.max = Math.max(1024 * 100, max * 1.05);

    const dx = W / 60;
    const drawSeries = (key, color) => {
      ctx.strokeStyle = color;
      ctx.fillStyle = color + "33";
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let i = 0; i < traffic.samples.length; i++) {
        const s = traffic.samples[i];
        const x = i * dx;
        const y = H - (s[key] / traffic.max) * (H - 4);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
      // fill under
      ctx.lineTo((traffic.samples.length - 1) * dx, H);
      ctx.lineTo(0, H);
      ctx.closePath();
      ctx.fill();
    };
    drawSeries("rxBps", getCSS("--teal"));
    drawSeries("txBps", getCSS("--ok"));
  }

  function getCSS(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
  }

  // ---- world map (real Natural-Earth countries, loaded from
  // countries-110m.json which lives in the embedded asset bundle) ----
  //
  // Equirectangular projection in a 720×360 viewBox: lon -180..180 →
  // x 0..720, lat 90..-90 → y 0..360.

  let mapPathsHTML = ""; // memoized after first load
  let mapLoadAttempted = false;

  async function loadCountryPaths() {
    if (mapPathsHTML || mapLoadAttempted) return mapPathsHTML;
    mapLoadAttempted = true;
    // Try 50m (sharper) first, fall back to 110m, then to stylised.
    for (const url of ["/countries-50m.json", "/countries-110m.json"]) {
      try {
        const r = await fetch(url);
        if (!r.ok) continue;
        const topo = await r.json();
        const out = topoToSVGPaths(topo, "countries");
        if (out) { mapPathsHTML = out; return mapPathsHTML; }
      } catch (_) { /* try next */ }
    }
    console.warn("country topojson not bundled — using stylised fallback");
    mapPathsHTML = fallbackContinentsSVG();
    return mapPathsHTML;
  }

  // topoToSVGPaths decodes TopoJSON (the d3 world-atlas format) into a
  // single SVG <g> of country <path> elements. Pure JS, no d3 needed.
  function topoToSVGPaths(topo, objectName) {
    const obj = topo.objects && topo.objects[objectName];
    if (!obj) return "";
    const T = topo.transform || { scale: [1, 1], translate: [0, 0] };
    const dequant = (arc) => {
      let x = 0, y = 0;
      const out = new Array(arc.length);
      for (let i = 0; i < arc.length; i++) {
        x += arc[i][0]; y += arc[i][1];
        out[i] = [x * T.scale[0] + T.translate[0], y * T.scale[1] + T.translate[1]];
      }
      return out;
    };
    const arcs = topo.arcs.map(dequant);
    const arcCoords = (idx) => idx < 0 ? arcs[~idx].slice().reverse() : arcs[idx];
    const ringCoords = (ringArcs) => {
      const out = [];
      for (let i = 0; i < ringArcs.length; i++) {
        const a = arcCoords(ringArcs[i]);
        out.push(...(i === 0 ? a : a.slice(1)));
      }
      return out;
    };
    const ringPath = (ring) => {
      // Equirectangular has no native handling for antimeridian
      // crossings (Russia, Fiji, Antarctica). Two consecutive points
      // can flip from lon=179 to lon=-179 -> x=718 to x=2 -> a line
      // would span the whole map. Detect the jump and break the
      // sub-path with M instead of L. Result: small seam at ±180°
      // but no horizontal-bar artifact across the planet.
      let s = "";
      let prevX = null;
      for (let i = 0; i < ring.length; i++) {
        const [lon, lat] = ring[i];
        const x = ((lon + 180) / 360) * 720;
        const y = ((90 - lat) / 180) * 360;
        const cmd = (i === 0 || (prevX !== null && Math.abs(x - prevX) > 360))
          ? "M" : "L";
        s += cmd + x.toFixed(1) + "," + y.toFixed(1);
        prevX = x;
      }
      return s + "Z";
    };
    let html = "";
    for (const g of obj.geometries) {
      let d = "";
      if (g.type === "Polygon") {
        for (const r of g.arcs) d += ringPath(ringCoords(r));
      } else if (g.type === "MultiPolygon") {
        for (const poly of g.arcs) for (const r of poly) d += ringPath(ringCoords(r));
      }
      if (d) html += `<path d="${d}"/>`;
    }
    return html;
  }

  function fallbackContinentsSVG() {
    return `
      <path d="M70,55 L160,40 L240,55 L260,90 L240,140 L210,160 L170,165 L140,185 L120,180 L95,150 L80,120 Z"/>
      <path d="M250,30 L290,30 L300,55 L280,75 L250,70 Z"/>
      <path d="M210,180 L255,180 L265,225 L250,290 L230,310 L210,290 L195,240 L200,210 Z"/>
      <path d="M335,55 L420,50 L440,80 L425,100 L380,110 L355,100 L340,80 Z"/>
      <path d="M345,125 L425,115 L450,150 L455,210 L425,260 L400,275 L370,260 L355,210 L340,170 Z"/>
      <path d="M430,100 L490,95 L505,130 L470,150 L440,140 Z"/>
      <path d="M455,55 L630,50 L645,90 L630,130 L580,150 L540,140 L505,135 L490,100 L470,75 Z"/>
      <path d="M510,140 L545,135 L555,180 L530,195 L510,170 Z"/>
      <path d="M560,160 L620,170 L640,205 L600,215 L570,200 Z"/>
      <path d="M600,235 L675,235 L685,275 L660,290 L615,285 L595,265 Z"/>
      <path d="M40,335 L680,335 L680,355 L40,355 Z"/>
    `;
  }

  async function buildMapSVG() {
    const lands = await loadCountryPaths();
    // Graticule: lat/lon every 30°. Equirectangular -> straight lines
    // at multiples of 60px (lon) and 30px (lat) within 720x360 viewBox.
    const meridians = [60, 120, 180, 240, 300, 360, 420, 480, 540, 600, 660]
      .map(x => `<line x1="${x}" y1="0" x2="${x}" y2="360"/>`).join("");
    const parallels = [30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330]
      .map(y => `<line x1="0" y1="${y}" x2="720" y2="${y}"/>`).join("");
    return `
<svg viewBox="0 0 720 360" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">
  <defs>
    <radialGradient id="ocean" cx="0.5" cy="0.5" r="0.7">
      <stop offset="0" stop-color="#0a0e14"/>
      <stop offset="1" stop-color="#070a0e"/>
    </radialGradient>
    <linearGradient id="landFade" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#1a212d"/>
      <stop offset="1" stop-color="#141a23"/>
    </linearGradient>
  </defs>
  <rect x="-1000" y="-1000" width="3000" height="3000" fill="url(#ocean)"/>
  <g class="map-graticule">${meridians}${parallels}</g>
  <g class="map-land" fill="url(#landFade)">${lands}</g>
  <g id="map-trace-group"></g>
  <g id="map-marker-group"></g>
</svg>`;
  }

  // ---- map zoom + pan ----
  const MAP_W = 720, MAP_H = 360;
  const MIN_W = 18; // most zoomed-in: 720/18 = 40x. Generous so users
                    // can drill into a single city when needed.
  const mapView = { x: 0, y: 0, w: MAP_W, h: MAP_H };
  let boundSVG = null; // current bound SVG element

  function applyMapView(svg) {
    if (mapView.w > MAP_W) mapView.w = MAP_W;
    if (mapView.w < MIN_W) mapView.w = MIN_W;
    mapView.h = mapView.w * (MAP_H / MAP_W);
    if (mapView.x < 0) mapView.x = 0;
    if (mapView.y < 0) mapView.y = 0;
    if (mapView.x + mapView.w > MAP_W) mapView.x = MAP_W - mapView.w;
    if (mapView.y + mapView.h > MAP_H) mapView.y = MAP_H - mapView.h;
    svg.setAttribute("viewBox",
      `${mapView.x} ${mapView.y} ${mapView.w} ${mapView.h}`);
    // Markers and labels need to shrink as we zoom in so they stay
    // visually proportional rather than ballooning to country-sized.
    redrawMapOverlay();
  }

  function resetMapView(svg) {
    mapView.x = 0; mapView.y = 0; mapView.w = MAP_W; mapView.h = MAP_H;
    applyMapView(svg);
  }

  function bindMapInteraction(svg) {
    // If the SVG element changed (re-render), rebind listeners.
    if (boundSVG === svg) return;
    boundSVG = svg;

    // Wheel: zoom around cursor — but no-op at the zoom limits so the
    // view doesn't drift toward the cursor when you can't actually
    // zoom further.
    svg.addEventListener("wheel", (e) => {
      e.preventDefault();
      const factor = e.deltaY > 0 ? 1.2 : 1 / 1.2;
      let newW = mapView.w * factor;
      if (newW > MAP_W) newW = MAP_W;
      if (newW < MIN_W) newW = MIN_W;
      if (Math.abs(newW - mapView.w) < 0.01) return; // already at limit
      const rect = svg.getBoundingClientRect();
      const fx = (e.clientX - rect.left) / rect.width;
      const fy = (e.clientY - rect.top)  / rect.height;
      const cx = mapView.x + fx * mapView.w;
      const cy = mapView.y + fy * mapView.h;
      mapView.w = newW;
      mapView.h = mapView.w * (MAP_H / MAP_W);
      mapView.x = cx - fx * mapView.w;
      mapView.y = cy - fy * mapView.h;
      applyMapView(svg);
    }, { passive: false });

    // Pan via Pointer Events (works for mouse + trackpad + touch on
    // WebKit2GTK). Use pointer capture so a fast drag doesn't lose
    // pointermove when the cursor leaves the SVG.
    let drag = null;
    svg.addEventListener("pointerdown", (e) => {
      // Don't start a drag if the click was on the floating controls
      // (they live above the SVG with z-index but bubbling can still
      // hit svg in some setups).
      if (e.target.closest && e.target.closest(".map-controls")) return;
      // Only left-button.
      if (e.button !== undefined && e.button !== 0) return;
      drag = { px: e.clientX, py: e.clientY, vx: mapView.x, vy: mapView.y, id: e.pointerId };
      svg.classList.add("dragging");
      svg.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    svg.addEventListener("pointermove", (e) => {
      if (!drag || drag.id !== e.pointerId) return;
      const rect = svg.getBoundingClientRect();
      const dx = (e.clientX - drag.px) / rect.width  * mapView.w;
      const dy = (e.clientY - drag.py) / rect.height * mapView.h;
      mapView.x = drag.vx - dx;
      mapView.y = drag.vy - dy;
      applyMapView(svg);
    });
    const endDrag = (e) => {
      if (drag && drag.id === e.pointerId) {
        try { svg.releasePointerCapture(e.pointerId); } catch (_) {}
        drag = null;
        svg.classList.remove("dragging");
      }
    };
    svg.addEventListener("pointerup", endDrag);
    svg.addEventListener("pointercancel", endDrag);
  }

  function lonLatToXY(lon, lat) {
    const x = ((lon + 180) / 360) * 720;
    const y = ((90 - lat) / 180) * 360;
    return { x, y };
  }

  // currentMapPoints is the list of {x, y, label, isExit} for the active
  // session's trace. Cached so applyMapView (zoom/pan) can re-render
  // markers at the correct screen-relative size.
  let currentMapPoints = [];

  // placeMap stores the latest trace and triggers a render.
  async function placeMap(hops, exitLoc) {
    const wrap = document.getElementById("dash-map-wrap");
    if (!wrap) return;
    if (!wrap.firstElementChild) {
      wrap.innerHTML = await buildMapSVG();
      ensureMapControls(wrap);
    }
    const svg = wrap.querySelector("svg");
    bindMapInteraction(svg);

    const points = [];
    for (const h of (hops || [])) {
      const p = parseLoc(h.loc);
      if (p) points.push({ ...p, label: h.label || "" });
    }
    const exit = parseLoc(exitLoc);
    if (exit) points.push({ ...exit, label: "exit", isExit: true });

    currentMapPoints = points;
    redrawMapOverlay();
  }

  // redrawMapOverlay renders the trace polyline + per-hop markers + labels.
  // Marker radii and label sizes scale with the current zoom level so
  // dots stay visually small when zoomed in (otherwise a 4-unit circle
  // covers a continent at 12× zoom).
  function redrawMapOverlay() {
    if (!boundSVG) return;
    const traceG = boundSVG.querySelector("#map-trace-group");
    const markG  = boundSVG.querySelector("#map-marker-group");
    if (!traceG || !markG) return;

    const points = currentMapPoints;
    if (!points || points.length === 0) {
      traceG.innerHTML = "";
      markG.innerHTML  = "";
      return;
    }

    // zoom = 1.0 at default, smaller as we zoom in. Multiply unit
    // dimensions by zoom to keep them at constant screen size.
    const zoom = mapView.w / MAP_W;
    const r       = 3.5 * zoom;
    const exitR   = 5   * zoom;
    const fontSz  = 8   * zoom;
    const labelDX = 6   * zoom;
    const labelDY = 4   * zoom;

    // Trace polyline. Stroke width is non-scaling (CSS), so it stays a
    // constant screen-pixel width regardless of zoom.
    if (points.length >= 2) {
      let d = `M${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
      for (let i = 1; i < points.length; i++) {
        const a = points[i - 1], b = points[i];
        const mx = (a.x + b.x) / 2;
        const my = (a.y + b.y) / 2 - Math.abs(b.x - a.x) * 0.15;
        d += ` Q${mx.toFixed(1)},${my.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
      }
      traceG.innerHTML = `<path class="map-trace" d="${d}"/>`;
    } else {
      traceG.innerHTML = "";
    }

    // Pair each marker with its label inside a <g class="map-marker">.
    // Hover state on the group fades the label in (CSS-driven). A
    // larger transparent circle inside the group expands the hit
    // zone so tiny pins are still easy to target — especially at
    // wide-zoom (markers shrink to a few CSS pixels).
    let html = "";
    for (const p of points) {
      const cls = p.isExit ? "map-hop exit" : "map-hop";
      const radius = (p.isExit ? exitR : r).toFixed(2);
      const hitR = (Math.max(r, exitR) * 3.5).toFixed(2);
      const cx = p.x.toFixed(1);
      const cy = p.y.toFixed(1);
      const lx = (p.x + labelDX).toFixed(1);
      const ly = (p.y - labelDY).toFixed(1);
      const groupCls = "map-marker" + (p.isExit ? " is-exit" : "");
      const pulse = p.isExit
        ? `<circle class="map-marker-pulse" cx="${cx}" cy="${cy}" r="${radius}"/>`
        : "";
      const label = p.label
        ? `<text class="map-hop-label" x="${lx}" y="${ly}" font-size="${fontSz.toFixed(2)}">${escapeHtml(p.label)}</text>`
        : "";
      html += `<g class="${groupCls}">${pulse}<circle class="${cls}" cx="${cx}" cy="${cy}" r="${radius}"/><circle class="map-hover-target" cx="${cx}" cy="${cy}" r="${hitR}"/>${label}</g>`;
    }
    markG.innerHTML = html;
  }

  function parseLoc(loc) {
    if (!loc || typeof loc !== "string") return null;
    const [lat, lon] = loc.split(",").map(Number);
    if (!isFinite(lat) || !isFinite(lon)) return null;
    return lonLatToXY(lon, lat);
  }

  function ensureMapControls(wrap) {
    if (wrap.querySelector(".map-controls")) return;
    const ctrls = document.createElement("div");
    ctrls.className = "map-controls";
    ctrls.innerHTML = `
      <button title="Zoom in" data-act="in">+</button>
      <button title="Zoom out" data-act="out">−</button>
      <button title="Reset" data-act="reset">⟳</button>
    `;
    wrap.appendChild(ctrls);
    const svg = wrap.querySelector("svg");
    ctrls.addEventListener("click", (e) => {
      const act = e.target.dataset && e.target.dataset.act;
      if (!act) return;
      if (act === "reset") { resetMapView(svg); return; }
      const factor = act === "in" ? 1 / 1.4 : 1.4;
      const cx = mapView.x + mapView.w / 2;
      const cy = mapView.y + mapView.h / 2;
      mapView.w = mapView.w * factor;
      mapView.h = mapView.w * (MAP_H / MAP_W);
      mapView.x = cx - mapView.w / 2;
      mapView.y = cy - mapView.h / 2;
      applyMapView(svg);
    });
  }

  // ---- path ----
  // Shapes a hop entry: { glyph: html-string, label: string, isExit?: bool }
  function renderPath(profileChainKinds, lastInfo, torData) {
    const el = document.getElementById("dash-path");
    if (!el) return;
    const hops = [];
    hops.push({ glyph: Icon("home"), label: "Your ISP" });
    for (const k of profileChainKinds || []) {
      switch (k) {
        case "wireguard":
        case "openvpn":
          hops.push({ glyph: Icon("lock"), label: HOP_LABEL[k] || k });
          break;
        case "socks5":
          hops.push({ glyph: Icon("network"), label: "SOCKS5" });
          break;
        case "http":
          hops.push({ glyph: Icon("globe"), label: "HTTP proxy" });
          break;
        case "tor":
          if (torData && torData.circuits && torData.circuits.length) {
            const built =
              torData.circuits.find(c => c.status === "BUILT" && c.purpose === "GENERAL") ||
              torData.circuits.find(c => c.status === "BUILT");
            if (built && built.hops && built.hops.length >= 2) {
              hops.push({ glyph: Icon("onion"), label: "Tor: " + built.hops.map(h => h.nickname || h.fingerprint.slice(0, 6)).join(" → ") });
            } else {
              hops.push({ glyph: Icon("onion"), label: "Tor (building circuit…)" });
            }
          } else {
            hops.push({ glyph: Icon("onion"), label: "Tor" });
          }
          break;
        case "direct":
          hops.push({ glyph: Icon("arrow-right"), label: "direct (namespaced)" });
          break;
      }
    }
    if (lastInfo && lastInfo.country) {
      hops.push({
        glyph: FlagImg(lastInfo.country),
        label: (lastInfo.city ? lastInfo.city + ", " : "") + lastInfo.country,
        isExit: true,
      });
    } else {
      hops.push({ glyph: Icon("map-pin"), label: "exit", isExit: true });
    }
    el.innerHTML = hops.map((h, i) => {
      const arrow = i ? `<span class="dash-arrow">→</span>` : "";
      const cls = "dash-hop" + (h.isExit ? " exit" : "");
      return arrow + `<span class="${cls}">${h.glyph}<span>${escapeHtml(h.label)}</span></span>`;
    }).join("");
  }

  function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, c =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ---- main loop ----
  let dashTimer = null;
  let ipTimer = null;
  let torTimer = null;
  let hopTimer = null;
  let activeProfile = null;
  let profileMeta = null;
  let lastInfo = null;
  let lastTor = null;
  let lastHops = null; // TorHopsTrace result with geo

  async function renderAll() {
    if (!activeProfile || !profileMeta) return;
    renderStatus(profileMeta);
    renderIP(lastInfo);
    renderPath(profileMeta.chain_kinds, lastInfo, lastTor);
    // Markers come from ChainTrace.hops; the exit comes from
    // ChainTrace.exit (which echoes the cached IP info).
    const hopMarkers = ((lastHops && lastHops.hops) || []).map(h => ({
      label: (h.nickname || (h.fingerprint || "").slice(0, 6)) + (h.country ? " " + h.country : ""),
      loc: h.loc,
    }));
    const exitLoc = (lastHops && lastHops.exit && lastHops.exit.loc)
      || (lastInfo && lastInfo.loc)
      || null;
    placeMap(hopMarkers, exitLoc);
  }

  function renderIP(info) {
    // Clear when info is null/undefined (profile switched, IP not
    // yet known). Otherwise the previous profile's IP, location,
    // ASN etc. linger and confuse the user.
    const flagImg = document.getElementById("stat-flag-img");
    const ipEl = document.getElementById("stat-exit-ip");
    const locEl = document.getElementById("stat-exit-loc");
    if (!info) {
      if (flagImg) flagImg.classList.add("hidden");
      if (ipEl) ipEl.textContent = "—";
      if (locEl) locEl.textContent = "—";
      const asnEl = document.getElementById("stat-asn-val");
      const orgEl = document.getElementById("stat-asn-org");
      if (asnEl) asnEl.textContent = "—";
      if (orgEl) orgEl.textContent = "—";
      return;
    }

    if (flagImg) {
      const cc = (info.country || "").toLowerCase();
      if (cc && cc.length === 2) {
        flagImg.src = "/assets/flags/" + cc + ".svg";
        flagImg.alt = cc.toUpperCase();
        flagImg.classList.remove("hidden");
      } else {
        flagImg.classList.add("hidden");
      }
    }
    if (ipEl) ipEl.textContent = info.ip || "—";
    if (locEl) {
      const geoLine = [info.city, info.region, info.country].filter(Boolean).join(", ");
      locEl.textContent = geoLine || "—";
    }

    // ASN card — split "AS9009 Bla bla" into ASN + org.
    const asnEl = document.getElementById("stat-asn-val");
    const asnSub = document.getElementById("stat-asn-sub");
    const org = info.org || "";
    let asn = "—";
    let orgRest = "";
    const m = org.match(/^(AS\d+)\s+(.+)$/);
    if (m) { asn = m[1]; orgRest = m[2]; }
    else if (org) { orgRest = org; }
    if (asnEl) asnEl.textContent = asn;
    if (asnSub) asnSub.textContent = orgRest || "—";
  }

  function renderStatus(meta) {
    const valEl = document.getElementById("stat-status-val");
    const subEl = document.getElementById("stat-status-sub");
    const card  = document.getElementById("stat-status");
    if (!valEl || !meta) return;
    let label = "stopped", sub = "—", mod = "";
    if (meta.running) {
      switch (meta.health) {
        case "degraded": label = "degraded"; mod = "is-warn"; break;
        case "failed":   label = "failed";   mod = "is-bad";  break;
        default:         label = "running";  mod = "is-good"; break;
      }
      const ks = meta.kill_switch === false ? "kill-switch off" : "kill-switch on";
      sub = ks + (meta.preset ? "  ·  " + meta.preset : "");
    } else {
      sub = meta.preset || "—";
    }
    valEl.textContent = label;
    if (subEl) subEl.textContent = sub;
    if (card) {
      card.classList.remove("is-good", "is-warn", "is-bad");
      if (mod) card.classList.add(mod);
    }
  }

  function renderRate(rxBps, txBps) {
    const valEl = document.getElementById("stat-rate-val");
    const subEl = document.getElementById("stat-rate-sub");
    if (valEl) {
      const total = (rxBps || 0) + (txBps || 0);
      valEl.textContent = humanBps(total);
    }
    if (subEl) {
      subEl.textContent = `↓ ${humanBps(rxBps || 0)}   ↑ ${humanBps(txBps || 0)}`;
    }
  }

  // Capture activeProfile at call entry. If the user switches profiles
  // mid-flight, the in-flight response would otherwise overwrite state
  // for the new profile (causing "same IP shown for multiple profiles").
  async function pollStats() {
    const askedFor = activeProfile;
    if (!askedFor) return;
    try {
      const s = await W.ProfileStats(askedFor);
      if (askedFor !== activeProfile) return;
      pushTraffic(s);
    } catch (_) { /* profile likely stopped */ }
  }
  async function pollIP() {
    const askedFor = activeProfile;
    if (!askedFor) return;
    try {
      const info = await W.ProfileExternalIPInfo(askedFor);
      if (askedFor !== activeProfile) return; // stale response
      lastInfo = info;
      renderAll();
    } catch (_) { /* may be still bootstrapping */ }
  }
  async function pollTor() {
    const askedFor = activeProfile;
    if (!askedFor || !profileMeta) return;
    if (!(profileMeta.chain_kinds || []).includes("tor")) return;
    try {
      const tor = await W.TorCircuits(askedFor);
      if (askedFor !== activeProfile) return;
      lastTor = tor;
      renderPath(profileMeta.chain_kinds, lastInfo, lastTor);
    } catch (_) { /* control port not ready */ }
  }
  async function pollHops() {
    const askedFor = activeProfile;
    if (!askedFor || !profileMeta) return;
    try {
      const hops = await W.ChainTrace(askedFor);
      if (askedFor !== activeProfile) return;
      lastHops = hops;
      renderAll();
    } catch (_) { /* still bootstrapping or rate-limited */ }
  }

  function stopDashboardTimers() {
    if (dashTimer) clearInterval(dashTimer);
    if (ipTimer) clearInterval(ipTimer);
    if (torTimer) clearInterval(torTimer);
    if (hopTimer) clearInterval(hopTimer);
    dashTimer = ipTimer = torTimer = hopTimer = null;
    traffic.samples = [];
    traffic.lastTx = traffic.lastRx = traffic.lastT = 0;
    lastHops = null;
  }

  async function setActiveProfile(name) {
    name = name || null;
    // Same profile → don't tear down. Just refresh metadata so the
    // traffic line graph persists across picker rebuilds and IP changes.
    if (activeProfile === name && profileMeta) {
      const profs = (await W.ListProfiles()) || [];
      profileMeta = profs.find(p => p.name === activeProfile) || profileMeta;
      renderStatus(profileMeta);
      return;
    }
    stopDashboardTimers();
    activeProfile = name;
    profileMeta = null;
    lastInfo = lastTor = null;
    // Reset all dashboard cards to their empty state so we don't
    // briefly show the previous profile's IP / ASN / location while
    // the new probe is in flight.
    renderIP(null);
    document.getElementById("dash-grid").classList.toggle("hidden", !activeProfile);
    document.getElementById("dash-empty").classList.toggle("hidden", !!activeProfile);
    if (!activeProfile) return;
    const profs = (await W.ListProfiles()) || [];
    profileMeta = profs.find(p => p.name === activeProfile) || null;
    if (!profileMeta) return;
    renderStatus(profileMeta);
    renderPath(profileMeta.chain_kinds, null, null);
    placeMap([], null);
    pollIP();
    pollTor();
    pollHops();
    dashTimer = setInterval(pollStats, 1000);
    ipTimer  = setInterval(pollIP,    30000);
    torTimer = setInterval(pollTor,   10000);
    hopTimer = setInterval(pollHops,  60000); // hop geo lookups are expensive
  }

  // When the user clicks the IP button on a profile row, we get a
  // veil:profile-ip-updated event. If that profile is the active one
  // on the dashboard, refresh the IP card immediately rather than
  // waiting for the next 30s poll cycle.
  window.addEventListener("veil:profile-ip-updated", (e) => {
    const detail = (e && e.detail) || {};
    if (!activeProfile || detail.profile !== activeProfile) return;
    pollIP();
    pollHops();
  });

  async function refreshDashboardPicker() {
    const sel = document.getElementById("dash-profile-pick");
    const profs = (await W.ListProfiles()) || [];
    const running = profs.filter(p => p.running);
    const prev = sel.value;
    sel.innerHTML = running.length === 0
      ? `<option value="">(no running profile)</option>`
      : running.map(p => `<option value="${p.name}">${p.name}</option>`).join("");
    if (prev && running.some(p => p.name === prev)) sel.value = prev;
    setActiveProfile(sel.value || null);
  }

  document.addEventListener("DOMContentLoaded", () => {
    traffic.canvas = document.getElementById("dash-traffic");
    drawTraffic();

    document.getElementById("dash-profile-pick").addEventListener("change", () => {
      setActiveProfile(document.getElementById("dash-profile-pick").value);
    });

    // Manual "Refresh" button — re-poll all the dashboard sources
    // immediately, no waiting for the 30s timer. Same backend calls
    // the timed pollers use.
    const refreshBtn = document.getElementById("btn-dash-refresh");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", async () => {
        if (!activeProfile) return;
        await Promise.allSettled([pollStats(), pollIP(), pollTor(), pollHops()]);
      });
    }

    // "Probe" — explicit user-triggered call that drives the running
    // browser via CDP to fetch full geo from ipinfo. Useful when the
    // local-first probe only returned an IP (no GeoLite2 country) and
    // you want richer data. Surfaces the result as a toast since the
    // dashboard's stat cards already update from pollIP afterward.
    const probeBtn = document.getElementById("btn-dash-probe");
    if (probeBtn && W.ProfileExternalIPInfo) {
      probeBtn.addEventListener("click", async () => {
        if (!activeProfile) return;
        probeBtn.disabled = true;
        try {
          const info = await W.ProfileExternalIPInfo(activeProfile);
          lastInfo = info;
          renderAll();
          window.toast && window.toast(
            "Exit: " + (info.ip || "?") + " — " +
            [info.city, info.country, info.org].filter(Boolean).join(" · "),
            "ok"
          );
        } catch (e) {
          window.toast && window.toast(String(e), "error");
        } finally {
          probeBtn.disabled = false;
        }
      });
    }
  });

  // Hook into the existing show() router.
  const origShow = window.show;
  window.show = function(viewName, opts) {
    const out = origShow ? origShow(viewName, opts) : null;
    if (viewName === "dashboard") {
      refreshDashboardPicker();
    } else {
      stopDashboardTimers();
    }
    return out;
  };
})();
