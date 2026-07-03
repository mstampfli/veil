// Inline icon set. SVG paths derived from Lucide (https://lucide.dev,
// ISC). Each value is a path / shape body; the wrapper supplies the
// <svg> attributes so size/color flow from CSS via stroke="currentColor".

(function () {
  const STROKE = 'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  const FILL = 'fill="currentColor" stroke="none"';

  // path data extracted from Lucide icons (MIT/ISC). One per glyph.
  const SHAPES = {
    // navigation / verbs
    plus:        ['stroke', '<path d="M5 12h14M12 5v14"/>'],
    check:       ['stroke', '<path d="M20 6L9 17l-5-5"/>'],
    x:           ['stroke', '<path d="M18 6L6 18M6 6l12 12"/>'],
    refresh:     ['stroke', '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>'],
    play:        ['stroke', '<path d="M5 4l14 8-14 8z"/>'],
    upload:      ['stroke', '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/>'],
    info:        ['stroke', '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h0"/>'],
    edit:        ['stroke', '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>'],
    trash:       ['stroke', '<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'],
    key:         ['stroke', '<circle cx="8" cy="15" r="4"/><path d="M10.85 12.15L19 4M18 5l3 3M15 8l3 3"/>'],

    // status
    'check-circle': ['stroke', '<circle cx="12" cy="12" r="10"/><path d="M9 12l2 2 4-4"/>'],
    warn:           ['stroke', '<path d="M12 2L2 22h20L12 2z"/><path d="M12 9v5M12 18h0"/>'],
    'x-circle':     ['stroke', '<circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>'],
    activity:       ['stroke', '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>'],

    // sidebar nav
    layers:      ['stroke', '<path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>'],
    terminal:    ['stroke', '<path d="M4 17l6-6-6-6"/><path d="M12 19h8"/>'],
    stethoscope: ['stroke', '<path d="M4 4v6a4 4 0 0 0 8 0V4"/><path d="M4 4h2M10 4h2"/><path d="M8 14v3a4 4 0 0 0 4 4 4 4 0 0 0 4-4v-1"/><circle cx="16" cy="11" r="2"/>'],
    circuit:     ['stroke', '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/>'],

    // chain hop kinds
    home:        ['stroke', '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2h-4v-7H10v7H6a2 2 0 0 1-2-2V9z"/>'],
    lock:        ['stroke', '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'],
    network:     ['stroke', '<rect x="9" y="2" width="6" height="6"/><rect x="3" y="16" width="6" height="6"/><rect x="15" y="16" width="6" height="6"/><path d="M12 8v4M6 16v-2h12v2"/>'],
    globe:       ['stroke', '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>'],
    'arrow-right':['stroke', '<path d="M5 12h14M13 5l7 7-7 7"/>'],
    onion:       ['stroke', '<path d="M12 21c-4 0-7-4-7-9 0-3.5 1.7-6.5 4-7.5"/><path d="M12 21c4 0 7-4 7-9 0-3.5-1.7-6.5-4-7.5"/><path d="M12 21V3"/><path d="M9 6.5C10 5 11 4 12 4M15 6.5C14 5 13 4 12 4"/>'],

    // dashboard / map
    'map-pin':   ['stroke', '<path d="M12 2a8 8 0 0 0-8 8c0 5.5 8 13 8 13s8-7.5 8-13a8 8 0 0 0-8-8z"/><circle cx="12" cy="10" r="3"/>'],
    shield:      ['stroke', '<path d="M12 2L4 5v7c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V5l-8-3z"/>'],
    'shield-x':  ['stroke', '<path d="M12 2L4 5v7c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V5l-8-3z"/><path d="M9 10l6 6M15 10l-6 6"/>'],
    'shield-check':['stroke', '<path d="M12 2L4 5v7c0 5 3.5 8.5 8 10 4.5-1.5 8-5 8-10V5l-8-3z"/><path d="M8 12l3 3 6-6"/>'],
    cpu:         ['stroke', '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 15h3M1 9h3M1 15h3"/>'],
    timer:       ['stroke', '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l3 2M9 1h6"/>'],
    chevron:     ['stroke', '<path d="M9 18l6-6-6-6"/>'],
  };

  function makeSVG(name, opts = {}) {
    const s = SHAPES[name];
    if (!s) return '';
    const [mode, body] = s;
    const cls = 'icon ' + (opts.class || '');
    const attrs = mode === 'fill'
      ? `fill="currentColor" stroke="none"`
      : `fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`;
    return `<svg viewBox="0 0 24 24" class="${cls.trim()}" ${attrs}>${body}</svg>`;
  }

  // Process [data-icon="<name>"] elements:
  //   - Empty placeholder element (no text/children) -> replace it with
  //     the icon SVG. Use for inline button icons.
  //   - Element with content (e.g. nav-item buttons) -> prepend the
  //     icon as the first child, leaving the rest of the content
  //     intact. The data-icon attr is consumed so subsequent calls
  //     don't double-inject.
  function hydrateIcons(root) {
    (root || document).querySelectorAll('[data-icon]').forEach(el => {
      const name = el.getAttribute('data-icon');
      if (!name) return;
      const empty = el.children.length === 0 && el.textContent.trim() === '';
      const svg = makeSVG(name, { class: empty ? el.className : 'icon' });
      if (empty) {
        el.outerHTML = svg;
      } else {
        el.removeAttribute('data-icon');
        el.insertAdjacentHTML('afterbegin', svg);
      }
    });
  }

  // Country code → <img> tag pointing at the bundled circle-flag svg.
  // Falls back to a generic globe icon when cc is unknown/missing.
  // The flags ship with the binary under /assets/flags/<cc>.svg .
  function flagImg(cc, opts = {}) {
    const cls = 'flag-img ' + (opts.class || '');
    if (!cc || cc.length !== 2) {
      return makeSVG('globe', { class: cls });
    }
    const file = cc.toLowerCase();
    return `<img class="${cls.trim()}" src="/assets/flags/${file}.svg" alt="${file.toUpperCase()}" loading="lazy" onerror="this.outerHTML='${makeSVG('globe', { class: cls }).replace(/'/g, "\\'")}'" />`;
  }

  window.Veil = window.Veil || {};
  window.Veil.icon = makeSVG;
  window.Veil.hydrateIcons = hydrateIcons;
  window.Veil.flagImg = flagImg;

  document.addEventListener('DOMContentLoaded', () => hydrateIcons());
})();
