// Veil persona — page-context fingerprint overrides.
//
// Runs at document_start in the page's MAIN world (Manifest V3 with
// world:"MAIN" gives us the real page JS environment, not an isolated
// content-script context, so Object.defineProperty actually overrides
// what page scripts see).
//
// Reads persona JSON Veil dropped at chrome.runtime.getURL("persona.json")
// before page scripts execute. Falls back to generic-Chrome defaults
// when persona.json is missing (graceful degradation: no persona =
// no override = browser defaults).
//
// Override surfaces (matched against veil-browser's fork patches):
//   navigator.userAgent / platform / oscpu / appVersion / vendor
//   navigator.hardwareConcurrency / deviceMemory / maxTouchPoints
//   navigator.userAgentData (Chromium Client Hints)
//   navigator.languages
//   screen.width / height / availWidth / availHeight / colorDepth
//   window.devicePixelRatio
//   WebGLRenderingContext.getParameter (UNMASKED_VENDOR/RENDERER)
//   AudioContext.sampleRate (matched to persona's expected device)
//   Intl.DateTimeFormat (timezone)
//   Date.prototype.getTimezoneOffset
//   Battery API (force "always plugged in, 100%")
//
// Detection-resistance notes:
//   - All overrides use Object.defineProperty with same descriptor
//     shape as native (configurable:true, enumerable:true, get:fn).
//   - toString of override functions is wrapped with the native
//     "[native code]" marker.
//   - Order: persona props are written before any page script can
//     check them (document_start in MAIN world is pre-page-script).
//
// This is best-effort browser-agnostic personification. For 100%
// indistinguishable-from-real-device fidelity at the C++ level
// (including canvas pixel output specific to the persona's GPU),
// veil-browser fork is the answer. This extension covers ~95% of
// the surfaces sites actually fingerprint.

(() => {
  // Persona data is parked on window.__veil_persona_data by the
  // sibling persona-data.js content script (which runs first per
  // manifest content_scripts.js order). MAIN-world content scripts
  // have NO access to chrome.runtime / browser.runtime, so the
  // earlier XHR-via-getURL approach silently failed and every
  // override no-op'd while the real GPU/screen/etc. leaked.
  const persona = window.__veil_persona_data;
  if (!persona) {
    try { console.warn("[veil] __veil_persona_data missing — overrides not applied"); } catch (_) {}
    return;
  }

  // One-time startup marker so we can verify the content script
  // actually ran. Site can check window.__veil_persona_active to
  // confirm overrides are in place. console.debug also lets the
  // user see "extension is alive" in DevTools without spamming.
  try {
    Object.defineProperty(window, "__veil_persona_active", {
      value: { name: persona.name || "", platform: persona.platform || "", at: Date.now() },
      configurable: false, writable: false, enumerable: false,
    });
    console.debug("[veil] persona overrides applied:", persona.name, persona.platform);
  } catch (_) {}

  // ---------- helper: native-looking getter ----------
  const NATIVE_TOSTRING = "function get() { [native code] }";
  function nativeGet(value) {
    const fn = function () { return value; };
    try {
      Object.defineProperty(fn, "toString", {
        value: function toString() { return NATIVE_TOSTRING; },
        configurable: true, writable: false,
      });
    } catch (_) {}
    return fn;
  }
  function defineGetter(obj, prop, value) {
    try {
      Object.defineProperty(obj, prop, {
        get: nativeGet(value),
        configurable: true, enumerable: true,
      });
    } catch (_) { /* property may be non-configurable on some platforms */ }
  }

  // ---------- navigator.* ----------
  const nav = navigator;
  if (persona.user_agent) defineGetter(nav, "userAgent", persona.user_agent);
  if (persona.platform) defineGetter(nav, "platform", persona.platform);
  if (persona.app_version) defineGetter(nav, "appVersion", persona.app_version);
  if (persona.oscpu) {
    try { defineGetter(nav, "oscpu", persona.oscpu); } catch (_) {}
  }
  if (persona.vendor !== undefined) defineGetter(nav, "vendor", persona.vendor);
  if (persona.vendor_sub !== undefined) defineGetter(nav, "vendorSub", persona.vendor_sub);
  if (persona.product_sub !== undefined) defineGetter(nav, "productSub", persona.product_sub);

  if (typeof persona.hardware_concurrency === "number")
    defineGetter(nav, "hardwareConcurrency", persona.hardware_concurrency);
  if (typeof persona.device_memory === "number")
    defineGetter(nav, "deviceMemory", persona.device_memory);
  if (typeof persona.max_touch_points === "number")
    defineGetter(nav, "maxTouchPoints", persona.max_touch_points);

  if (persona.accept_language) {
    const langs = persona.accept_language.split(",").map(s => s.trim().split(";")[0]);
    defineGetter(nav, "languages", Object.freeze(langs));
    if (langs[0]) defineGetter(nav, "language", langs[0]);
  }

  // ---------- navigator.userAgentData (Client Hints) ----------
  if (persona.client_hints && nav.userAgentData) {
    const ch = persona.client_hints;
    const brands = (ch.full_version_list || []).map(b => ({ brand: b.brand, version: b.version.split(".")[0] }));
    const fullList = (ch.full_version_list || []).map(b => ({ brand: b.brand, version: b.version }));
    try {
      const fakeUAD = {
        brands,
        mobile: !!ch.mobile,
        platform: ch.platform || "",
        getHighEntropyValues: function (hints) {
          const out = {
            brands,
            mobile: !!ch.mobile,
            platform: ch.platform || "",
            architecture: ch.architecture || "",
            bitness: ch.bitness || "",
            model: ch.model || "",
            platformVersion: ch.platform_version || "",
            uaFullVersion: (fullList[0] && fullList[0].version) || "",
            wow64: !!ch.wow64,
            fullVersionList: fullList,
          };
          return Promise.resolve(out);
        },
        toJSON: function () {
          return { brands, mobile: !!ch.mobile, platform: ch.platform || "" };
        },
      };
      Object.defineProperty(nav, "userAgentData", {
        get: nativeGet(fakeUAD), configurable: true, enumerable: true,
      });
    } catch (_) {}
  }

  // ---------- screen.* ----------
  if (typeof persona.screen_width === "number") {
    defineGetter(screen, "width", persona.screen_width);
    defineGetter(screen, "availWidth", persona.screen_width);
  }
  if (typeof persona.screen_height === "number") {
    defineGetter(screen, "height", persona.screen_height);
    // availHeight typically less than height by ~40-80px (dock/menubar).
    defineGetter(screen, "availHeight", Math.max(0, persona.screen_height - 40));
  }
  if (typeof persona.color_depth === "number") {
    defineGetter(screen, "colorDepth", persona.color_depth);
    defineGetter(screen, "pixelDepth", persona.color_depth);
  }
  if (typeof persona.device_pixel_ratio === "number") {
    try {
      Object.defineProperty(window, "devicePixelRatio", {
        get: nativeGet(persona.device_pixel_ratio),
        configurable: true,
      });
    } catch (_) {}
  }

  // ---------- WebGL UNMASKED_VENDOR / UNMASKED_RENDERER ----------
  // The most-fingerprinted GPU surface. Override getParameter on
  // both WebGL1 and WebGL2 so the persona's claimed GPU strings
  // come back regardless of real hardware.
  if (persona.webgl_unmasked_vendor || persona.webgl_unmasked_renderer || persona.webgl_vendor || persona.webgl_renderer) {
    const VENDOR = 0x1F00;
    const RENDERER = 0x1F01;
    const VERSION = 0x1F02;
    const SHADING_LANGUAGE_VERSION = 0x8B8C;
    const UNMASKED_VENDOR_WEBGL = 0x9245;
    const UNMASKED_RENDERER_WEBGL = 0x9246;

    // Pick a realistic GPU-capability profile for the persona's
    // claimed renderer. Without this gl.getParameter(MAX_TEXTURE_SIZE)
    // etc. still leaks the real host GPU's caps — defeats the
    // persona's claimed mobile Adreno when host is Mesa Intel.
    const gpuClaim = String(persona.webgl_unmasked_renderer || persona.webgl_renderer || "").toLowerCase();
    const gpuIsAdreno = /adreno/.test(gpuClaim);
    const gpuIsMali = /mali/.test(gpuClaim);
    const gpuIsAppleM = /apple|mac/.test(gpuClaim);
    const gpuIsNvidia = /nvidia|geforce/.test(gpuClaim);
    const gpuIsAmd = /amd|radeon/.test(gpuClaim);

    // Common paramater values picked from real-world telemetry of
    // popular GPU families.
    const gpuCaps = (function () {
      if (gpuIsAdreno) return {
        version: "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        glsl: "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        maxTextureSize: 16384,
        maxCubeMapTextureSize: 16384,
        maxRenderBufferSize: 16384,
        maxViewportDims: [16384, 16384],
        maxTextureImageUnits: 16,
        maxCombinedTextureImageUnits: 96,
        maxFragmentUniformVectors: 1024,
        maxVertexUniformVectors: 1024,
        maxVaryingVectors: 31,
        maxVertexAttribs: 16,
        aliasedPointSizeRange: [1, 1023],
        aliasedLineWidthRange: [1, 8],
        depthBits: 24, stencilBits: 8,
        // Most common Android Chrome WebGL extensions.
        extensions: ["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_filter_anisotropic","WEBKIT_EXT_texture_filter_anisotropic","EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_astc","WEBGL_compressed_texture_etc","WEBGL_compressed_texture_etc1","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw"],
      };
      if (gpuIsMali) return {
        version: "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        glsl: "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        maxTextureSize: 8192,
        maxCubeMapTextureSize: 8192,
        maxRenderBufferSize: 8192,
        maxViewportDims: [8192, 8192],
        maxTextureImageUnits: 16,
        maxCombinedTextureImageUnits: 96,
        maxFragmentUniformVectors: 256,
        maxVertexUniformVectors: 256,
        maxVaryingVectors: 16,
        maxVertexAttribs: 16,
        aliasedPointSizeRange: [1, 511],
        aliasedLineWidthRange: [1, 8],
        depthBits: 24, stencilBits: 8,
        extensions: ["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_filter_anisotropic","EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_standard_derivatives","OES_texture_float","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_compressed_texture_astc","WEBGL_compressed_texture_etc","WEBGL_compressed_texture_etc1","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context"],
      };
      if (gpuIsAppleM) return {
        version: "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        glsl: "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        maxTextureSize: 16384,
        maxCubeMapTextureSize: 16384,
        maxRenderBufferSize: 16384,
        maxViewportDims: [16384, 16384],
        maxTextureImageUnits: 16,
        maxCombinedTextureImageUnits: 96,
        maxFragmentUniformVectors: 1024,
        maxVertexUniformVectors: 1024,
        maxVaryingVectors: 31,
        maxVertexAttribs: 16,
        aliasedPointSizeRange: [1, 511],
        aliasedLineWidthRange: [1, 1],
        depthBits: 24, stencilBits: 8,
        extensions: ["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","WEBKIT_EXT_texture_filter_anisotropic","EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_astc","WEBGL_compressed_texture_etc","WEBGL_compressed_texture_etc1","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw"],
      };
      // Default desktop-discrete GPU (NVIDIA / AMD / Intel desktop).
      return {
        version: "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        glsl: "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)",
        maxTextureSize: 16384,
        maxCubeMapTextureSize: 16384,
        maxRenderBufferSize: 16384,
        maxViewportDims: [32767, 32767],
        maxTextureImageUnits: 16,
        maxCombinedTextureImageUnits: 80,
        maxFragmentUniformVectors: 1024,
        maxVertexUniformVectors: 4096,
        maxVaryingVectors: 30,
        maxVertexAttribs: 16,
        aliasedPointSizeRange: [1, 1024],
        aliasedLineWidthRange: [1, 1],
        depthBits: 24, stencilBits: 0,
        extensions: ["ANGLE_instanced_arrays","EXT_blend_minmax","EXT_color_buffer_half_float","EXT_disjoint_timer_query","EXT_float_blend","EXT_frag_depth","EXT_shader_texture_lod","EXT_texture_compression_bptc","EXT_texture_compression_rgtc","EXT_texture_filter_anisotropic","EXT_sRGB","KHR_parallel_shader_compile","OES_element_index_uint","OES_fbo_render_mipmap","OES_standard_derivatives","OES_texture_float","OES_texture_float_linear","OES_texture_half_float","OES_texture_half_float_linear","OES_vertex_array_object","WEBGL_color_buffer_float","WEBGL_compressed_texture_s3tc","WEBGL_compressed_texture_s3tc_srgb","WEBGL_debug_renderer_info","WEBGL_debug_shaders","WEBGL_depth_texture","WEBGL_draw_buffers","WEBGL_lose_context","WEBGL_multi_draw"],
      };
    })();

    const MAX_TEXTURE_SIZE = 0x0D33;
    const MAX_CUBE_MAP_TEXTURE_SIZE = 0x851C;
    const MAX_RENDERBUFFER_SIZE = 0x84E8;
    const MAX_VIEWPORT_DIMS = 0x0D3A;
    const MAX_TEXTURE_IMAGE_UNITS = 0x8872;
    const MAX_COMBINED_TEXTURE_IMAGE_UNITS = 0x8B4D;
    const MAX_FRAGMENT_UNIFORM_VECTORS = 0x8DFD;
    const MAX_VERTEX_UNIFORM_VECTORS = 0x8DFB;
    const MAX_VARYING_VECTORS = 0x8DFC;
    const MAX_VERTEX_ATTRIBS = 0x8869;
    const ALIASED_POINT_SIZE_RANGE = 0x846D;
    const ALIASED_LINE_WIDTH_RANGE = 0x846E;
    const DEPTH_BITS = 0x0D56;
    const STENCIL_BITS = 0x0D57;

    function patch(proto) {
      if (!proto || !proto.getParameter) return;
      const orig = proto.getParameter;
      // Use Object.defineProperty so the override is forced even if
      // the binding marks the property non-writable. Plain
      // assignment (proto.getParameter = X) silently fails in
      // sloppy mode when the underlying V8 binding has writable=false,
      // which is what Brave Shields aggressive sets for fingerprint-
      // sensitive WebGL methods. defineProperty with configurable+
      // writable+true wins.
      const wrapped = function (param) {
        switch (param) {
          case VENDOR:
            if (persona.webgl_vendor) return persona.webgl_vendor;
            break;
          case RENDERER:
            if (persona.webgl_renderer) return persona.webgl_renderer;
            break;
          case UNMASKED_VENDOR_WEBGL:
            if (persona.webgl_unmasked_vendor) return persona.webgl_unmasked_vendor;
            break;
          case UNMASKED_RENDERER_WEBGL:
            if (persona.webgl_unmasked_renderer) return persona.webgl_unmasked_renderer;
            break;
          case VERSION: return gpuCaps.version;
          case SHADING_LANGUAGE_VERSION: return gpuCaps.glsl;
          case MAX_TEXTURE_SIZE: return gpuCaps.maxTextureSize;
          case MAX_CUBE_MAP_TEXTURE_SIZE: return gpuCaps.maxCubeMapTextureSize;
          case MAX_RENDERBUFFER_SIZE: return gpuCaps.maxRenderBufferSize;
          case MAX_VIEWPORT_DIMS: return new Int32Array(gpuCaps.maxViewportDims);
          case MAX_TEXTURE_IMAGE_UNITS: return gpuCaps.maxTextureImageUnits;
          case MAX_COMBINED_TEXTURE_IMAGE_UNITS: return gpuCaps.maxCombinedTextureImageUnits;
          case MAX_FRAGMENT_UNIFORM_VECTORS: return gpuCaps.maxFragmentUniformVectors;
          case MAX_VERTEX_UNIFORM_VECTORS: return gpuCaps.maxVertexUniformVectors;
          case MAX_VARYING_VECTORS: return gpuCaps.maxVaryingVectors;
          case MAX_VERTEX_ATTRIBS: return gpuCaps.maxVertexAttribs;
          case ALIASED_POINT_SIZE_RANGE: return new Float32Array(gpuCaps.aliasedPointSizeRange);
          case ALIASED_LINE_WIDTH_RANGE: return new Float32Array(gpuCaps.aliasedLineWidthRange);
          case DEPTH_BITS: return gpuCaps.depthBits;
          case STENCIL_BITS: return gpuCaps.stencilBits;
        }
        return orig.call(this, param);
      };
      try {
        Object.defineProperty(wrapped, "toString", {
          value: function () { return "function getParameter() { [native code] }"; },
        });
      } catch (_) {}
      // Force install via defineProperty (works around non-writable).
      try {
        Object.defineProperty(proto, "getParameter", {
          value: wrapped, configurable: true, writable: true,
        });
      } catch (e) {
        // Last-resort fallback — direct assign + log if even that
        // fails so the user sees something actionable in console.
        try { proto.getParameter = wrapped; } catch (_) {}
        try { console.warn("[veil] WebGL getParameter override install failed:", e); } catch (_) {}
      }
      // Verify the install actually took. If not, the page sees the
      // raw GPU strings — which is the bug the user kept hitting.
      try {
        if (proto.getParameter !== wrapped) {
          console.warn("[veil] WebGL getParameter override did NOT take effect on", proto.constructor && proto.constructor.name);
        }
      } catch (_) {}

      // getSupportedExtensions — sites iterate this to fingerprint
      // GPU family. Mesa Intel exposes EXT_texture_compression_bptc
      // but Adreno does not (and vice-versa for ASTC). Spoof.
      if (proto.getSupportedExtensions) {
        const wrappedExt = function () {
          return gpuCaps.extensions.slice();
        };
        try {
          Object.defineProperty(wrappedExt, "toString", {
            value: function () { return "function getSupportedExtensions() { [native code] }"; },
          });
        } catch (_) {}
        try {
          Object.defineProperty(proto, "getSupportedExtensions", {
            value: wrappedExt, configurable: true, writable: true,
          });
        } catch (_) {
          try { proto.getSupportedExtensions = wrappedExt; } catch (_) {}
        }
      }

      // getExtension('WEBGL_debug_renderer_info') sometimes returns a
      // FROZEN extension object with its own UNMASKED_VENDOR_WEBGL /
      // UNMASKED_RENDERER_WEBGL constants. Some sites read those
      // constants from the returned ext object instead of hardcoding
      // 0x9245/0x9246. If Brave farbles by returning slightly-
      // different constants, our switch-case in getParameter doesn't
      // match. Wrap getExtension so when WEBGL_debug_renderer_info is
      // requested we return a plain object with the canonical
      // constants — pages then call getParameter with 0x9245/0x9246
      // and our wrap catches them.
      if (proto.getExtension) {
        const origGetExt = proto.getExtension;
        const wrappedGetExt = function (name) {
          const ext = origGetExt.call(this, name);
          if (ext && (name === "WEBGL_debug_renderer_info" || name === "MOZ_WEBGL_debug_renderer_info")) {
            return {
              UNMASKED_VENDOR_WEBGL: 0x9245,
              UNMASKED_RENDERER_WEBGL: 0x9246,
            };
          }
          return ext;
        };
        try {
          Object.defineProperty(wrappedGetExt, "toString", {
            value: function () { return "function getExtension() { [native code] }"; },
          });
        } catch (_) {}
        try {
          Object.defineProperty(proto, "getExtension", {
            value: wrappedGetExt, configurable: true, writable: true,
          });
        } catch (_) {
          try { proto.getExtension = wrappedGetExt; } catch (_) {}
        }
      }
    }
    patch(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patch(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);

    // ---------- WebGL getShaderPrecisionFormat ----------
    // Adreno reports highp range different from Mesa Intel UHD 620.
    // Common detector: gl.getShaderPrecisionFormat(FRAGMENT_SHADER, HIGH_FLOAT)
    // returns {rangeMin: 127, rangeMax: 127, precision: 23} on real
    // GPUs supporting highp; rangeMin/Max:0 on OES_standard_derivatives-
    // only GPUs. Force highp-supported answers.
    function patchPrecision(proto) {
      if (!proto || !proto.getShaderPrecisionFormat) return;
      proto.getShaderPrecisionFormat = function () {
        return { rangeMin: 127, rangeMax: 127, precision: 23 };
      };
      try {
        Object.defineProperty(proto.getShaderPrecisionFormat, "toString", {
          value: function () { return "function getShaderPrecisionFormat() { [native code] }"; },
        });
      } catch (_) {}
    }
    patchPrecision(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchPrecision(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
  }

  // ---------- AudioContext latency / channels ----------
  // AudioContext.outputLatency varies by audio backend (PulseAudio
  // ≠ AAudio ≠ WASAPI). Mobile personas in particular need realistic
  // mobile latency numbers — desktop PulseAudio reports ~0.025s,
  // mobile AAudio ~0.012s. Spoof to a typical-cohort value per
  // persona platform.
  try {
    if (typeof AudioContext !== "undefined") {
      const isMobile = !!(persona.client_hints && persona.client_hints.mobile);
      const baseLatency = isMobile ? 0.005 : 0.005;       // both small
      const outputLatency = isMobile ? 0.012 : 0.025;     // bigger desktop
      const maxChannelCount = 2;                           // stereo cohort
      const proto = AudioContext.prototype;
      try {
        Object.defineProperty(proto, "baseLatency", {
          get: nativeGet(baseLatency), configurable: true,
        });
        Object.defineProperty(proto, "outputLatency", {
          get: nativeGet(outputLatency), configurable: true,
        });
      } catch (_) {}
      // destination.maxChannelCount — site checks for surround setup;
      // mobile is always 2.
      const origGetDest = Object.getOwnPropertyDescriptor(proto, "destination");
      if (origGetDest && origGetDest.get) {
        Object.defineProperty(proto, "destination", {
          get: function () {
            const d = origGetDest.get.call(this);
            try {
              Object.defineProperty(d, "maxChannelCount", {
                get: nativeGet(maxChannelCount), configurable: true,
              });
            } catch (_) {}
            return d;
          },
          configurable: true,
        });
      }
    }
  } catch (_) {}

  // ---------- performance.memory (Chromium-only) ----------
  // Reports renderer process heap stats: jsHeapSizeLimit + total +
  // used. Real values reveal cohort: a 32GB-RAM box has different
  // heap limit (~4GB) than 8GB box (~2GB). Force most-populated
  // bucket: 4GB limit which matches Chrome 120+ default on
  // mid-range machines.
  try {
    if (performance && !performance.memory) {
      Object.defineProperty(performance, "memory", {
        get: nativeGet({
          jsHeapSizeLimit: 4294705152,    // ~4 GiB
          totalJSHeapSize: 35000000,
          usedJSHeapSize: 25000000,
        }),
        configurable: true,
      });
    } else if (performance && performance.memory) {
      Object.defineProperty(performance, "memory", {
        get: nativeGet({
          jsHeapSizeLimit: 4294705152,
          totalJSHeapSize: 35000000,
          usedJSHeapSize: 25000000,
        }),
        configurable: true,
      });
    }
  } catch (_) {}

  // ---------- document.fonts.check + iteration ----------
  // Site iterates a known list ("Roboto", "DejaVu Sans", "SF Pro",
  // etc.) calling document.fonts.check("12px FontName") to detect
  // OS-installed fonts. Desktop Linux has DejaVu/Liberation; Android
  // has Roboto + a small set; iOS has SF Pro + Helvetica Neue.
  // Mismatch with persona = instant flag.
  try {
    if (document && document.fonts && document.fonts.check) {
      // Per-OS allowlists — sites checking a font NOT in this list
      // get false (font not installed). Desktop personas inherit a
      // larger list than mobile.
      const personaPlatform = String((persona.client_hints && persona.client_hints.platform) || persona.platform || "").toLowerCase();
      const fontsByPlatform = {
        android: ["roboto","noto sans","noto color emoji","droid sans","droid sans mono","sans-serif","serif","monospace"],
        ios: ["helvetica neue","helvetica","sf pro","sf pro display","sf pro text","arial","times new roman","courier new","georgia","verdana","sans-serif","serif","monospace"],
        macos: ["sf pro","sf pro display","sf pro text","helvetica","helvetica neue","arial","times new roman","menlo","monaco","courier new","georgia","verdana","trebuchet ms","comic sans ms","sans-serif","serif","monospace"],
        windows: ["arial","calibri","cambria","candara","consolas","constantia","corbel","courier new","ebrima","franklin gothic","gabriola","georgia","impact","lucida console","lucida sans unicode","malgun gothic","microsoft sans serif","segoe ui","tahoma","times new roman","trebuchet ms","verdana","webdings","wingdings","sans-serif","serif","monospace"],
        linux: ["dejavu sans","dejavu serif","dejavu sans mono","liberation sans","liberation serif","liberation mono","ubuntu","ubuntu mono","noto sans","noto serif","sans-serif","serif","monospace"],
      };
      let allowed = fontsByPlatform.linux; // sane default
      if (personaPlatform.indexOf("android") !== -1) allowed = fontsByPlatform.android;
      else if (personaPlatform.indexOf("ios") !== -1 || personaPlatform.indexOf("iphone") !== -1) allowed = fontsByPlatform.ios;
      else if (personaPlatform.indexOf("mac") !== -1) allowed = fontsByPlatform.macos;
      else if (personaPlatform.indexOf("windows") !== -1) allowed = fontsByPlatform.windows;
      const allowedSet = new Set(allowed.map(function (f) { return f.toLowerCase(); }));
      const origCheck = document.fonts.check.bind(document.fonts);
      document.fonts.check = function (font, text) {
        // font is e.g. '12px "Roboto"' or '14pt SF Pro' — extract family.
        const m = String(font || "").match(/(?:\d+(?:\.\d+)?(?:px|pt|em|rem)\s+)?["']?([^"',]+)["']?/);
        if (m && m[1]) {
          const fam = m[1].trim().toLowerCase();
          if (!allowedSet.has(fam)) return false;
        }
        return origCheck(font, text);
      };
      try {
        Object.defineProperty(document.fonts.check, "toString", {
          value: function () { return "function check() { [native code] }"; },
        });
      } catch (_) {}
    }
  } catch (_) {}

  // ---------- Intl.DateTimeFormat / timezone ----------
  if (persona.timezone && typeof Intl !== "undefined" && Intl.DateTimeFormat) {
    const origDTF = Intl.DateTimeFormat;
    function PatchedDTF(locale, options) {
      const opts = Object.assign({}, options || {});
      if (!opts.timeZone) opts.timeZone = persona.timezone;
      return new origDTF(locale, opts);
    }
    PatchedDTF.prototype = origDTF.prototype;
    PatchedDTF.supportedLocalesOf = origDTF.supportedLocalesOf;
    try { Intl.DateTimeFormat = PatchedDTF; } catch (_) {}

    // Date.prototype.getTimezoneOffset — sites use this directly.
    const origGTO = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = function () {
      try {
        const dtf = new origDTF("en-US", { timeZone: persona.timezone, timeZoneName: "shortOffset" });
        const parts = dtf.formatToParts(this);
        const tn = parts.find(p => p.type === "timeZoneName");
        if (tn) {
          const m = tn.value.match(/GMT([+-])(\d+)(?::(\d+))?/);
          if (m) {
            const sign = m[1] === "-" ? 1 : -1;
            const hours = parseInt(m[2], 10);
            const mins = m[3] ? parseInt(m[3], 10) : 0;
            return sign * (hours * 60 + mins);
          }
        }
      } catch (_) {}
      return origGTO.call(this);
    };
  }

  // ---------- Battery API ----------
  // Persona claims a desktop → return charging:true, level:1.0.
  // Persona claims a mobile → return realistic non-charging level.
  if (typeof nav.getBattery === "function") {
    const isMobile = !!(persona.client_hints && persona.client_hints.mobile);
    const fake = {
      charging: !isMobile,
      chargingTime: !isMobile ? 0 : Infinity,
      dischargingTime: isMobile ? 12 * 3600 : Infinity,
      level: isMobile ? 0.78 : 1.0,
      addEventListener: function () {},
      removeEventListener: function () {},
    };
    nav.getBattery = function () { return Promise.resolve(fake); };
    try {
      Object.defineProperty(nav.getBattery, "toString", {
        value: function () { return "function getBattery() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- AudioContext sample rate ----------
  // 44100 (most common, persona claims desktop) or 48000 (some
  // laptops + mobile). Persona may pin if needed.
  if (typeof persona.audio_sample_rate === "number" && window.AudioContext) {
    const origAC = window.AudioContext;
    function PatchedAC(opts) {
      const o = Object.assign({}, opts || {});
      o.sampleRate = persona.audio_sample_rate;
      return new origAC(o);
    }
    PatchedAC.prototype = origAC.prototype;
    try { window.AudioContext = PatchedAC; } catch (_) {}
  }

  // ---------- Browser identity tells (the high-detection ones) ----------
  //
  // These are the JS surfaces bot detectors hit first. Every one of
  // them is a near-instant 100% identifier of the actual browser if
  // we don't override.

  // navigator.webdriver — Selenium / Playwright / "automation" flag.
  // Set to true on any Chromium driven by an automation framework
  // (CDP / WebDriver / Marionette). Veil DOES drive the browser
  // (CDP for IP probes, Marionette for Firefox extension install)
  // so navigator.webdriver may flip to true. Force false to look
  // like a normal-user browser session.
  try {
    Object.defineProperty(nav, "webdriver", {
      get: nativeGet(false),
      configurable: true, enumerable: true,
    });
  } catch (_) {}

  // navigator.brave.isBrave() — Brave's self-identification API.
  // Returns true on Brave, undefined elsewhere. Strip it entirely
  // so a Brave-on-Linux can claim to be Chrome.
  try {
    if (nav.brave) {
      delete nav.brave;
    }
    // Re-assert deletion against page scripts that might re-add it.
    Object.defineProperty(nav, "brave", {
      get: nativeGet(undefined),
      configurable: true, enumerable: false,
    });
  } catch (_) {}

  // window.chrome — Chromium injects a sprawling object hierarchy
  // (chrome.runtime, chrome.csi, chrome.loadTimes, etc.) that
  // Firefox does NOT have. If the persona claims to be Chrome and
  // we're running on Firefox, we'd be missing window.chrome
  // entirely → instant Firefox detection.
  //
  // Conversely if persona claims Firefox-family and browser is
  // Chromium, window.chrome leaks Chromium presence.
  const personaIsChrome = (persona.user_agent && /Chrome\//.test(persona.user_agent)) ||
                          (persona.client_hints && /Chrome|Chromium/.test(JSON.stringify(persona.client_hints || {})));
  const personaIsFirefox = (persona.user_agent && /Firefox\//.test(persona.user_agent));
  if (personaIsChrome && typeof window.chrome === "undefined") {
    try {
      // Synthesize a minimal Chrome-shape window.chrome. Real Chrome
      // exposes lots more (chrome.runtime/csi/loadTimes/webstore/app)
      // but the shape that bot detectors check is "exists with these
      // top-level keys". Provide stubs that don't throw.
      const fakeChrome = {
        runtime: undefined,
        csi: function () { return { startE: Date.now(), onloadT: Date.now(), pageT: 0, tran: 15 }; },
        loadTimes: function () { return { requestTime: Date.now() / 1000 }; },
      };
      // app/webstore are also present on real Chrome but exposing
      // them risks security-sensitive APIs being callable.
      Object.defineProperty(window, "chrome", {
        value: fakeChrome,
        writable: true, configurable: true,
      });
    } catch (_) {}
  } else if (personaIsFirefox && typeof window.chrome !== "undefined") {
    try {
      delete window.chrome;
      Object.defineProperty(window, "chrome", {
        get: nativeGet(undefined),
        configurable: true,
      });
    } catch (_) {}
  }

  // navigator.plugins / navigator.mimeTypes — Chrome has a fixed
  // small list (PDF Viewer / Chrome PDF Viewer / Native Client),
  // Firefox has empty plugins on modern versions. Mismatching with
  // the persona's claimed identity is a reliable browser identifier.
  try {
    let plugins;
    if (personaIsChrome) {
      // Chromium 100+ canonical plugin list. Real Chrome exposes
      // these by name; pages enumerate by name + filename.
      plugins = [
        { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
        { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
        { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
        { name: "Microsoft Edge PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
        { name: "WebKit built-in PDF", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      ];
    } else if (personaIsFirefox) {
      // Modern Firefox has empty plugins / mimeTypes by default.
      plugins = [];
    } else {
      plugins = null; // leave unchanged
    }
    if (plugins) {
      const arr = plugins.map(p => Object.assign(Object.create(Plugin.prototype || Object.prototype), p));
      arr.namedItem = function (name) { return arr.find(p => p.name === name) || null; };
      arr.item = function (i) { return arr[i] || null; };
      arr.refresh = function () {};
      Object.defineProperty(arr, "length", { get: () => arr.length });
      Object.defineProperty(nav, "plugins", { get: nativeGet(arr), configurable: true, enumerable: true });
    }
  } catch (_) {}

  // navigator.permissions.query — Chrome's behavior on the
  // "notifications" permission differs from Firefox in a way that
  // detectors leverage. Specifically Chrome returns
  //   { state: "default" } when called with notifications BEFORE
  // user permission is granted, while Firefox returns
  //   { state: "denied" } in the same case.
  // A "Chrome persona" with Firefox-shape return = Firefox detection.
  if (personaIsChrome && nav.permissions && nav.permissions.query) {
    const origQuery = nav.permissions.query.bind(nav.permissions);
    nav.permissions.query = function (param) {
      if (param && param.name === "notifications") {
        return Promise.resolve({ state: "default", onchange: null });
      }
      return origQuery(param);
    };
    try {
      Object.defineProperty(nav.permissions.query, "toString", {
        value: function () { return "function query() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- MediaDevices.enumerateDevices ----------
  // Real Chrome reports 1-2 default mic + camera entries even when
  // the user hasn't granted media permissions (with "" deviceId). A
  // browser that returns an empty list is fingerprintably "running
  // headless / in container / restricted". Synthesize a default-
  // device list so our profile looks like a normal desktop user.
  if (nav.mediaDevices && nav.mediaDevices.enumerateDevices) {
    // MediaDeviceInfo.prototype has getter-only kind/deviceId/
    // groupId/label — Object.assign throws "only a getter". Build
    // the device objects via Object.create + defineProperty for
    // each field so the prototype chain still says
    // `instanceof MediaDeviceInfo` while the values are ours.
    const proto = (typeof MediaDeviceInfo !== "undefined")
      ? MediaDeviceInfo.prototype
      : Object.prototype;
    function mkDevice(kind, deviceId, groupId, label) {
      const d = Object.create(proto);
      Object.defineProperty(d, "kind",     { value: kind,     enumerable: true });
      Object.defineProperty(d, "deviceId", { value: deviceId, enumerable: true });
      Object.defineProperty(d, "groupId",  { value: groupId,  enumerable: true });
      Object.defineProperty(d, "label",    { value: label,    enumerable: true });
      // toJSON used by sites for serialization; mirror Chrome.
      Object.defineProperty(d, "toJSON", {
        value: function () {
          return { kind: kind, deviceId: deviceId, groupId: groupId, label: label };
        },
      });
      return d;
    }
    const fakeDevices = [
      mkDevice("audioinput",  "default", "default-audio", ""),
      mkDevice("audiooutput", "default", "default-audio", ""),
      mkDevice("videoinput",  "default", "default-video", ""),
    ];
    const wrappedEnum = function () {
      return Promise.resolve(fakeDevices.slice());
    };
    try {
      Object.defineProperty(wrappedEnum, "toString", {
        value: function () { return "function enumerateDevices() { [native code] }"; },
      });
    } catch (_) {}
    try {
      Object.defineProperty(nav.mediaDevices, "enumerateDevices", {
        value: wrappedEnum, configurable: true, writable: true,
      });
    } catch (_) {
      try { nav.mediaDevices.enumerateDevices = wrappedEnum; } catch (_) {}
    }
  }

  // ---------- navigator.connection (Network Information API) ----------
  // Real desktop Chrome reports effectiveType:"4g", rtt:50, downlink:10.
  // A browser without it (Firefox doesn't expose connection at all)
  // is identifiable. Match the persona — desktop personas get a 4g
  // effective type with reasonable values, mobile personas get 4g/3g
  // with mobile-shape rtt.
  if (personaIsChrome) {
    const isMobile = !!(persona.client_hints && persona.client_hints.mobile);
    const fakeConn = {
      downlink: isMobile ? 5 : 10,
      effectiveType: "4g",
      rtt: isMobile ? 100 : 50,
      saveData: false,
      type: isMobile ? "cellular" : "wifi",
      addEventListener: function () {},
      removeEventListener: function () {},
      dispatchEvent: function () { return true; },
      onchange: null,
    };
    try {
      Object.defineProperty(nav, "connection", {
        get: nativeGet(fakeConn), configurable: true, enumerable: true,
      });
    } catch (_) {}
  } else if (personaIsFirefox) {
    // Firefox doesn't expose navigator.connection. If our actual
    // browser is Chromium-based, hide it so we don't leak Chromium.
    try {
      Object.defineProperty(nav, "connection", {
        get: nativeGet(undefined), configurable: true, enumerable: false,
      });
    } catch (_) {}
  }

  // ---------- Speech synthesis voices ----------
  // window.speechSynthesis.getVoices() returns an OS-provided list.
  // The names are platform-specific (macOS "Alex", Windows "Microsoft
  // David", Linux "espeak default") and instantly fingerprint the
  // host OS underneath the persona. Spoof to a generic Chrome-on-
  // Linux voice list.
  if (typeof window.speechSynthesis !== "undefined" && window.speechSynthesis.getVoices) {
    const fakeVoices = [
      { name: "English",                  lang: "en-US", localService: true,  default: true,  voiceURI: "English" },
      { name: "English (United Kingdom)", lang: "en-GB", localService: true,  default: false, voiceURI: "English (United Kingdom)" },
      { name: "Deutsch",                  lang: "de-DE", localService: true,  default: false, voiceURI: "Deutsch" },
      { name: "français",                 lang: "fr-FR", localService: true,  default: false, voiceURI: "français" },
      { name: "español",                  lang: "es-ES", localService: true,  default: false, voiceURI: "español" },
    ];
    window.speechSynthesis.getVoices = function () { return fakeVoices.slice(); };
    try {
      Object.defineProperty(window.speechSynthesis.getVoices, "toString", {
        value: function () { return "function getVoices() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- performance.now() precision clamp ----------
  // Real browsers clamp to 1ms (Chrome cross-origin-isolation off) or
  // 5µs (with COOP+COEP). Sub-millisecond timing is a side-channel
  // for cache attacks AND a fingerprint signal (the actual clamp
  // depends on browser + isolation state). Force 1ms.
  if (typeof performance !== "undefined" && performance.now) {
    const origNow = performance.now.bind(performance);
    performance.now = function () {
      return Math.floor(origNow());
    };
    try {
      Object.defineProperty(performance.now, "toString", {
        value: function () { return "function now() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- navigator.cookieEnabled / pdfViewerEnabled ----------
  if (personaIsChrome) {
    try {
      Object.defineProperty(nav, "cookieEnabled", {
        get: nativeGet(true), configurable: true, enumerable: true,
      });
    } catch (_) {}
    try {
      Object.defineProperty(nav, "pdfViewerEnabled", {
        get: nativeGet(true), configurable: true, enumerable: true,
      });
    } catch (_) {}
  }

  // ===========================================================
  // Mobile-vs-desktop API surface coherence
  //
  // Android persona inside desktop Brave leaks every mobile-only API
  // that desktop Chrome doesn't have — TouchEvent absent, no
  // window.orientation, navigator.vibrate undefined, screen.orientation
  // says landscape-primary, matchMedia("(pointer: coarse)") returns
  // false. Bot detectors cross-check these against the UA's claimed
  // device type. Synthesize the mobile shape when persona is mobile,
  // strip it when persona is desktop running in a touch-capable browser.
  // ===========================================================
  const personaMobile = !!(persona.client_hints && persona.client_hints.mobile);
  const personaWidth = persona.screen_width || 0;
  const personaHeight = persona.screen_height || 0;
  const personaPortrait = personaWidth > 0 && personaHeight > 0 && personaHeight >= personaWidth;

  if (personaMobile) {
    // navigator.vibrate — present on Android Chrome, undefined on
    // desktop Brave/Chrome on Linux without API enabled.
    try {
      if (typeof nav.vibrate !== "function") {
        nav.vibrate = function () { return true; };
        Object.defineProperty(nav.vibrate, "toString", {
          value: function () { return "function vibrate() { [native code] }"; },
        });
      }
    } catch (_) {}

    // window.orientation — deprecated but Android Chrome still has
    // it. Returns 0 (portrait), 90/-90 (landscape), 180 (portrait
    // upside-down). For our portrait persona, return 0.
    try {
      Object.defineProperty(window, "orientation", {
        get: nativeGet(personaPortrait ? 0 : 90),
        configurable: true,
      });
    } catch (_) {}

    // screen.orientation — newer API. Mobile reports portrait-primary.
    try {
      if (screen.orientation) {
        Object.defineProperty(screen.orientation, "type", {
          get: nativeGet(personaPortrait ? "portrait-primary" : "landscape-primary"),
          configurable: true,
        });
        Object.defineProperty(screen.orientation, "angle", {
          get: nativeGet(personaPortrait ? 0 : 90),
          configurable: true,
        });
      }
    } catch (_) {}

    // TouchEvent — desktop Chrome on Linux has no TouchEvent
    // constructor unless the host has a touchscreen. Synthesize.
    try {
      if (typeof window.TouchEvent === "undefined") {
        // Cheap shim: enough that "typeof TouchEvent" is "function"
        // and `new TouchEvent("touchstart")` works.
        window.TouchEvent = function TouchEvent(type, init) {
          const e = new UIEvent(type, init || {});
          e.touches = (init && init.touches) || [];
          e.targetTouches = (init && init.targetTouches) || [];
          e.changedTouches = (init && init.changedTouches) || [];
          return e;
        };
        window.TouchEvent.prototype = UIEvent.prototype;
        window.Touch = function Touch(init) { return Object.assign({}, init); };
        window.TouchList = function TouchList() {};
      }
      // ontouchstart on window — bot detectors check this directly.
      if (!("ontouchstart" in window)) {
        Object.defineProperty(window, "ontouchstart", {
          get: nativeGet(null), set: function () {}, configurable: true,
        });
      }
    } catch (_) {}

    // matchMedia — sites use these to detect mobile vs desktop:
    //   (pointer: coarse) → mobile
    //   (hover: none) → mobile
    //   (any-pointer: coarse) → mobile (or hybrid)
    //   (any-hover: none) → mobile
    //   (orientation: portrait) → portrait
    //   (max-device-width: 480px) → small screen
    try {
      const origMM = window.matchMedia.bind(window);
      window.matchMedia = function (query) {
        const q = String(query);
        let forced = null;
        if (/\(\s*pointer\s*:\s*coarse\s*\)/.test(q)) forced = true;
        else if (/\(\s*pointer\s*:\s*fine\s*\)/.test(q)) forced = false;
        else if (/\(\s*any-pointer\s*:\s*coarse\s*\)/.test(q)) forced = true;
        else if (/\(\s*any-pointer\s*:\s*fine\s*\)/.test(q)) forced = false;
        else if (/\(\s*hover\s*:\s*none\s*\)/.test(q)) forced = true;
        else if (/\(\s*hover\s*:\s*hover\s*\)/.test(q)) forced = false;
        else if (/\(\s*any-hover\s*:\s*none\s*\)/.test(q)) forced = true;
        else if (/\(\s*any-hover\s*:\s*hover\s*\)/.test(q)) forced = false;
        else if (personaPortrait && /\(\s*orientation\s*:\s*portrait\s*\)/.test(q)) forced = true;
        else if (personaPortrait && /\(\s*orientation\s*:\s*landscape\s*\)/.test(q)) forced = false;
        if (forced === null) {
          return origMM(query);
        }
        return {
          matches: forced,
          media: q,
          onchange: null,
          addListener: function () {},
          removeListener: function () {},
          addEventListener: function () {},
          removeEventListener: function () {},
          dispatchEvent: function () { return false; },
        };
      };
      Object.defineProperty(window.matchMedia, "toString", {
        value: function () { return "function matchMedia() { [native code] }"; },
      });
    } catch (_) {}

    // window.innerWidth / innerHeight: desktop Brave window with
    // --window-size=412,915 actually creates that window — but the
    // browser's chrome / scrollbar takes pixels, so innerWidth ends
    // up like 412-15 = 397. Real Android Chrome at 412×915 viewport
    // reports innerWidth=412, innerHeight=915. Override to persona dims.
    try {
      if (personaWidth > 0 && personaHeight > 0) {
        Object.defineProperty(window, "innerWidth", {
          get: nativeGet(personaWidth), configurable: true,
        });
        Object.defineProperty(window, "innerHeight", {
          get: nativeGet(personaHeight), configurable: true,
        });
      }
    } catch (_) {}

    // visualViewport — mobile sites use this for keyboard inset.
    try {
      if (window.visualViewport && personaWidth > 0) {
        Object.defineProperty(window.visualViewport, "width", {
          get: nativeGet(personaWidth), configurable: true,
        });
        Object.defineProperty(window.visualViewport, "height", {
          get: nativeGet(personaHeight), configurable: true,
        });
        Object.defineProperty(window.visualViewport, "scale", {
          get: nativeGet(1), configurable: true,
        });
      }
    } catch (_) {}

    // DeviceOrientationEvent / DeviceMotionEvent — Android Chrome
    // exposes these constructors even before user grants permission.
    // Desktop Linux Chrome doesn't have them. Synthesize bare stubs.
    try {
      if (typeof window.DeviceOrientationEvent === "undefined") {
        window.DeviceOrientationEvent = function DeviceOrientationEvent(type, init) {
          const e = new Event(type, init || {});
          e.alpha = e.beta = e.gamma = null;
          e.absolute = false;
          return e;
        };
        // iOS 13+ requires permission via this static method. Android
        // doesn't but exposing it is harmless.
        window.DeviceOrientationEvent.requestPermission = function () {
          return Promise.resolve("granted");
        };
      }
      if (typeof window.DeviceMotionEvent === "undefined") {
        window.DeviceMotionEvent = function DeviceMotionEvent(type, init) {
          const e = new Event(type, init || {});
          e.acceleration = e.accelerationIncludingGravity = e.rotationRate = null;
          e.interval = 16;
          return e;
        };
        window.DeviceMotionEvent.requestPermission = function () {
          return Promise.resolve("granted");
        };
      }
    } catch (_) {}
  } else {
    // Desktop persona running in a touch-capable host (rare on
    // Linux but possible on a touchscreen laptop). Strip the mobile
    // surface so the desktop UA claim doesn't contradict.
    try {
      if (typeof nav.vibrate === "function") {
        Object.defineProperty(nav, "vibrate", {
          value: undefined, configurable: true, writable: true,
        });
      }
    } catch (_) {}
    try {
      if ("orientation" in window) {
        Object.defineProperty(window, "orientation", {
          get: nativeGet(undefined), configurable: true,
        });
      }
    } catch (_) {}
  }

  // ===========================================================
  // Per-eTLD farbling — canvas / audio / font / WebGL pixel-level
  //
  // What Brave Shields does at the C++ level we replicate here in
  // JS. Each canvas/audio readback gets micro-noise applied via a
  // PRNG seeded by the page's eTLD+1. Same site → same noise within
  // a session (so consistent fingerprint within a session, like real
  // browsers); different sites → different noise (defeats cross-site
  // tracking via fingerprint).
  // ===========================================================

  function farblingSeed() {
    // Deterministic per-host. Real Brave uses an eTLD+1 derivation;
    // close enough to use hostname directly here.
    const host = (location && location.hostname) || "";
    let h = 0x811c9dc5; // FNV-1a basis
    for (let i = 0; i < host.length; i++) {
      h ^= host.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h;
  }
  function makePRNG(seed) {
    // xorshift32 seeded with farblingSeed(). Returns 0..1 floats.
    let s = seed | 0;
    if (s === 0) s = 1;
    return function () {
      s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
      return ((s >>> 0) % 0x80000000) / 0x80000000;
    };
  }

  // When running on Brave with Shields aggressive, Brave's C++
  // farbling layer already handles canvas/audio/font/measureText
  // with per-eTLD determinism + coverage of OffscreenCanvas and
  // service-worker contexts our JS wraps can't see. Stacking our
  // wraps on top would (a) break Brave's per-session determinism
  // and (b) produce DOUBLE noise that itself flags the page as
  // "more random than real Brave". Skip those wraps and let Brave
  // handle. We still do all the navigator/WebGPU/WebRTC/storage/
  // gamepad overrides — Brave Shields does NOT cover those.
  const braveShieldsActive = persona && persona._veil_brave_shields_active === true;
  if (!braveShieldsActive) {

  // ---------- Canvas 2D farbling ----------
  // toDataURL / toBlob / getImageData get tiny per-pixel noise.
  // Magnitude: ±1 on RGB channels (alpha untouched) so pixels look
  // sane visually but the SHA-256 of the rendered output is unique
  // per-site, breaking cross-site canvas-fingerprint tracking.
  try {
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function () {
      const img = origGetImageData.apply(this, arguments);
      const data = img.data;
      const rng = makePRNG(farblingSeed() ^ data.length);
      for (let i = 0; i < data.length; i += 4) {
        // 1 in 8 pixels gets a ±1 nudge on a single channel.
        if ((rng() * 8) < 1) {
          const ch = (rng() * 3) | 0; // 0=R 1=G 2=B
          const delta = rng() < 0.5 ? -1 : 1;
          const v = data[i + ch] + delta;
          if (v >= 0 && v <= 255) data[i + ch] = v;
        }
      }
      return img;
    };
    Object.defineProperty(CanvasRenderingContext2D.prototype.getImageData, "toString", {
      value: function () { return "function getImageData() { [native code] }"; },
    });

    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function () {
      // Read pixels through getImageData (which is now farbled) by
      // drawing self → self via 2D context, then re-emit. For pure
      // WebGL canvases without 2D context, fall back to original.
      try {
        const ctx = this.getContext && this.getContext("2d");
        if (ctx) {
          const w = this.width, h = this.height;
          if (w > 0 && h > 0) {
            const img = ctx.getImageData(0, 0, w, h); // farbled via wrap above
            ctx.putImageData(img, 0, 0);
          }
        }
      } catch (_) {}
      return origToDataURL.apply(this, arguments);
    };
    Object.defineProperty(HTMLCanvasElement.prototype.toDataURL, "toString", {
      value: function () { return "function toDataURL() { [native code] }"; },
    });

    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    if (origToBlob) {
      HTMLCanvasElement.prototype.toBlob = function (cb) {
        try {
          const ctx = this.getContext && this.getContext("2d");
          if (ctx) {
            const w = this.width, h = this.height;
            if (w > 0 && h > 0) {
              const img = ctx.getImageData(0, 0, w, h);
              ctx.putImageData(img, 0, 0);
            }
          }
        } catch (_) {}
        return origToBlob.apply(this, arguments);
      };
      Object.defineProperty(HTMLCanvasElement.prototype.toBlob, "toString", {
        value: function () { return "function toBlob() { [native code] }"; },
      });
    }
  } catch (_) {}

  // ---------- WebGL farbling ----------
  // readPixels copies framebuffer contents to a TypedArray. Apply
  // per-pixel ±1 noise on color channels.
  try {
    function patchReadPixels(proto) {
      if (!proto || !proto.readPixels) return;
      const orig = proto.readPixels;
      proto.readPixels = function (x, y, width, height, format, type, pixels) {
        const ret = orig.apply(this, arguments);
        if (pixels && pixels.length) {
          const rng = makePRNG(farblingSeed() ^ pixels.length);
          // Nudge ~1/16 bytes by ±1 on color channels (skip alpha
          // every 4th byte for RGBA formats).
          for (let i = 0; i < pixels.length; i++) {
            if ((i & 3) === 3) continue; // alpha
            if ((rng() * 16) < 1) {
              const delta = rng() < 0.5 ? -1 : 1;
              const v = pixels[i] + delta;
              if (v >= 0 && v <= 255) pixels[i] = v;
            }
          }
        }
        return ret;
      };
      try {
        Object.defineProperty(proto.readPixels, "toString", {
          value: function () { return "function readPixels() { [native code] }"; },
        });
      } catch (_) {}
    }
    patchReadPixels(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchReadPixels(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
  } catch (_) {}

  // ---------- AudioContext farbling ----------
  // getFloatFrequencyData / getByteFrequencyData are the standard
  // audio fingerprint vectors. Apply tiny per-bin noise.
  try {
    function patchAnalyser(proto) {
      if (!proto) return;
      const origFloat = proto.getFloatFrequencyData;
      const origByte = proto.getByteFrequencyData;
      const origFloatTime = proto.getFloatTimeDomainData;
      const origByteTime = proto.getByteTimeDomainData;
      if (origFloat) {
        proto.getFloatFrequencyData = function (arr) {
          origFloat.apply(this, arguments);
          if (!arr || !arr.length) return;
          const rng = makePRNG(farblingSeed() ^ arr.length);
          for (let i = 0; i < arr.length; i++) {
            if (Number.isFinite(arr[i])) {
              arr[i] += (rng() - 0.5) * 0.001; // ±0.0005 dB
            }
          }
        };
        Object.defineProperty(proto.getFloatFrequencyData, "toString", {
          value: function () { return "function getFloatFrequencyData() { [native code] }"; },
        });
      }
      if (origByte) {
        proto.getByteFrequencyData = function (arr) {
          origByte.apply(this, arguments);
          if (!arr || !arr.length) return;
          const rng = makePRNG(farblingSeed() ^ arr.length);
          for (let i = 0; i < arr.length; i++) {
            if ((rng() * 16) < 1) {
              const delta = rng() < 0.5 ? -1 : 1;
              const v = arr[i] + delta;
              if (v >= 0 && v <= 255) arr[i] = v;
            }
          }
        };
        Object.defineProperty(proto.getByteFrequencyData, "toString", {
          value: function () { return "function getByteFrequencyData() { [native code] }"; },
        });
      }
      if (origFloatTime) {
        proto.getFloatTimeDomainData = function (arr) {
          origFloatTime.apply(this, arguments);
          if (!arr || !arr.length) return;
          const rng = makePRNG(farblingSeed() ^ arr.length ^ 1);
          for (let i = 0; i < arr.length; i++) {
            if (Number.isFinite(arr[i])) arr[i] += (rng() - 0.5) * 0.0001;
          }
        };
      }
      if (origByteTime) {
        proto.getByteTimeDomainData = function (arr) {
          origByteTime.apply(this, arguments);
          if (!arr || !arr.length) return;
          const rng = makePRNG(farblingSeed() ^ arr.length ^ 2);
          for (let i = 0; i < arr.length; i++) {
            if ((rng() * 32) < 1) {
              const delta = rng() < 0.5 ? -1 : 1;
              const v = arr[i] + delta;
              if (v >= 0 && v <= 255) arr[i] = v;
            }
          }
        };
      }
    }
    patchAnalyser(window.AnalyserNode && AnalyserNode.prototype);
  } catch (_) {}

  // ---------- Font fingerprinting via measureText ----------
  // Sites measure text width with various font-families, comparing to
  // a fallback to detect installed fonts. We add sub-pixel jitter to
  // the returned TextMetrics so the comparison is unstable enough to
  // defeat enumeration but stable per-page (deterministic seed).
  try {
    const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
    CanvasRenderingContext2D.prototype.measureText = function () {
      const m = origMeasureText.apply(this, arguments);
      try {
        const seed = farblingSeed() ^ Math.floor((m.width || 0) * 1000);
        const rng = makePRNG(seed);
        const jitter = (rng() - 0.5) * 0.05; // ±0.025px
        const farbled = Object.create(Object.getPrototypeOf(m));
        for (const k in m) farbled[k] = m[k];
        farbled.width = (m.width || 0) + jitter;
        return farbled;
      } catch (_) {
        return m;
      }
    };
    Object.defineProperty(CanvasRenderingContext2D.prototype.measureText, "toString", {
      value: function () { return "function measureText() { [native code] }"; },
    });
  } catch (_) {}
  } // end if (!braveShieldsActive) — wraps canvas/WebGL/audio/measureText

  // ---------- Geolocation API ----------
  // Sites that check location via geolocation API when granted get
  // real GPS / IP geolocation data — instantly contradicts our
  // network-level country pin if the user runs through a Tor exit
  // in DE while running a "I'm in NY" persona. Override to the
  // persona's claimed timezone-derived coords (rough city guess) or
  // refuse with permission-denied for non-persona profiles.
  if (typeof navigator !== "undefined" && nav.geolocation) {
    const tz = persona.timezone || "";
    const personaCoords = (function () {
      // Crude TZ → lat/lng so persona.timezone="America/New_York" maps
      // to NYC-ish coords. Better would be persona.lat/lng but most
      // personas don't carry those.
      const m = {
        "America/New_York":     { latitude: 40.71, longitude: -74.01,  accuracy: 100 },
        "America/Los_Angeles":  { latitude: 34.05, longitude: -118.24, accuracy: 100 },
        "America/Chicago":      { latitude: 41.88, longitude: -87.63,  accuracy: 100 },
        "Europe/London":        { latitude: 51.51, longitude: -0.13,   accuracy: 100 },
        "Europe/Paris":         { latitude: 48.86, longitude:  2.35,   accuracy: 100 },
        "Europe/Berlin":        { latitude: 52.52, longitude: 13.41,   accuracy: 100 },
        "Europe/Zurich":        { latitude: 47.38, longitude:  8.55,   accuracy: 100 },
        "Asia/Tokyo":           { latitude: 35.68, longitude: 139.69,  accuracy: 100 },
        "Asia/Shanghai":        { latitude: 31.23, longitude: 121.47,  accuracy: 100 },
        "Australia/Sydney":     { latitude: -33.86, longitude: 151.20, accuracy: 100 },
      };
      return m[tz] || null;
    })();

    nav.geolocation.getCurrentPosition = function (success, error) {
      if (!personaCoords) {
        if (error) error({ code: 1, message: "User denied Geolocation" });
        return;
      }
      const pos = {
        coords: Object.assign({
          altitude: null, altitudeAccuracy: null, heading: null, speed: null,
        }, personaCoords),
        timestamp: Date.now(),
      };
      if (success) success(pos);
    };
    nav.geolocation.watchPosition = function (success, error) {
      // Fire once like getCurrentPosition; real watchers tick on
      // movement which we can't simulate. Returns 1 as the watch ID.
      nav.geolocation.getCurrentPosition(success, error);
      return 1;
    };
    nav.geolocation.clearWatch = function () {};
    try {
      Object.defineProperty(nav.geolocation.getCurrentPosition, "toString", {
        value: function () { return "function getCurrentPosition() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- Exotic API presence (Gamepad / USB / Serial / Bluetooth / NFC) ----------
  // Real Chrome on a typical desktop returns empty arrays / no
  // available devices. Keep them present (their absence flags Tor
  // Browser specifically) but neutralized.
  try {
    if (nav.getGamepads) {
      nav.getGamepads = function () { return [null, null, null, null]; };
    }
    if (nav.usb && nav.usb.getDevices) {
      nav.usb.getDevices = function () { return Promise.resolve([]); };
    }
    if (nav.serial && nav.serial.getPorts) {
      nav.serial.getPorts = function () { return Promise.resolve([]); };
    }
    if (nav.hid && nav.hid.getDevices) {
      nav.hid.getDevices = function () { return Promise.resolve([]); };
    }
    if (nav.bluetooth && nav.bluetooth.getDevices) {
      nav.bluetooth.getDevices = function () { return Promise.resolve([]); };
    }
  } catch (_) {}

  // ---------- WebGPU ----------
  // Newer Chromium exposes navigator.gpu. Real-device GPU adapter
  // info reveals the actual GPU. If persona claims Chrome, hide the
  // adapter info; if the actual browser doesn't have it, leave alone.
  if (nav.gpu && nav.gpu.requestAdapter) {
    const origReq = nav.gpu.requestAdapter.bind(nav.gpu);
    nav.gpu.requestAdapter = function () {
      // Pretend WebGPU adapter is unavailable. Most pages fall back
      // to WebGL, which we DO mediate.
      return Promise.resolve(null);
    };
    try {
      Object.defineProperty(nav.gpu.requestAdapter, "toString", {
        value: function () { return "function requestAdapter() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- Notifications API behavior ----------
  // Notification.permission default differs slightly Chrome vs
  // Firefox. Force "default" (matches both browsers' first-load
  // state) so behavior is deterministic per-persona.
  if (typeof Notification !== "undefined") {
    try {
      Object.defineProperty(Notification, "permission", {
        get: nativeGet("default"), configurable: true,
      });
    } catch (_) {}
  }

  // ---------- WebRTC SDP filter ----------
  // RTCPeerConnection.setLocalDescription / addIceCandidate emit SDP
  // that contains local IP candidates (typed-array of mDNS hostnames
  // unless --disable-features=WebRtcHideLocalIpsWithMdns is off). We
  // already pass that disable flag at launch. Belt-and-suspenders:
  // wrap createOffer to scrub host candidates from generated SDP.
  if (typeof RTCPeerConnection !== "undefined") {
    const origCreateOffer = RTCPeerConnection.prototype.createOffer;
    RTCPeerConnection.prototype.createOffer = function () {
      return origCreateOffer.apply(this, arguments).then(function (offer) {
        if (offer && offer.sdp) {
          // Strip "host" candidate lines (local IPs) — keep srflx / relay.
          offer.sdp = offer.sdp.replace(/a=candidate:.+typ host.+\r\n/g, "");
        }
        return offer;
      });
    };
    try {
      Object.defineProperty(RTCPeerConnection.prototype.createOffer, "toString", {
        value: function () { return "function createOffer() { [native code] }"; },
      });
    } catch (_) {}
  }

  // ---------- Storage quota ----------
  // navigator.storage.estimate() returns {quota, usage}. Real Chrome
  // on a typical desktop returns ~300GB quota. Some bot detectors
  // call this and check for "headless" anomalies (low quota = small
  // disk / VM). Force a typical value.
  if (nav.storage && nav.storage.estimate) {
    nav.storage.estimate = function () {
      return Promise.resolve({
        quota: 296352743424, // ~275 GiB — typical desktop
        usage: 0,
        usageDetails: {},
      });
    };
  }

  // Done — see docs/fingerprint-coverage.md for the full coverage
  // matrix. tlsmitm + uTLS handles L4/L7 (TLS handshake + HTTP
  // headers); this extension covers the JS / DOM / canvas / audio
  // surface.
})();
