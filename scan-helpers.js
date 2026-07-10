(function () {
  "use strict";

  const MARK_ATTR = "data-piscan-mark";
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);

  // Recursively collect every Document/ShadowRoot reachable from `root`:
  // open shadow roots (element.shadowRoot) and same-origin iframe documents
  // (iframe.contentDocument), nested arbitrarily deep. Closed shadow roots
  // and cross-origin iframes are unreachable by design (spec / same-origin
  // policy respectively) and are silently skipped rather than throwing.
  function collectRoots(root, acc) {
    acc = acc || [];
    acc.push(root);
    const scope = root.nodeType === Node.DOCUMENT_NODE ? root.body : root;
    if (!scope) return acc;
    scope.querySelectorAll("*").forEach((el) => {
      if (el.shadowRoot) collectRoots(el.shadowRoot, acc);
      if (el.tagName === "IFRAME") {
        let doc = null;
        try {
          doc = el.contentDocument;
        } catch {
          doc = null;
        }
        if (doc && doc.body) collectRoots(doc, acc);
      }
    });
    return acc;
  }

  // Find the first element matching `selector` across `root` and every
  // shadow root / same-origin iframe document reachable from it. Needed to
  // re-locate an element by data-piscan-id from a later, separate
  // executeScript call (popup.js's scrollTo), where a plain
  // document.querySelector can't see past a shadow or frame boundary.
  function deepQuerySelector(root, selector) {
    for (const r of collectRoots(root)) {
      const found = r.querySelector(selector);
      if (found) return found;
    }
    return null;
  }

  function clearMarks(root) {
    root = root || document;
    root.querySelectorAll(`[${MARK_ATTR}]`).forEach((el) => {
      try {
        const saved = JSON.parse(el.dataset.piscanSaved || "{}");
        for (const [prop, val] of Object.entries(saved)) el.style[prop] = val;
      } catch {
        // ignore malformed saved data
      }
      el.removeAttribute("data-piscan-saved");
      el.removeAttribute("data-piscan-id");
      el.removeAttribute(MARK_ATTR);
    });
    root.querySelectorAll(".piscan-candle").forEach((n) => n.remove());
    root.querySelectorAll(".piscan-badge").forEach((n) => n.remove());
  }

  // Like el.parentElement, but continues through a shadow-root boundary into
  // the shadow host instead of stopping at null — needed so ancestor walks
  // (resolveBackgroundColor) don't cut short for elements inside a shadow
  // root and wrongly fall back to the top document's background.
  function parentOrHost(node) {
    if (node.parentElement) return node.parentElement;
    const root = node.getRootNode();
    return root instanceof ShadowRoot ? root.host : null;
  }

  // Check if a background-color string represents a fully transparent color.
  // Handles the standard "rgba(0, 0, 0, 0)", spaces/no-spaces formats,
  // "transparent" keyword, CSS Color 4 modern "rgb(0 0 0 / 0)" syntax,
  // decimal alpha, and null/undefined/empty.
  function isTransparentBg(bg) {
    if (!bg) return true;
    const s = bg.replace(/\s+/g, " ").toLowerCase().trim();
    if (s === "transparent") return true;
    const m = s.match(/^rgba?\(([^)]+)\)$/);
    if (!m) return false;
    const args = m[1].trim();
    // Modern CSS Color 4 syntax: "r g b / a" or "r g b"
    if (args.includes("/")) {
      const sides = args.split("/").map((p) => p.trim());
      const rgb = sides[0].split(/\s+/).map((n) => parseInt(n, 10));
      if (rgb.length < 3) return false;
      if (rgb[0] !== 0 || rgb[1] !== 0 || rgb[2] !== 0) return false;
      return sides.length >= 2 && parseFloat(sides[1]) === 0;
    }
    // Legacy comma syntax: "r, g, b, a" or "r, g, b"
    const legacy = args.split(",").map((p) => p.trim());
    if (legacy.length < 3) return false;
    if (
      parseInt(legacy[0], 10) !== 0 ||
      parseInt(legacy[1], 10) !== 0 ||
      parseInt(legacy[2], 10) !== 0
    )
      return false;
    if (legacy.length < 4) return false;
    return parseFloat(legacy[3]) === 0;
  }

  // Resolve the effective background color of an element: walk up the
  // ancestor chain (through shadow-root boundaries) while the computed
  // background is transparent, then fall back to <body>, then <html>, then
  // white. Shared between elementHidesText (below) and scan.js's
  // makeHighlightVisible, which both need to know what an element visually
  // sits on top of. `ownBg` is passed in rather than recomputed here since
  // callers already have a getComputedStyle(el) result for other
  // properties, and this runs per-element across a full-page walk. Uses
  // el.ownerDocument rather than the module-level `document`/
  // `getComputedStyle` because `el` may belong to a same-origin iframe's
  // document rather than the top one this script was injected into.
  function resolveBackgroundColor(el, ownBg) {
    const ownerDoc = el.ownerDocument;
    const view = ownerDoc.defaultView;
    let bg = ownBg;
    if (isTransparentBg(bg)) {
      let p = parentOrHost(el);
      while (p && p !== ownerDoc.documentElement) {
        const pBg = p.ownerDocument.defaultView.getComputedStyle(p).backgroundColor;
        if (!isTransparentBg(pBg)) {
          bg = pBg;
          break;
        }
        p = parentOrHost(p);
      }
    }
    if (isTransparentBg(bg) && ownerDoc.body)
      bg = view.getComputedStyle(ownerDoc.body).backgroundColor;
    if (isTransparentBg(bg) && ownerDoc.documentElement)
      bg = view.getComputedStyle(ownerDoc.documentElement).backgroundColor;
    if (isTransparentBg(bg)) bg = "rgb(255, 255, 255)";
    return bg;
  }

  // Common screen-reader-only class names across major frameworks (Bootstrap
  // & Tailwind: sr-only, WordPress: screen-reader-text, various: visually-hidden,
  // offscreen). Not exhaustive — CSS-module/hashed class names and other
  // conventions won't match — this is a best-effort severity signal, not a
  // detection boundary (unlike the original approach that fully suppressed
  // these; see docs/plans/2026-07-07-false-positive-fatigue.md for why).
  const A11Y_HIDDEN_CLASSES = [
    "sr-only",
    "visually-hidden",
    "offscreen",
    "screen-reader-text",
  ];

  function elementIsA11yHidden(el) {
    if (el.getAttribute("aria-hidden") === "true") return true;
    return A11Y_HIDDEN_CLASSES.some((c) => el.classList.contains(c));
  }

  function elementHidesText(el) {
    const cs = el.ownerDocument.defaultView.getComputedStyle(el);
    const reasons = [];
    const fontPx = parseFloat(cs.fontSize);
    if (fontPx <= 1) reasons.push("font-size " + cs.fontSize);
    if (cs.opacity !== "" && parseFloat(cs.opacity) === 0) reasons.push("opacity:0");
    const left = parseFloat(cs.left);
    const top = parseFloat(cs.top);
    if (cs.position === "absolute" && (left < -1000 || top < -1000))
      reasons.push("off-screen position");
    if (parseFloat(cs.textIndent) < -1000) reasons.push("negative text-indent");
    const bg = resolveBackgroundColor(el, cs.backgroundColor);
    if (!isTransparentBg(bg)) {
      const tl = luminance(cs.color),
        bl = luminance(bg);
      if (Math.abs(tl - bl) < 30) reasons.push("text color = background");
    }
    return reasons;
  }

  function luminance(str) {
    const m = str.match(/(\d+)/g);
    if (!m || m.length < 3) return 0;
    return 0.299 * +m[0] + 0.587 * +m[1] + 0.114 * +m[2];
  }

  function highlightElement(el, color, severity) {
    el.setAttribute(MARK_ATTR, severity || "");
    const icon = el.ownerDocument.createElement("span");
    icon.className = "piscan-candle";
    icon.textContent = "\ud83d\udd6f";
    icon.style.cssText = `color:${color};font-size:16px;margin:0 2px 0 0;cursor:help;vertical-align:middle;`;
    icon.title = (severity || "") + " severity finding";
    el.insertBefore(icon, el.firstChild);
  }

  function directText(el) {
    let t = "";
    for (const n of el.childNodes) if (n.nodeType === Node.TEXT_NODE) t += n.nodeValue;
    return t.trim();
  }

  function snippet(s) {
    const clean = s.replace(/\s+/g, " ").trim();
    return clean.length > 90 ? clean.slice(0, 90) + "\u2026" : clean;
  }

  function colorFor(sev) {
    return sev === "high" ? "#e5484d" : sev === "medium" ? "#f5a623" : "#3b82f6";
  }

  const Helpers = {
    MARK_ATTR,
    SKIP_TAGS,
    collectRoots,
    deepQuerySelector,
    clearMarks,
    elementHidesText,
    elementIsA11yHidden,
    isTransparentBg,
    luminance,
    resolveBackgroundColor,
    highlightElement,
    directText,
    snippet,
    colorFor,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = Helpers;
  if (typeof globalThis !== "undefined") globalThis.__PIScannerHelpers = Helpers;
})();
