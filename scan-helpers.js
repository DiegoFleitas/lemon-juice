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
    // Markers live in a single overlay layer, not inline in page elements —
    // removing the overlay tears down every candle/badge/box at once.
    root.querySelectorAll("." + OVERLAY_CLASS).forEach((n) => n.remove());
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

  function isTransparentBg(bg) {
    if (!bg) return true;
    const s = bg.replace(/\s+/g, "").toLowerCase();
    return /^(?:rgba\(0,0,0,0(?:\.0+)?\)|rgba?\(000\/0(?:\.0+)?\)|transparent)$/.test(s);
  }

  // Resolve the effective background color an element visually sits on top of:
  // walk up the ancestor chain (through shadow-root boundaries) while the
  // computed background is transparent, then fall back to <body>, then <html>.
  // Returns null when nothing in that chain paints a real background — i.e.
  // when the only thing behind the text is the browser's viewport canvas.
  // We deliberately do NOT probe the system `Canvas` keyword here: it reflects
  // the *browser* theme, not what the page actually paints, so an app that
  // self-themes dark on a light-mode browser (Notion, etc.) would report a
  // white canvas behind its own white-on-dark text and trip a false
  // "text color = background" match (see docs/plans, dark-page FP fix).
  // Callers must treat null as "background unknown" rather than guessing.
  //
  // `ownBg` is passed in rather than recomputed here since callers already
  // have a getComputedStyle(el) result for other properties, and this runs
  // per-element across a full-page walk. Uses el.ownerDocument rather than the
  // module-level `document`/`getComputedStyle` because `el` may belong to a
  // same-origin iframe's document rather than the top one this script was
  // injected into.
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
    return isTransparentBg(bg) ? null : bg;
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
    // Only compare against a real, resolved background. resolveBackgroundColor
    // returns null when nothing paints behind the text (only the browser
    // canvas would) — we can't claim text ≈ background without knowing the
    // background, and guessing the canvas color false-positives on
    // self-themed dark pages viewed in a light-mode browser.
    const bg = resolveBackgroundColor(el, cs.backgroundColor);
    if (bg) {
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

  // Record a finding on an element WITHOUT touching its rendered box: only the
  // invisible MARK_ATTR is set (used by clearMarks and the Pass-2 severity
  // check). The visible candle/badge/outline is drawn separately into an
  // overlay layer by drawMarker, so marking never reflows or restyles the page.
  function highlightElement(el, severity) {
    el.setAttribute(MARK_ATTR, severity || "");
  }

  const OVERLAY_CLASS = "piscan-overlay";

  // Get (or lazily create) the single absolutely-positioned overlay layer for
  // `ownerDoc`. One per real Document (top document + each same-origin iframe);
  // shadow-DOM elements share their host document's coordinate space, so they
  // are covered by the host document's overlay. pointer-events:none lets clicks
  // fall through to the page.
  function getOverlay(ownerDoc) {
    let overlay = ownerDoc.querySelector("." + OVERLAY_CLASS);
    if (!overlay) {
      overlay = ownerDoc.createElement("div");
      overlay.className = OVERLAY_CLASS;
      overlay.style.cssText =
        "position:absolute;left:0;top:0;width:0;height:0;margin:0;padding:0;" +
        "border:0;pointer-events:none;z-index:2147483647;";
      ownerDoc.body.appendChild(overlay);
    }
    return overlay;
  }

  // Draw a non-invasive marker for one element: a severity-colored outline box
  // sized to the element's rect, plus a corner chip holding the candle glyph
  // and a numbered badge per finding on that element (`indices`). Positioned in
  // document coordinates (rect + scroll) so it stays aligned as the page
  // scrolls. `targetId` is stamped as data-piscan-for on the box, chip, and
  // each badge so popup/tests can associate a marker with its element.
  function drawMarker(el, color, severity, indices, targetId) {
    const ownerDoc = el.ownerDocument;
    const view = ownerDoc.defaultView;
    const rect = el.getBoundingClientRect();
    const left = rect.left + view.scrollX;
    const top = rect.top + view.scrollY;
    const overlay = getOverlay(ownerDoc);

    const box = ownerDoc.createElement("div");
    box.className = "piscan-mark-box";
    if (targetId) box.setAttribute("data-piscan-for", targetId);
    box.style.cssText =
      `position:absolute;left:${left}px;top:${top}px;` +
      `width:${Math.max(rect.width, 8)}px;height:${Math.max(rect.height, 8)}px;` +
      `box-sizing:border-box;outline:2px solid ${color};pointer-events:none;`;

    const chip = ownerDoc.createElement("span");
    chip.className = "piscan-candle";
    if (targetId) chip.setAttribute("data-piscan-for", targetId);
    chip.title = (severity || "") + " severity finding";
    chip.style.cssText =
      `position:absolute;left:0;top:0;transform:translateY(-100%);` +
      `display:inline-flex;align-items:center;gap:2px;color:${color};` +
      `font:600 11px/1.2 system-ui,sans-serif;background:rgba(0,0,0,.6);` +
      `padding:0 3px;border-radius:2px;white-space:nowrap;`;

    const glyph = ownerDoc.createElement("span");
    glyph.textContent = "\ud83d\udd6f";
    glyph.style.cssText = "font-size:12px;";
    chip.appendChild(glyph);

    for (const index of indices) {
      const badge = ownerDoc.createElement("span");
      badge.className = "piscan-badge";
      if (targetId) badge.setAttribute("data-piscan-for", targetId);
      badge.textContent = index;
      chip.appendChild(badge);
    }

    box.appendChild(chip);
    overlay.appendChild(box);
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
    drawMarker,
    directText,
    snippet,
    colorFor,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = Helpers;
  if (typeof globalThis !== "undefined") globalThis.__PIScannerHelpers = Helpers;
})();
