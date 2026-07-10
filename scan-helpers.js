(function () {
  "use strict";

  const MARK_ATTR = "data-piscan-mark";
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);

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

  // Walk ancestor chain for a real background. Returns null when nothing paints
  // (don't guess Canvas — see docs/plans). `ownBg` passed in since callers
  // already have it; uses el.ownerDocument for iframe support.
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

  // Best-effort, not exhaustive — see docs/plans for why we don't fully suppress.
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
    const t = cs.transform;
    if (t && t !== "none") {
      const m = t.match(/matrix(3d)?\(([^)]+)\)/);
      if (m) {
        const is3d = !!m[1];
        const nums = m[2].split(",").map(Number);
        const tx = is3d ? nums[12] : nums[4];
        const ty = is3d ? nums[13] : nums[5];
        const sx = nums[0];
        const sy = is3d ? nums[5] : nums[3];
        if (tx < -9000 || ty < -9000) reasons.push("transform off-screen");
        if (sx === 0 || sy === 0) reasons.push("transform scale(0)");
      }
    }
    const cp = cs.clipPath;
    if (cp && cp !== "none") {
      if (/^circle\(\s*0(px|%)?\s*(at|\))/i.test(cp) || /^inset\(\s*(50%|100%)/i.test(cp))
        reasons.push("clip-path hides content");
    }
    // Legacy `clip: rect(...)` — not a clip-path value, but still hides text.
    if (cs.clip && cs.clip !== "auto" && /^rect\(\s*0(?:px)?\b/g.test(cs.clip))
      reasons.push("clip hides content");
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

  function highlightElement(el, severity) {
    el.setAttribute(MARK_ATTR, severity || "");
  }

  const OVERLAY_CLASS = "piscan-overlay";

  // One overlay per Document (top doc + each iframe). Shadow-DOM elements
  // share their host's overlay. pointer-events:none so clicks pass through.
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
