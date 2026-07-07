(function () {
  "use strict";

  const MARK_ATTR = "data-piscan-mark";
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);

  function clearMarks() {
    document.querySelectorAll(`[${MARK_ATTR}]`).forEach((el) => {
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
    document.querySelectorAll(".piscan-candle").forEach((n) => n.remove());
    document.querySelectorAll(".piscan-badge").forEach((n) => n.remove());
  }

  // Resolve the effective background color of an element: walk up the
  // ancestor chain while the computed background is transparent, then fall
  // back to <body>, then <html>, then white. Shared between elementHidesText
  // (below) and scan.js's makeHighlightVisible, which both need to know what
  // an element visually sits on top of. `ownBg` is passed in rather than
  // recomputed here since callers already have a getComputedStyle(el) result
  // for other properties, and this runs per-element across a full-page walk.
  function resolveBackgroundColor(el, ownBg) {
    let bg = ownBg;
    if (!bg || bg === "rgba(0, 0, 0, 0)") {
      let p = el.parentElement;
      while (p && p !== document.documentElement) {
        const pBg = getComputedStyle(p).backgroundColor;
        if (pBg && pBg !== "rgba(0, 0, 0, 0)") {
          bg = pBg;
          break;
        }
        p = p.parentElement;
      }
    }
    if (!bg || bg === "rgba(0, 0, 0, 0)")
      bg = getComputedStyle(document.body).backgroundColor;
    if (!bg || bg === "rgba(0, 0, 0, 0)")
      bg = getComputedStyle(document.documentElement).backgroundColor;
    if (!bg || bg === "rgba(0, 0, 0, 0)") bg = "rgb(255, 255, 255)";
    return bg;
  }

  function elementHidesText(el) {
    const cs = getComputedStyle(el);
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
    if (bg && bg !== "rgba(0, 0, 0, 0)") {
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
    const icon = document.createElement("span");
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
    clearMarks,
    elementHidesText,
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
