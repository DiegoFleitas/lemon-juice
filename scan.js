/**
 * scan.js — the DOM side. Injected AFTER detectors.js AND scan-helpers.js,
 * so both PIScanner and __PIScannerHelpers exist.
 *
 * Injection order matters: popup.js runs
 *   scripting.executeScript({ files: ["detectors.js", "scan-helpers.js", "scan.js"] })
 * then reads back window.__PIScanResult with a tiny follow-up call.
 */
(function () {
  "use strict";

  const S = globalThis.PIScanner;
  const {
    MARK_ATTR,
    SKIP_TAGS,
    collectRoots,
    clearMarks,
    elementHidesText,
    elementIsA11yHidden,
    isTransparentBg,
    directText,
    snippet,
    colorFor,
    highlightElement,
    luminance,
    resolveBackgroundColor,
  } = globalThis.__PIScannerHelpers;

  function contrastingColor(bg) {
    return luminance(bg) > 128 ? "#000000" : "#ffffff";
  }

  function makeHighlightVisible(el) {
    const savedOverrides = {};
    const cs = el.ownerDocument.defaultView.getComputedStyle(el);
    if (parseFloat(cs.fontSize) <= 1) {
      savedOverrides.fontSize = el.style.fontSize || "";
      el.style.fontSize = "16px";
    }
    if (cs.opacity !== "" && parseFloat(cs.opacity) === 0) {
      savedOverrides.opacity = el.style.opacity || "";
      el.style.opacity = "0.5";
    }
    const left = parseFloat(cs.left);
    const top = parseFloat(cs.top);
    if (cs.position === "absolute" && (left < -1000 || top < -1000)) {
      savedOverrides.position = el.style.position || "";
      savedOverrides.left = el.style.left || "";
      savedOverrides.top = el.style.top || "";
      el.style.position = "static";
      el.style.left = "auto";
      el.style.top = "auto";
    }
    if (parseFloat(cs.textIndent) < -1000) {
      savedOverrides.textIndent = el.style.textIndent || "";
      el.style.textIndent = "0";
    }
    const bg = resolveBackgroundColor(el, cs.backgroundColor);
    if (!isTransparentBg(bg)) {
      const tl = luminance(cs.color),
        bl = luminance(bg);
      if (Math.abs(tl - bl) < 30) {
        savedOverrides.color = el.style.color || "";
        el.style.color = contrastingColor(bg);
      }
    }
    if (Object.keys(savedOverrides).length)
      el.dataset.piscanSaved = JSON.stringify(savedOverrides);
  }

  function runScan() {
    // Every Document/ShadowRoot reachable from the top document: itself,
    // any open shadow roots (nested arbitrarily deep), and any same-origin
    // iframe documents (ditto). Closed shadow roots and cross-origin
    // iframes can't be reached and are silently skipped by collectRoots.
    const roots = collectRoots(document);
    roots.forEach((root) => clearMarks(root));

    const items = [];
    let nextElementId = 1;
    const elementById = new Map();

    for (const root of roots) {
      const scope = root.nodeType === Node.DOCUMENT_NODE ? root.body : root;
      if (!scope) continue;

      // Pass 1: invisible/encoded/instruction findings in text nodes.
      // A ShadowRoot has no createTreeWalker of its own, so use its
      // ownerDocument (a plain Document's ownerDocument is always null,
      // hence the `|| root` fallback) — and root itself as the walker's
      // root node, since `scope` for a ShadowRoot is the root itself.
      // SHOW_COMMENT alongside SHOW_TEXT: an injected instruction hidden in
      // an HTML comment (`<!-- ignore all previous instructions -->`) never
      // renders, but an LLM ingesting the page's raw HTML/DOM still sees it —
      // Comment nodes expose the same `.nodeValue`/`.parentElement` shape as
      // Text nodes, so the rest of this loop handles both without change.
      const walker = (root.ownerDocument || root).createTreeWalker(
        scope,
        NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT,
        {
          acceptNode(node) {
            if (!node.nodeValue || !node.nodeValue.trim())
              return NodeFilter.FILTER_REJECT;
            if (node.parentElement && SKIP_TAGS.has(node.parentElement.tagName))
              return NodeFilter.FILTER_REJECT;
            return NodeFilter.FILTER_ACCEPT;
          },
        }
      );
      let node;
      while ((node = walker.nextNode())) {
        const findings = S.scanText(node.nodeValue);
        if (!findings.length) continue;
        const worst = S.worstSeverity(findings);
        if (node.parentElement) {
          const el = node.parentElement;
          if (!el.dataset.piscanId) el.dataset.piscanId = `pi-${nextElementId++}`;
          elementById.set(el.dataset.piscanId, el);
          highlightElement(el, colorFor(worst), worst);
          makeHighlightVisible(el);
        }
        const inComment = node.nodeType === Node.COMMENT_NODE;
        for (const f of findings)
          items.push({
            ...f,
            context: snippet(node.nodeValue),
            targetId: node.parentElement?.dataset.piscanId,
            ...(inComment ? { inComment: true } : {}),
          });
      }

      // Pass 2: elements whose text is visually hidden by CSS.
      scope.querySelectorAll("*").forEach((el) => {
        if (SKIP_TAGS.has(el.tagName)) return;
        // Skip our own decoration nodes: Pass 1 injects .piscan-candle spans
        // before this querySelectorAll runs, and their glyph counts as
        // directText, so without this guard Pass 2 re-flags them (candle color
        // ≈ background), nesting a mark inside a mark.
        if (
          el.classList.contains("piscan-candle") ||
          el.classList.contains("piscan-badge")
        )
          return;
        const ownText = directText(el);
        if (!ownText) return;
        const reasons = elementHidesText(el);
        if (reasons.length) {
          const isA11yMarked = elementIsA11yHidden(el);
          const baseSev = isA11yMarked ? "low" : "medium";
          // Respect existing mark from Pass 1: don't downgrade the outline color.
          const existingSev = el.getAttribute(MARK_ATTR);
          const sev = existingSev
            ? S.worstSeverity([{ severity: existingSev }, { severity: baseSev }])
            : baseSev;
          if (!el.dataset.piscanId) el.dataset.piscanId = `pi-${nextElementId++}`;
          elementById.set(el.dataset.piscanId, el);
          highlightElement(el, colorFor(sev), sev);
          makeHighlightVisible(el);
          items.push({
            type: "css-hidden",
            severity: baseSev,
            reasons,
            ...(isA11yMarked ? { likelyA11y: true } : {}),
            context: snippet(ownText),
            targetId: el.dataset.piscanId,
          });
        }
      });
    }

    // Dedup: findings with the same type + signal + surrounding text are the
    // same content repeated across elements (e.g. a nav item in 5 <li>s) —
    // collapse them in the list, but keep every occurrence highlighted on
    // the page and record how many there were so a collapsed entry doesn't
    // read as if it's the only occurrence.
    //
    // Also returns `group`: the same type+fingerprint identity but WITHOUT
    // context, exposed on surviving items as `groupKey` purely for popup.js
    // to fold large clusters of near-duplicates (e.g. the same invisible
    // character scattered across many unrelated paragraphs) into one row at
    // render time. This is deliberately NOT used for the dedup decision
    // itself — dropping context from the actual dedup key was tried and
    // reverted (see docs/plans/2026-07-07-false-positive-fatigue.md, Task 4
    // background): it silently merged genuinely distinct findings that only
    // shared a code point/pattern, breaking shadow-DOM/many-findings e2e
    // coverage. `groupKey` lets popup.js apply that same collapsing idea as
    // a presentation-only, volume-gated choice instead.
    function findingIdentityKey(item) {
      const fingerprint =
        item.type === "instruction-phrase" || item.type === "control-token"
          ? item.pattern
          : item.type === "invisible" || item.type === "unicode-tag"
            ? item.hex
            : item.type === "css-hidden"
              ? item.reasons.join(",")
              : (item.decoded ?? "");
      return {
        full: `${item.type}:${fingerprint}:${item.context}`,
        group: `${item.type}:${fingerprint}`,
      };
    }
    const seenItems = new Map();
    const deduped = [];
    for (const item of items) {
      const { full: key, group } = findingIdentityKey(item);
      const existing = seenItems.get(key);
      if (existing) {
        existing.matchCount = (existing.matchCount || 1) + 1;
        if (item.targetId) existing.targetIds.push(item.targetId);
      } else {
        item.targetIds = item.targetId ? [item.targetId] : [];
        item.groupKey = group;
        seenItems.set(key, item);
        deduped.push(item);
      }
    }
    items.splice(0, items.length, ...deduped);

    const SEV_ORDER = { high: 0, medium: 1, low: 2 };
    items.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    items.forEach((item, i) => (item.index = i + 1));

    const MAX_ITEMS = 200;
    const capped = items.slice(0, MAX_ITEMS);

    // Add numbered badges on elements — supports multiple elements per
    // item after dedup (targetIds from the dedup loop, or targetId fallback
    // for items that predate the dedup change).
    for (let i = capped.length - 1; i >= 0; i--) {
      const item = capped[i];
      for (const id of item.targetIds && item.targetIds.length
        ? item.targetIds
        : [item.targetId]) {
        if (!id) continue;
        const el = elementById.get(id);
        if (!el) continue;
        const badge = el.ownerDocument.createElement("sup");
        badge.className = "piscan-badge";
        badge.textContent = item.index;
        badge.style.cssText = "color:#000;font-size:10px;margin:0 1px;";
        el.insertBefore(badge, el.firstChild);
      }
    }

    const summary = {
      url: location.href,
      count: capped.length,
      worst: S.worstSeverity(capped),
      bySeverity: {
        high: capped.filter((i) => i.severity === "high").length,
        medium: capped.filter((i) => i.severity === "medium").length,
        low: capped.filter((i) => i.severity === "low").length,
      },
      items: capped,
    };
    window.__PIScanResult = summary;
    return summary;
  }

  runScan();
})();
