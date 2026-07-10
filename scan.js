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
    directText,
    snippet,
    colorFor,
    highlightElement,
    drawMarker,
  } = globalThis.__PIScannerHelpers;

  // Record original values so clearMarks can restore them. Never changes text color.
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
    if (Object.keys(savedOverrides).length)
      el.dataset.piscanSaved = JSON.stringify(savedOverrides);
  }

  function runScan() {
    const roots = collectRoots(document);
    roots.forEach((root) => clearMarks(root));

    const items = [];
    let nextElementId = 1;
    const elementById = new Map();

    for (const root of roots) {
      const scope = root.nodeType === Node.DOCUMENT_NODE ? root.body : root;
      if (!scope) continue;

      // Pass 1 — also walks comments (SHOW_COMMENT): injected instructions in
      // <!-- --> never render but an LLM sees them.
      // A ShadowRoot has no createTreeWalker of its own, so use its
      // ownerDocument; a plain Document's ownerDocument is null, hence `|| root`.
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
          highlightElement(el, worst);
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
          highlightElement(el, sev);
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

      // Pass 3: attribute-based text — aria-label, title (never rendered as page text).
      const ATTR_NAMES = ["aria-label", "title"];
      scope.querySelectorAll("*").forEach((el) => {
        if (SKIP_TAGS.has(el.tagName)) return;
        for (const attrName of ATTR_NAMES) {
          const val = el.getAttribute(attrName);
          if (!val || val.length < 20) continue;
          const findings = S.scanText(val);
          if (!findings.length) continue;
          const worst = S.worstSeverity(findings);
          if (!el.dataset.piscanId) el.dataset.piscanId = `pi-${nextElementId++}`;
          elementById.set(el.dataset.piscanId, el);
          highlightElement(el, worst);
          for (const f of findings)
            items.push({
              ...f,
              context: snippet(`[${attrName}] ${val}`),
              targetId: el.dataset.piscanId,
              attrName,
            });
        }
      });
    }

    // full = dedup key (type+signal+context), group = fold key (type+signal only).
    // Don't drop context from the dedup key: it was tried and reverted (silently
    // merged genuinely distinct findings, broke shadow-DOM e2e; see
    // docs/plans/2026-07-07-false-positive-fatigue.md, Task 4). groupKey is
    // presentation-only — popup.js uses it to fold near-dup clusters at render.
    function findingIdentityKey(item) {
      const signal = item.attrName ? `${item.type}:${item.attrName}` : item.type;
      const fingerprint =
        item.type === "instruction-phrase" || item.type === "control-token"
          ? item.pattern
          : item.type === "invisible" || item.type === "unicode-tag"
            ? item.hex
            : item.type === "css-hidden"
              ? item.reasons.join(",")
              : (item.decoded ?? "");
      return {
        full: `${signal}:${fingerprint}:${item.context}`,
        group: `${signal}:${fingerprint}`,
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

    const markerByEl = new Map();
    for (const item of capped) {
      for (const id of item.targetIds && item.targetIds.length
        ? item.targetIds
        : [item.targetId]) {
        if (!id || !elementById.has(id)) continue;
        const m = markerByEl.get(id);
        if (m) {
          m.severity = S.worstSeverity([{ severity: m.severity }, item]);
          m.indices.push(item.index);
        } else {
          markerByEl.set(id, {
            el: elementById.get(id),
            severity: item.severity,
            indices: [item.index],
          });
        }
      }
    }
    for (const [id, m] of markerByEl)
      drawMarker(m.el, colorFor(m.severity), m.severity, m.indices, id);

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
