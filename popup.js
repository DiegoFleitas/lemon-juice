// popup.js — Firefox (browser.* promise API).
// activeTab grants us scripting on the current tab the moment the user opens
// this popup, so we need no host permissions in the manifest.

const els = {
  status: document.getElementById("status"),
  list: document.getElementById("list"),
  rescan: document.getElementById("rescan"),
};

// Tracks which collapsed element to scroll to next time a deduped row is
// clicked. Each item gets a cycling index into its targetIds array.
const clickCycles = new Map();

async function activeTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scan() {
  const tab = await activeTab();
  if (!tab || /^(about:|moz-extension:)/.test(tab.url || "")) {
    els.status.textContent = "Can't scan this page.";
    return;
  }
  els.status.textContent = "Scanning…";
  els.list.replaceChildren();

  let result;
  try {
    // 1) Inject the pure detectors, then helpers, then the DOM scanner (order matters).
    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["detectors.js", "scan-helpers.js", "scan.js"],
    });
    // 2) Read back the summary the scanner stashed on window.
    const injected = await browser.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.__PIScanResult || null,
    });
    result = injected[0]?.result;
  } catch {
    // Injection can reject if the tab closed mid-scan, navigated away, or the
    // page/CSP blocks content scripts (e.g. addons.mozilla.org, some PDF
    // viewers) — none of that is this extension's fault, so just say so
    // instead of leaving "Scanning…" stuck with an unhandled rejection.
    els.status.textContent = "Can't scan this page.";
    return;
  }

  render(result);
  setBadge(result, tab.id);
}

async function scrollTo(targetId) {
  const tab = await activeTab();
  if (!tab) return;
  try {
    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      func: (id) => {
        // Search the top document, open shadow roots, and same-origin
        // iframes for a matching data-piscan-id — copies the logic from
        // scan-helpers.js's deepQuerySelector inline rather than relying
        // on globalThis.__PIScannerHelpers, because executeScript func
        // runs in a separate execution environment from file injections.
        function find(root) {
          let found = root.querySelector(`[data-piscan-id="${CSS.escape(id)}"]`);
          if (found) return found;
          const scope = root.nodeType === Node.DOCUMENT_NODE ? root.body : root;
          if (!scope) return null;
          const children = scope.querySelectorAll("*");
          for (let i = 0; i < children.length; i++) {
            const el = children[i];
            if (el.shadowRoot) {
              found = find(el.shadowRoot);
              if (found) return found;
            }
            if (el.tagName === "IFRAME") {
              try {
                if (el.contentDocument && el.contentDocument.body) {
                  found = find(el.contentDocument);
                  if (found) return found;
                }
              } catch {
                // cross-origin — skip
              }
            }
          }
          return null;
        }
        const el = find(document);
        if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
      },
      args: [targetId],
    });
  } catch {
    // tab closed or navigated mid-scroll
  }
}

// Folding threshold for Task 4 (docs/plans/2026-07-07-false-positive-fatigue.md):
// 5+ findings sharing the same type+fingerprint (scan.js's item.groupKey,
// ignoring surrounding context) render as one summary row instead of one
// row each — e.g. the same zero-width space scattered across many unrelated
// paragraphs. Below the threshold, every item still renders individually
// (this is what keeps a handful of genuinely separate occurrences, like the
// shadow-DOM/iframe test fixtures, fully distinguishable).
const FOLD_THRESHOLD = 5;

function typeLabel(item) {
  return item.type === "unicode-tag"
    ? `Invisible ASCII-smuggling character${item.decoded ? ` → decodes to: “${item.decoded}”` : ""}`
    : item.type === "invisible"
      ? `Invisible character: ${item.name} (${item.hex})`
      : item.type === "encoded-base64"
        ? `Encoded blob${item.likelyJwt ? " (looks like a JWT)" : ""} → “${item.decoded}”`
        : item.type === "encoded-percent"
          ? `Percent-encoded blob → “${item.decoded}”`
          : item.type === "encoded-hex-escape"
            ? `Hex-escaped blob → “${item.decoded}”`
            : item.type === "encoded-spaced-hex"
              ? `Space-separated hex byte blob → “${item.decoded}”`
              : item.type === "variation-selector-smuggling"
                ? `Hidden variation-selector payload → “${item.decoded}”`
                : item.type === "sneaky-bits-smuggling"
                  ? `Hidden invisible-bit-encoded payload → “${item.decoded}”`
                  : item.type === "control-token"
                    ? `LLM chat-template control token: “${item.match}”`
                    : item.type === "css-hidden"
                      ? `Visually hidden text (${item.reasons.join(", ")})${item.likelyA11y ? " — looks like accessibility markup, downgraded" : ""}`
                      : item.type === "instruction-phrase"
                        ? `Instruction-like phrase${item.normalized ? " (revealed after removing invisible characters)" : ""}: “${item.match}”`
                        : item.type;
}

// `item` is the representative finding shown (first occurrence for a folded
// group). `ids` lists every targetId this row should cycle through on
// click. `contexts`, when given, is a parallel array of each id's own
// context text: a folded group's members can have genuinely different
// underlying text (e.g. ten separate SEO-stuffed phrases all hidden the
// same way), so the context preview should track whichever occurrence is
// currently selected instead of always showing the first one. Individual
// (non-folded) rows omit this, since every id there already shares
// identical context by construction. `cycleKey` identifies this row in
// `clickCycles`: an item's own index for a normal row, or the shared
// groupKey for a folded row, since a folded row has no single backing
// item.index. `count` is the displayed ×N suffix.
function buildRow(item, { ids, contexts, cycleKey, count }) {
  const row = document.createElement("div");
  row.className = "finding sev-" + item.severity;
  if (item.targetId) row.dataset.targetId = item.targetId;
  const label = `#${item.index || "?"} ${typeLabel(item)}${item.inComment ? " (in an HTML comment)" : ""}${count > 1 ? ` (×${count})` : ""}`;
  const labelEl = document.createElement("div");
  labelEl.className = "label";
  labelEl.textContent = label;
  row.appendChild(labelEl);
  let ctxEl = null;
  if (item.context) {
    ctxEl = document.createElement("div");
    ctxEl.className = "ctx";
    ctxEl.textContent = item.context;
    row.appendChild(ctxEl);
  }
  if (ids.length > 1) {
    // Cycling only helps if you can see which occurrence you just landed
    // on. Without this, a second click on the same row looks like it did
    // nothing.
    const posEl = document.createElement("div");
    posEl.className = "cycle-pos";
    posEl.textContent = `1 of ${ids.length}`;
    row.appendChild(posEl);
    row.addEventListener("click", () => {
      const idx = (clickCycles.get(cycleKey) || 0) % ids.length;
      clickCycles.set(cycleKey, idx + 1);
      posEl.textContent = `${idx + 1} of ${ids.length}`;
      if (ctxEl && contexts && contexts[idx]) ctxEl.textContent = contexts[idx];
      scrollTo(ids[idx]);
    });
  } else if (ids.length === 1) {
    row.addEventListener("click", () => scrollTo(ids[0]));
  }
  return row;
}

function render(r) {
  // Findings are freshly rebuilt on every scan, so any cycling position from
  // a previous render is stale — a numeric index could otherwise silently
  // apply to an unrelated item in the new render (indices are per-render
  // slot numbers, not stable identities), and never clearing this also grew
  // unboundedly across repeated re-scans.
  clickCycles.clear();
  if (!r || r.count === 0) {
    els.status.textContent = "No hidden content or injection markers found.";
    return;
  }
  const parts = [];
  if (r.bySeverity.high) parts.push(`${r.bySeverity.high} high`);
  if (r.bySeverity.medium) parts.push(`${r.bySeverity.medium} medium`);
  if (r.bySeverity.low) parts.push(`${r.bySeverity.low} low`);
  els.status.textContent = `${r.count} finding${r.count === 1 ? "" : "s"}: ${parts.join(", ")}`;

  const groups = new Map(); // groupKey -> item[]
  for (const item of r.items) {
    if (!item.groupKey) continue;
    const arr = groups.get(item.groupKey) || [];
    arr.push(item);
    groups.set(item.groupKey, arr);
  }

  const renderedGroups = new Set();
  for (const item of r.items) {
    const group = item.groupKey ? groups.get(item.groupKey) : null;
    if (group && group.length >= FOLD_THRESHOLD) {
      if (renderedGroups.has(item.groupKey)) continue; // one row per folded group
      renderedGroups.add(item.groupKey);
      const ids = [];
      const contexts = [];
      let count = 0;
      for (const g of group) {
        count += g.matchCount || 1;
        const gIds = g.targetIds?.length ? g.targetIds : g.targetId ? [g.targetId] : [];
        for (const id of gIds) {
          ids.push(id);
          contexts.push(g.context);
        }
      }
      els.list.appendChild(
        buildRow(group[0], { ids, contexts, cycleKey: item.groupKey, count })
      );
    } else {
      const ids = item.targetIds?.length
        ? item.targetIds
        : item.targetId
          ? [item.targetId]
          : [];
      els.list.appendChild(
        buildRow(item, { ids, cycleKey: item.index, count: item.matchCount || 1 })
      );
    }
  }
}

function setBadge(r, tabId) {
  const worst = r && r.worst;
  const concerning = r ? r.bySeverity.high + r.bySeverity.medium : 0;
  const text = concerning ? String(concerning) : "";
  const color = worst === "high" ? "#e5484d" : worst === "medium" ? "#f5a623" : "#3b82f6";
  browser.action.setBadgeText({ text, tabId });
  browser.action.setBadgeBackgroundColor({ color, tabId });
}

els.rescan.addEventListener("click", scan);
scan();
