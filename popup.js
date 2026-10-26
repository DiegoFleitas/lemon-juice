// popup.js — Firefox (browser.*) and Chrome (chrome.*); both expose
// promise-returning MV3 APIs, so one namespace shim covers both browsers.
// activeTab grants us scripting on the current tab the moment the user opens
// this popup, so we need no host permissions in the manifest.

const api = globalThis.browser ?? globalThis.chrome;

const els = {
  status: document.getElementById("status"),
  list: document.getElementById("list"),
  rescan: document.getElementById("rescan"),
  exportJson: document.getElementById("export-json"),
  exportTxt: document.getElementById("export-txt"),
};

// Latest scan, kept only so the export buttons can serialize what is on screen.
let latestResult = null;
let latestTab = null;

function setExportEnabled(enabled) {
  els.exportJson.disabled = !enabled;
  els.exportTxt.disabled = !enabled;
}

// Tracks which collapsed element to scroll to next time a deduped row is
// clicked. Each item gets a cycling index into its targetIds array.
const clickCycles = new Map();

// Mirrors scan.js's cap so a merged multi-frame page cannot post more work to
// the popup than a single-frame one.
const MAX_ITEMS = 200;
const SEV_ORDER = { high: 0, medium: 1, low: 2 };

// --- per-frame aggregation -------------------------------------------------
// A popup page script cannot import detectors.js, so the page-verdict rules are
// reimplemented here for the merged (multi-frame) item list. This duplication is
// deliberate and pinned by __tests__/popup.test.js, which runs these against
// PIScanner.pageVerdict/worstSeverity/corroborationCount on the same inputs —
// if the two ever disagree, CI fails instead of the badge silently drifting.
function isCorroborated(item) {
  return !!(item.corroboration?.length || item.contextual?.length);
}

function corroborationCount(items) {
  return items.reduce(
    (n, i) => n + (i.corroboration?.length || 0) + (i.contextual?.length || 0),
    0
  );
}

function pageVerdict(items) {
  if (!items.length) return "clean";
  const corroborated = items.filter(isCorroborated);
  if (corroborated.some((i) => i.severity === "high")) return "likely-injection";
  if (corroborated.length >= 2) return "likely-injection";
  if (corroborated.length) return "suspicious";
  if (items.some((i) => i.severity === "high")) return "suspicious";
  return "noise";
}

function worstSeverity(items) {
  if (items.some((i) => i.severity === "high")) return "high";
  if (items.some((i) => i.severity === "medium")) return "medium";
  return items.length ? "low" : null;
}

function itemTargets(item) {
  if (item.targetIds && item.targetIds.length) return item.targetIds;
  return item.targetId ? [item.targetId] : [];
}

// Combines the per-frame summaries from scripting.executeScript({allFrames}) into
// the single summary shape the rest of this file renders and exports.
//
// Target ids are namespaced per frame ("<frameId>:<data-piscan-id>"): scan.js
// numbers elements from 1 in every frame, so without a frame qualifier two
// frames' findings would both claim "pi-1" and a click could scroll to the wrong
// frame. scrollTo() splits the qualifier back off.
//
// `frames` is [{ frameId, result }] as returned by the browser; entries whose
// result is null (a frame the scanner could not run in, e.g. about:blank or a
// frame Chrome's activeTab cannot reach) are skipped.
function mergeFrameResults(frames) {
  const present = (frames || []).filter((f) => f && f.result);
  // Frame 0 is the top document, which is where the page-level metadata and the
  // URL come from. Without it (impossible in practice) fall back to whatever
  // frame reported first rather than dropping the URL entirely.
  const top = present.find((f) => (f.frameId ?? 0) === 0) || present[0];

  const items = [];
  for (const frame of present) {
    const frameId = frame.frameId ?? 0;
    for (const item of frame.result.items || []) {
      const ids = itemTargets(item).map((id) => `${frameId}:${id}`);
      items.push({
        ...item,
        frameId,
        ...(ids.length ? { targetId: ids[0], targetIds: ids } : {}),
      });
    }
  }

  // Dedupe across frames: the same finding (same groupKey + context) surfaced by
  // more than one frame is one finding — e.g. the same ad iframe loaded twice.
  // Every target id is kept so the row can still cycle to each occurrence.
  const byIdentity = new Map();
  const unique = [];
  for (const item of items) {
    const key = `${item.groupKey ?? item.type}\u0000${item.context ?? ""}`;
    const existing = byIdentity.get(key);
    if (!existing) {
      byIdentity.set(key, item);
      unique.push(item);
      continue;
    }
    existing.matchCount = (existing.matchCount || 1) + (item.matchCount || 1);
    existing.targetIds = [...(existing.targetIds || []), ...(item.targetIds || [])];
    if (SEV_ORDER[item.severity] < SEV_ORDER[existing.severity])
      existing.severity = item.severity;
  }

  unique.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  unique.forEach((item, i) => (item.index = i + 1));
  const capped = unique.slice(0, MAX_ITEMS);

  return {
    url: top?.result?.url || "",
    count: capped.length,
    worst: worstSeverity(capped),
    verdict: pageVerdict(capped),
    corroborationCount: corroborationCount(capped),
    bySeverity: {
      high: capped.filter((i) => i.severity === "high").length,
      medium: capped.filter((i) => i.severity === "medium").length,
      low: capped.filter((i) => i.severity === "low").length,
    },
    framesScanned: present.length,
    items: capped,
  };
}

// Injects into every frame the browser lets us address, then merges the
// per-frame summaries. Firefox under activeTab can reach frames that were part
// of the original page (bug 1653408), so cross-origin iframes are scanned
// there; Chrome's activeTab only covers the top frame's origin, so
// cross-origin frames are simply absent from the results (and the merge still
// works). Scanning is still a snapshot taken on click.
async function scanAllFrames(tab) {
  // 1) Put every reachable frame into per-frame mode before the scanner loads,
  //    so scan.js does not also walk descendant frames (that would double-report
  //    every same-origin iframe finding).
  await api.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: () => {
      window.__PISCAN_PER_FRAME__ = true;
    },
  });
  // 2) Same injection order as the single-frame path (see AGENTS.md).
  await api.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    files: ["detectors.js", "scan-helpers.js", "scan.js"],
  });
  // 3) Read back every frame's summary; the result array carries frameId.
  const injected = await api.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: () => window.__PIScanResult || null,
  });
  return mergeFrameResults(
    injected.map((entry) => ({ frameId: entry?.frameId ?? 0, result: entry?.result }))
  );
}

// The pre-per-frame path: one injection into the tab's top frame, whose scanner
// walks same-origin iframes itself. Used when this browser refuses allFrames
// outright, so a page that used to scan still scans exactly as it did before.
async function scanTopFrame(tab) {
  // A partial allFrames attempt may have left the flag set in the top frame;
  // clear it so this rescan keeps the recursive iframe walk.
  await api.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      window.__PISCAN_PER_FRAME__ = false;
    },
  });
  await api.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["detectors.js", "scan-helpers.js", "scan.js"],
  });
  const injected = await api.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => window.__PIScanResult || null,
  });
  return mergeFrameResults([{ frameId: 0, result: injected[0]?.result }]);
}

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scan() {
  const tab = await activeTab();
  if (
    !tab ||
    /^(about:|chrome:|chrome-extension:|moz-extension:|edge:|devtools:|view-source:)/.test(
      tab.url || ""
    )
  ) {
    els.status.textContent = "Can't scan this page.";
    return;
  }
  resetStatus(els.status);
  els.status.textContent = "Scanning…";
  els.list.replaceChildren();
  latestResult = null;
  latestTab = null;
  setExportEnabled(false);

  let result;
  try {
    result = await scanAllFrames(tab);
  } catch {
    // Some browsers/builds refuse allFrames outright (and a frame can reject
    // mid-injection). Degrade to the single-frame scan instead of surfacing an
    // error: on Chrome that is the only reachable path anyway, and on Firefox it
    // is exactly what shipped before this feature. Nothing about the page is the
    // user's fault either way.
    try {
      result = await scanTopFrame(tab);
    } catch {
      // Injection can reject if the tab closed mid-scan, navigated away, or the
      // page/CSP blocks content scripts (e.g. addons.mozilla.org, some PDF
      // viewers) — none of that is this extension's fault, so just say so
      // instead of leaving "Scanning…" stuck with an unhandled rejection.
      els.status.textContent = "Can't scan this page.";
      return;
    }
  }

  render(result);
  latestResult = result || null;
  latestTab = tab;
  setExportEnabled(!!latestResult);
  setBadge(result, tab.id);
}

// `target` is a frame-qualified target id from mergeFrameResults
// ("<frameId>:<data-piscan-id>"); a bare id is still accepted. Address the frame
// that owns the element, so a finding inside an iframe scrolls that iframe
// rather than searching the top document for an id it does not contain.
async function scrollTo(target) {
  const tab = await activeTab();
  if (!tab) return;
  const qualified = /^(\d+):(.+)$/.exec(String(target));
  const frameId = qualified ? Number(qualified[1]) : null;
  const id = qualified ? qualified[2] : target;
  try {
    await api.scripting.executeScript({
      target:
        frameId === null ? { tabId: tab.id } : { tabId: tab.id, frameIds: [frameId] },
      func: (targetId) => {
        // Search this frame's document, open shadow roots, and same-origin
        // iframes (nested frames that were allowed to be traversed) for a
        // matching data-piscan-id — copies the logic from scan-helpers.js's
        // deepQuerySelector inline rather than relying on
        // globalThis.__PIScannerHelpers, because executeScript func
        // runs in a separate execution environment from file injections.
        function find(root) {
          let found = root.querySelector(`[data-piscan-id="${CSS.escape(targetId)}"]`);
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
      args: [id],
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

// Short forms for corroboration sub-lines. Deliberately not typeLabel() — a
// corroboration entry carries only {type, severity, match}, so the full
// labels' decoded/reasons/name interpolations would have nothing to read.
const CORROBORATION_LABEL = {
  "control-token": "an LLM chat-template control token",
  "instruction-phrase": "an instruction-like phrase",
  "context-switch": "a fabricated conversation turn",
  "code-execution": "a code-execution pattern",
  "reverse-shell": "a reverse-shell command",
};

const VERDICT_LABEL = {
  // Deliberately not "Hidden characters" — a css-hidden-only or
  // instruction-phrase-only page reaches this tier with nothing invisible.
  noise: "Findings present, nothing corroborating",
  suspicious: "Suspicious",
  "likely-injection": "Likely injection attempt",
};

// The verdict class is sticky state on a long-lived element, so every path
// that does not set it must clear it — otherwise a clean re-scan after a
// likely-injection scan renders "No hidden content…" in red.
function resetStatus(el) {
  el.className = "";
}

function verdictLine(r) {
  const parts = [];
  if (r.bySeverity.high) parts.push(`${r.bySeverity.high} high`);
  if (r.bySeverity.medium) parts.push(`${r.bySeverity.medium} medium`);
  if (r.bySeverity.low) parts.push(`${r.bySeverity.low} low`);
  const corroborating = r.corroborationCount
    ? `, ${r.corroborationCount} corroborating signal${r.corroborationCount === 1 ? "" : "s"}`
    : "";
  const label = VERDICT_LABEL[r.verdict] ?? r.verdict;
  return `${label}: ${r.count} finding${r.count === 1 ? "" : "s"} (${parts.join(", ")}${corroborating})`;
}

// Findings carry decoded payloads at full length so detectors.js can re-scan
// them for corroborating content; the popup is where they get shortened.
function preview(s) {
  if (typeof s !== "string") return "";
  return s.length > 120 ? s.slice(0, 120) + "…" : s;
}

function typeLabel(item) {
  return (
    {
      "unicode-tag": (i) =>
        `Invisible ASCII-smuggling character${i.decoded ? ` → decodes to: “${preview(i.decoded)}”` : ""}`,
      invisible: (i) => `Invisible character: ${i.name} (${i.hex})`,
      "encoded-base64": (i) =>
        `Encoded blob${i.likelyJwt ? " (looks like a JWT)" : ""} → “${preview(i.decoded)}”`,
      "encoded-base32": (i) => `Base32-encoded blob → “${preview(i.decoded)}”`,
      "encoded-ascii85": (i) => `ASCII85-encoded blob → “${preview(i.decoded)}”`,
      "encoded-hex": (i) => `Hex-encoded blob → “${preview(i.decoded)}”`,
      "encoded-rot13": (i) => `ROT13-decoded blob → “${preview(i.decoded)}”`,
      "encoded-atbash": (i) => `Atbash-decoded blob → “${preview(i.decoded)}”`,
      "encoded-percent": (i) => `Percent-encoded blob → “${preview(i.decoded)}”`,
      "encoded-hex-escape": (i) => `Hex-escaped blob → “${preview(i.decoded)}”`,
      "encoded-spaced-hex": (i) =>
        `Space-separated hex byte blob → “${preview(i.decoded)}”`,
      "encoded-unicode-escape": (i) => `\\uXXXX-escaped blob → “${preview(i.decoded)}”`,
      "encoded-html-entity": (i) => `HTML-entity-encoded blob → “${preview(i.decoded)}”`,
      "variation-selector-smuggling": (i) =>
        `Hidden variation-selector payload → “${preview(i.decoded)}”`,
      "sneaky-bits-smuggling": (i) =>
        `Hidden invisible-bit-encoded payload → “${preview(i.decoded)}”`,
      "control-token": (i) => `LLM chat-template control token: “${i.match}”`,
      "fake-reasoning-frame": (i) =>
        `Fake model frame <${i.tag}>${i.incomplete ? " (unclosed)" : ""}: “${preview(i.decoded)}”`,
      "css-hidden": (i) =>
        `Visually hidden text (${i.reasons.join(", ")})${i.likelyA11y ? " — looks like accessibility markup, downgraded" : ""}`,
      "instruction-phrase": (i) =>
        `Instruction-like phrase${i.normalized ? " (revealed after removing invisible characters)" : ""}${i.attrName ? ` (in ${i.attrName})` : ""}: “${i.match}”`,
      "excessive-combining-marks": (i) =>
        `Excessive combining diacritical marks (${i.count} marks on one character)`,
      "context-switch": (i) =>
        `Fabricated conversation turn${i.roles ? ` (${i.roles.join(", ")})` : ""}: \u201c${i.match}\u201d`,
      "mixed-script": (i) => `Mixed-script token: \u201c${i.token}\u201d`,
      "code-execution": (i) => `Code-execution pattern: \u201c${i.match}\u201d`,
      "reverse-shell": (i) => `Reverse-shell command: \u201c${i.match}\u201d`,
    }[item.type]?.(item) ?? `${item.type}${item.attrName ? ` (in ${item.attrName})` : ""}`
  );
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
  // Why this finding was promoted. Both sources render the same way — the user
  // does not care whether the evidence came from inside the payload or from a
  // neighbouring finding, only that it exists.
  const why = [
    ...(item.corroboration || []).map(
      (c) =>
        `decoded text contains ${CORROBORATION_LABEL[c.type] ?? c.type}${c.match ? `: “${preview(c.match)}”` : ""}`
    ),
    ...(item.contextual || []),
  ];
  for (const reason of why) {
    const el = document.createElement("div");
    el.className = "why";
    el.textContent = `└ ${reason}`;
    row.appendChild(el);
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
    resetStatus(els.status);
    els.status.textContent = "No hidden content or injection markers found.";
    return;
  }
  els.status.className = "verdict-" + r.verdict;
  els.status.textContent = verdictLine(r);

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

function exportSafeFinding(item) {
  const copy = { ...item };
  // Internal correlation/scroll bookkeeping, not useful outside the popup.
  delete copy.targetId;
  delete copy.targetIds;
  delete copy.groupKey;
  delete copy.index;
  delete copy.pattern;
  delete copy.frameId;
  return copy;
}

function buildExportJson(result, tab, version, now = new Date()) {
  const bySeverity = result?.bySeverity || { high: 0, medium: 0, low: 0 };
  return {
    tool: "Lemon Juice",
    version,
    generatedAt: now.toISOString(),
    page: {
      url: tab?.url || result?.url || "",
      title: tab?.title || "",
    },
    verdict: result?.verdict || "clean",
    counts: {
      total: result?.count || 0,
      high: bySeverity.high || 0,
      medium: bySeverity.medium || 0,
      low: bySeverity.low || 0,
      corroborating: result?.corroborationCount || 0,
    },
    findings: (result?.items || []).map(exportSafeFinding),
  };
}

function buildExportText(result, tab, version, now = new Date()) {
  const data = buildExportJson(result, tab, version, now);
  const lines = [
    `Lemon Juice ${data.version}`,
    `Page: ${data.page.title || "(untitled)"}`,
    data.page.url,
    `Scanned: ${data.generatedAt}`,
    `Verdict: ${data.verdict}`,
    `Findings: ${data.counts.total} (${data.counts.high} high, ${data.counts.medium} medium, ${data.counts.low} low; ${data.counts.corroborating} corroborating signals)`,
    "",
  ];
  data.findings.forEach((item, i) => {
    lines.push(`#${i + 1} [${String(item.severity).toUpperCase()}] ${typeLabel(item)}`);
    if (item.context) lines.push(`    context: ${item.context}`);
    if (item.corroboration?.length) {
      lines.push(
        `    corroborated by: ${item.corroboration.map((c) => c.type).join(", ")}`
      );
    }
    if (item.contextual?.length) {
      lines.push(`    placement: ${item.contextual.join(", ")}`);
    }
    lines.push("");
  });
  return lines.join("\n");
}

function exportFilename(ext, now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  // Deliberately no host/page name: exported files often land in shared or
  // synced folders, and the filename should not leak where they came from.
  return `lemon-juice-findings-${stamp}.${ext}`;
}

function downloadExport(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function extensionVersion() {
  try {
    return api.runtime.getManifest().version;
  } catch {
    return "unknown";
  }
}

function exportResult(ext) {
  if (!latestResult) return;
  const now = new Date();
  const version = extensionVersion();
  const isJson = ext === "json";
  const text = isJson
    ? JSON.stringify(buildExportJson(latestResult, latestTab, version, now), null, 2)
    : buildExportText(latestResult, latestTab, version, now);
  downloadExport(
    exportFilename(ext, now),
    text,
    isJson ? "application/json" : "text/plain"
  );
}

function setBadge(r, tabId) {
  // Colour tracks the VERDICT, not the worst single finding: an uncorroborated
  // MEDIUM (a lone zero-width space) is noise and should not read amber.
  const concerning = r ? r.bySeverity.high + r.bySeverity.medium : 0;
  const text = concerning ? String(concerning) : "";
  const color =
    r && r.verdict === "likely-injection"
      ? "#e5484d"
      : r && r.verdict === "suspicious"
        ? "#f5a623"
        : "#3b82f6";
  api.action.setBadgeText({ text, tabId });
  api.action.setBadgeBackgroundColor({ color, tabId });
}

els.rescan.addEventListener("click", scan);
els.exportJson.addEventListener("click", () => exportResult("json"));
els.exportTxt.addEventListener("click", () => exportResult("txt"));
scan();

if (typeof module !== "undefined" && module.exports)
  module.exports = {
    typeLabel,
    preview,
    verdictLine,
    resetStatus,
    buildExportJson,
    buildExportText,
    exportFilename,
    mergeFrameResults,
    pageVerdict,
    worstSeverity,
    corroborationCount,
  };
