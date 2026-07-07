// popup.js — Firefox (browser.* promise API).
// activeTab grants us scripting on the current tab the moment the user opens
// this popup, so we need no host permissions in the manifest.

const els = {
  status: document.getElementById("status"),
  list: document.getElementById("list"),
  rescan: document.getElementById("rescan"),
};

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
  els.list.innerHTML = "";

  // 1) Inject the pure detectors, then helpers, then the DOM scanner (order matters).
  await browser.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["detectors.js", "scan-helpers.js", "scan.js"],
  });
  // 2) Read back the summary the scanner stashed on window.
  const [{ result }] = await browser.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => window.__PIScanResult || null,
  });

  render(result);
  setBadge(result, tab.id);
}

async function scrollTo(targetId) {
  const tab = await activeTab();
  await browser.scripting.executeScript({
    target: { tabId: tab.id },
    func: (id) => {
      const el = document.querySelector(`[data-piscan-id="${CSS.escape(id)}"]`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
    },
    args: [targetId],
  });
}

function render(r) {
  if (!r || r.count === 0) {
    els.status.textContent = "No hidden content or injection markers found.";
    return;
  }
  els.status.textContent = `${r.count} finding${r.count === 1 ? "" : "s"} — ${r.bySeverity.high} high, ${r.bySeverity.medium} medium, ${r.bySeverity.low} low`;

  for (const item of r.items) {
    const row = document.createElement("div");
    row.className = "finding sev-" + item.severity;
    if (item.targetId) row.dataset.targetId = item.targetId;
    const label = `#${item.index || "?"} ${
      item.type === "unicode-tag"
        ? `Invisible ASCII-smuggling character${item.decoded ? ` → decodes to: “${item.decoded}”` : ""}`
        : item.type === "invisible"
          ? `Invisible character: ${item.name} (${item.hex})`
          : item.type === "encoded-base64"
            ? `Encoded blob${item.likelyJwt ? " (looks like a JWT)" : ""} → “${item.decoded}”`
            : item.type === "encoded-percent"
              ? `Percent-encoded blob → “${item.decoded}”`
              : item.type === "encoded-hex-escape"
                ? `Hex-escaped blob → “${item.decoded}”`
                : item.type === "variation-selector-smuggling"
                  ? `Hidden variation-selector payload → “${item.decoded}”`
                  : item.type === "sneaky-bits-smuggling"
                    ? `Hidden invisible-bit-encoded payload → “${item.decoded}”`
                    : item.type === "css-hidden"
                      ? `Visually hidden text (${item.reasons.join(", ")})`
                      : item.type === "instruction-phrase"
                        ? `Instruction-like phrase${item.normalized ? " (revealed after removing invisible characters)" : ""}: “${item.match}”`
                        : item.type
    }`;
    row.innerHTML = `<div class="label">${escapeHtml(label)}</div>${item.context ? `<div class="ctx">${escapeHtml(item.context)}</div>` : ""}`;
    if (item.targetId) row.addEventListener("click", () => scrollTo(item.targetId));
    els.list.appendChild(row);
  }
}

function setBadge(r, tabId) {
  const worst = r && r.worst;
  const text = r && r.count ? String(r.count) : "";
  const color = worst === "high" ? "#e5484d" : worst === "medium" ? "#f5a623" : "#3b82f6";
  browser.action.setBadgeText({ text, tabId });
  browser.action.setBadgeBackgroundColor({ color, tabId });
}

function escapeHtml(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );
}

els.rescan.addEventListener("click", scan);
scan();
