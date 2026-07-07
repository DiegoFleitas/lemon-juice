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
  await browser.scripting.executeScript({
    target: { tabId: tab.id },
    func: (id) => {
      const helpers = window.__PIScannerHelpers;
      if (!helpers) return;
      const el = helpers.deepQuerySelector(
        document,
        `[data-piscan-id="${CSS.escape(id)}"]`
      );
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
  const parts = [];
  if (r.bySeverity.high) parts.push(`${r.bySeverity.high} high`);
  if (r.bySeverity.medium) parts.push(`${r.bySeverity.medium} medium`);
  if (r.bySeverity.low) parts.push(`${r.bySeverity.low} low`);
  els.status.textContent = `${r.count} finding${r.count === 1 ? "" : "s"}: ${parts.join(", ")}`;

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
                : item.type === "encoded-spaced-hex"
                  ? `Space-separated hex byte blob → “${item.decoded}”`
                  : item.type === "variation-selector-smuggling"
                    ? `Hidden variation-selector payload → “${item.decoded}”`
                    : item.type === "sneaky-bits-smuggling"
                      ? `Hidden invisible-bit-encoded payload → “${item.decoded}”`
                      : item.type === "control-token"
                        ? `LLM chat-template control token: “${item.match}”`
                        : item.type === "css-hidden"
                          ? `Visually hidden text (${item.reasons.join(", ")})`
                          : item.type === "instruction-phrase"
                            ? `Instruction-like phrase${item.normalized ? " (revealed after removing invisible characters)" : ""}: “${item.match}”`
                            : item.type
    }${item.inComment ? " (in an HTML comment)" : ""}`;
    const labelEl = document.createElement("div");
    labelEl.className = "label";
    labelEl.textContent = label;
    row.appendChild(labelEl);
    if (item.context) {
      const ctxEl = document.createElement("div");
      ctxEl.className = "ctx";
      ctxEl.textContent = item.context;
      row.appendChild(ctxEl);
    }
    if (item.targetId) row.addEventListener("click", () => scrollTo(item.targetId));
    els.list.appendChild(row);
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
