# False-Positive Fatigue Mitigation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Tasks 1-3 are implemented and committed (`d8a2d30` badge/status; `2fcb5f9` dedup + a11y downgrade). Task 2's `targetIds`/click-cycling was subsequently extended in `popup.js` beyond what's written below — see the note at the end of Task 2. **Task 4 is new, not yet implemented** — it addresses a real gap found after Tasks 1-3 shipped (see its Background section).

**Goal:** Reduce false-positive noise so users don't tune out findings. Four small, contained changes to `popup.js`, `scan.js`, and `scan-helpers.js`.

**Architecture:** The scanner already sorts findings by severity and caps at 200 items, but the popup and toolbar badge don't distinguish between "informational" (LOW) and actionable findings. The plan adds dedup-with-count, a11y-aware severity, and smarter badge/status text.

**Tech Stack:** Plain JS (no dependencies), MV3 extension, `node --test` for unit tests, Playwright for e2e.

**Before starting:** This plan's file:line references were re-verified against the current `main` (post shadow-DOM/iframe/control-token work), but re-check them yourself before editing — `scan.js` and `popup.js` have moved multiple times recently and will keep moving. Locate insertion points by the surrounding code shown in each step, not by line number alone. Also don't trust hardcoded test counts in this doc; run `pnpm test` and compare against its own printed total, not a number written here.

**Known gap in this plan:** `popup.js` is not exercised by any existing e2e test — the Playwright harness in this repo only injects `detectors.js`/`scan-helpers.js`/`scan.js` directly against a fixture page; it never loads `popup.html`/`popup.js` or drives `browser.scripting`. Task 1's changes are therefore manual-verification-only (see the checklist at the end). This is a pre-existing harness limitation, not something to fix as part of this plan — call it out if you find yourself tempted to fake coverage for it.

---

### Task 1: Better toolbar badge and status line

**Files:**

- Modify: `popup.js` — `render()`'s status-line assignment (currently the single-line `els.status.textContent = ...` near the top of `render()`)
- Modify: `popup.js` — `setBadge()` (currently a 6-line function near the bottom of the file)

**Background:** Currently the badge shows the total finding count and the status line shows all three severity counts even when zero. Both amplify noise.

**Step 1: Suppress zero-count items in the status line**

Find this line inside `render()`:

```js
els.status.textContent = `${r.count} finding${r.count === 1 ? "" : "s"} — ${r.bySeverity.high} high, ${r.bySeverity.medium} medium, ${r.bySeverity.low} low`;
```

Replace with:

```js
const parts = [];
if (r.bySeverity.high) parts.push(`${r.bySeverity.high} high`);
if (r.bySeverity.medium) parts.push(`${r.bySeverity.medium} medium`);
if (r.bySeverity.low) parts.push(`${r.bySeverity.low} low`);
els.status.textContent = `${r.count} finding${r.count === 1 ? "" : "s"}: ${parts.join(", ")}`;
```

Output changes:

- Before: `"17 findings — 0 high, 17 medium, 0 low"`
- After: `"17 findings: 17 medium"`
- Before: `"3 findings — 0 high, 0 medium, 3 low"`
- After: `"3 findings: 3 low"`

**Step 2: Change badge to show HIGH + MEDIUM count instead of total**

Find `setBadge`:

```js
function setBadge(r, tabId) {
  const worst = r && r.worst;
  const text = r && r.count ? String(r.count) : "";
  const color = worst === "high" ? "#e5484d" : worst === "medium" ? "#f5a623" : "#3b82f6";
  browser.action.setBadgeText({ text, tabId });
  browser.action.setBadgeBackgroundColor({ color, tabId });
}
```

Replace with:

```js
function setBadge(r, tabId) {
  const worst = r && r.worst;
  const concerning = r ? r.bySeverity.high + r.bySeverity.medium : 0;
  const text = concerning ? String(concerning) : "";
  const color = worst === "high" ? "#e5484d" : worst === "medium" ? "#f5a623" : "#3b82f6";
  browser.action.setBadgeText({ text, tabId });
  browser.action.setBadgeBackgroundColor({ color, tabId });
}
```

**Explicit behavior change — confirm this is intended before shipping:** a page with _only_ LOW-severity findings will now show **no toolbar badge at all** (previously showed the count in blue). The popup itself still lists everything when opened; this only affects the at-a-glance badge. If that's too aggressive, an alternative is a dimmed/outlined badge for LOW-only rather than no badge — not implemented here, flagging as a design call.

**Step 3: Run linter and unit tests**

```bash
pnpm lint && pnpm test
```

Expected: lint passes, all unit tests pass (this task touches no detection logic, so the count shouldn't change either way).

**Step 4: Manual verification (no e2e coverage exists for popup.js — see note at top of this doc)**

1. Load as a temporary add-on.
2. Visit a page with only LOW findings (e.g. a page that just discusses prompt injection in prose) — confirm no badge appears, and the popup status line omits the zero-count severities.
3. Visit a page with mixed severities — confirm the badge shows HIGH+MEDIUM count only, and the status line lists only nonzero buckets.

**Step 5: Commit**

```bash
git add popup.js
git commit -m "fix(popup): suppress zero counts in status line, badge shows actionable count only"
```

---

### Task 2: Dedup identical findings across elements, with a repeat count

**Files:**

- Modify: `scan.js` — inside `runScan()`, after the per-root `for (const root of roots)` loop, before the `SEV_ORDER` sort; and the badge-insertion loop right after
- Modify: `popup.js` — `render()`'s label construction, to surface the repeat count

**Background:** The same text appearing in multiple DOM elements (e.g., a nav item rendered in 5 `<li>`s, or a repeated footer) produces N separate findings with identical `type` and content. Reading the same finding 5 times in the popup list is noise.

**Design notes — read before implementing (this revises the original naive version of this task):**

1. **Dedup key must be a finding fingerprint, not just the raw context snippet.** `context` is a 90-char truncated snippet of the _entire source text node_ (see `snippet()` in `scan-helpers.js`). If one text node triggers two genuinely different `instruction-phrase` matches (e.g. a string that matches two different patterns in `INSTRUCTION_PATTERNS`), both findings share the same `type` AND the same `context` — keying on `type:context` alone would silently collapse them into one, dropping a real distinct finding. Key on `type` + a per-type fingerprint of the actual signal (`pattern` for `instruction-phrase`/`control-token`, `hex` for `invisible`, `reasons` for `css-hidden`, `decoded` for encoded-blob types) + `context`, so two things only collapse when they're genuinely the same signal _and_ the same surrounding text — this mirrors `contentFindingKey()` in `detectors.js`, which already solves the identical problem for the raw/normalized-rescan dedup within a single `scanText()` call. Reuse that pattern rather than reinventing a coarser one.

2. **Don't silently strand highlighted-but-unlisted elements.** In the original draft, dedup ran only on the `items` array _after_ `highlightElement`/`makeHighlightVisible` had already run on every matching element in the per-root loop. That means all 5 nav `<li>`s would still get a candle icon on the page, but only 1 would appear in the popup list with a badge — the other 4 are marked with no explanation and no click target. Fix: keep highlighting every occurrence (that's still useful — it shows all the places the pattern was found), but track a `matchCount` on the surviving deduped item and give **every** occurrence's element the same badge number (not just the first), so the popup entry and the page markings stay visually consistent. Concretely: track `targetIds: []` (all element ids that matched this key) alongside the single `targetId` (first occurrence, used by the existing `scrollTo` click handler unchanged), and update the badge-insertion loop to place the same numbered badge on every id in `targetIds`.

**Step 1: Add a finding-identity key helper and dedup loop**

Insert after the closing `}` of the per-root `for (const root of roots) { ... }` loop and before `const SEV_ORDER = ...`:

```js
// Dedup: findings with the same type + signal + surrounding text are the
// same content repeated across elements (e.g. a nav item in 5 <li>s) —
// collapse them in the list, but keep every occurrence highlighted on
// the page and record how many there were so a collapsed entry doesn't
// read as if it's the only occurrence.
function findingIdentityKey(item) {
  const fingerprint =
    item.type === "instruction-phrase" || item.type === "control-token"
      ? item.pattern
      : item.type === "invisible"
        ? item.hex
        : item.type === "css-hidden"
          ? item.reasons.join(",")
          : (item.decoded ?? "");
  return `${item.type}:${fingerprint}:${item.context}`;
}
const seenItems = new Map(); // key -> surviving item
const deduped = [];
for (const item of items) {
  const key = findingIdentityKey(item);
  const existing = seenItems.get(key);
  if (existing) {
    existing.matchCount = (existing.matchCount || 1) + 1;
    if (item.targetId) existing.targetIds.push(item.targetId);
  } else {
    item.targetIds = item.targetId ? [item.targetId] : [];
    seenItems.set(key, item);
    deduped.push(item);
  }
}
items.splice(0, items.length, ...deduped);
```

**Step 2: Badge every occurrence, not just the first**

Find the existing badge-insertion loop (uses `elementById.get(item.targetId)`):

```js
for (let i = capped.length - 1; i >= 0; i--) {
  const item = capped[i];
  if (item.targetId) {
    const el = elementById.get(item.targetId);
    if (el) {
      const badge = el.ownerDocument.createElement("sup");
      badge.className = "piscan-badge";
      badge.textContent = item.index;
      badge.style.cssText = "color:#000;font-size:10px;margin:0 1px;";
      el.insertBefore(badge, el.firstChild);
    }
  }
}
```

Replace the body to iterate `item.targetIds` (falls back to `[item.targetId]` for any item that predates this change, e.g. `css-hidden` items that never got `targetIds` populated — the dedup loop above sets it on every item, so this fallback is defensive only):

```js
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
```

**Step 3: Surface the repeat count in the popup**

In `popup.js`'s `render()`, after the label ternary chain (which currently ends with `}${item.inComment ? " (in an HTML comment)" : ""}`), append the match count:

```js
    }${item.inComment ? " (in an HTML comment)" : ""}${item.matchCount > 1 ? ` (×${item.matchCount})` : ""}`;
```

**Step 4: Add a fixture + e2e test exercising the new dedup behavior**

The original draft of this task shipped with zero test coverage ("no behaviour change — tests don't have repeated-context elements"). Since this _is_ new behavior, add:

- `__tests__/fixtures/repeated-findings.html`: 3+ elements (e.g. `<li>` items) with identical text containing the same detectable finding (e.g. the same zero-width-space-containing phrase, or the same instruction phrase), plus one _different_ finding elsewhere on the page to confirm it's not accidentally collapsed too.
- A test in `__tests__/e2e/scan.spec.js` (or a new spec) asserting:
  - The repeated finding appears exactly once in `result.items`, with `matchCount` equal to the number of repeated elements.
  - The unrelated finding elsewhere on the page is unaffected (still present, `matchCount` absent or `1`).
  - All of the repeated elements still have a `.piscan-candle` and `data-piscan-mark` (highlighting wasn't skipped for the collapsed duplicates).
  - All of the repeated elements carry the _same_ badge number (`.piscan-badge` textContent).

**Step 5: Run linter and tests**

```bash
pnpm lint && pnpm test && pnpm test:e2e
```

Expected: all pass, including the new dedup test.

**Step 6: Commit**

```bash
git add scan.js popup.js __tests__/fixtures/repeated-findings.html __tests__/e2e/scan.spec.js
git commit -m "fix(scan): dedup repeated findings across elements, keep count and highlights"
```

**Post-commit addendum — click-cycling (not in the original plan, added afterward):** a deduped item's `targetIds` array was originally only used to badge every occurrence; clicking the row always scrolled to the _first_ one. This was extended so clicking cycles through every occurrence on successive clicks (`clickCycles` Map in `popup.js`, keyed by item, tracking a cycling offset into `targetIds`). Two real bugs were found and fixed in that extension, worth knowing about if this code is touched again:

1. `scrollTo`'s injected function was rewritten to inline its own shadow-root/same-origin-iframe traversal instead of calling `window.__PIScannerHelpers.deepQuerySelector(...)`. This looks like unnecessary duplication (scan-helpers.js exists specifically to be the shared source of truth for this exact traversal) — it was flagged as likely wrong in review — but it was empirically confirmed to fix a real failure: `__PIScannerHelpers` is not reliably available to a `browser.scripting.executeScript({ func: ... })` call made well after the original `files: [...]` injection (e.g. on a later popup click), even though the analogous `window.__PIScanResult` read-back immediately after scanning does work. **Keep the inlined traversal** — don't "simplify" it back to calling the shared helper without re-verifying against a real loaded Firefox extension first. The inlined copy does need `CSS.escape(id)` in its `querySelector` call (was initially dropped, then re-added) to match the escaping used everywhere else this selector shape is built.
2. `clickCycles` must be cleared at the start of every `render()` call. It's a module-level `Map` that otherwise never shrinks (leaks a growing number of stale entries across repeated re-scans), and — worse — if keyed by a per-render slot number like `item.index` rather than the item object itself, a stale cycling offset from a previous scan can silently apply to an unrelated item in a new scan (indices aren't stable identities across renders). Both problems go away by clearing the Map at the top of `render()`.

---

### Task 3: Downgrade (not skip) legitimate a11y text in the CSS-hidden pass

**Files:**

- Modify: `scan-helpers.js` — add an `elementIsA11yHidden(el)` helper, exported alongside the others
- Modify: `scan.js` — Pass 2 CSS-hidden check, inside the per-root loop
- Modify: `popup.js` — `render()`'s `css-hidden` label case
- Modify: `README.md` — the existing false-positives note about `.sr-only` text

**Background — this task was originally written as a full skip and got pushback in review:** screen-reader-only text (`sr-only`, `visually-hidden` classes, `aria-hidden="true"` elements) uses `opacity:0`, off-screen positioning, and micro-font — the exact same techniques the scanner's CSS-hidden pass looks for, and `README.md`'s existing Limitations section already documents `.sr-only` text as an _accepted_ false positive (a deliberate prior call, not an oversight).

Fully skipping CSS-hidden detection for anything carrying `aria-hidden="true"` or a `sr-only`-style class would open a real evasion path: those markers are attacker-controllable, and the bypass list is visible in this public repo. An attacker could hide a plain, non-obfuscated instruction (one that doesn't happen to match any instruction-phrase/encoding heuristic, so Pass 1 wouldn't catch it either) inside `<span aria-hidden="true">` and guarantee it's never flagged as CSS-hidden. **Decision: downgrade severity instead of skipping.** A11y-marked elements still get a `css-hidden` finding, but at LOW (informational) severity instead of MEDIUM — this cuts the noise (LOW findings don't affect the toolbar badge after Task 1, and read as "worth a glance, not alarming" in the popup) without creating a silent blind spot. Pass 1 (text-node scan for invisible chars/encoded blobs/instruction phrases/control tokens) is completely unaffected either way — it doesn't look at `elementHidesText` at all.

**Step 1: Add the a11y-detection helper to `scan-helpers.js`**

Add near `elementHidesText`:

```js
// Common screen-reader-only class names across major frameworks (Bootstrap
// & Tailwind: sr-only, WordPress: screen-reader-text, various: visually-hidden,
// offscreen). Not exhaustive — CSS-module/hashed class names and other
// conventions won't match — this is a best-effort severity signal, not a
// detection boundary (unlike the original draft of this task, elements
// matching this are still scanned, just at lower severity; see the
// Background note in the plan for why full suppression was rejected).
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
```

Add `elementIsA11yHidden` to the `Helpers` export object at the bottom of the file.

**Step 2: Use it in `scan.js`'s Pass 2 to pick the base severity**

Find (Pass 2, inside the per-root loop):

```js
scope.querySelectorAll("*").forEach((el) => {
  if (SKIP_TAGS.has(el.tagName)) return;
  const ownText = directText(el);
  if (!ownText) return;
  const reasons = elementHidesText(el);
  if (reasons.length) {
    // Respect existing mark from Pass 1: don't downgrade the outline color.
    const existingSev = el.getAttribute(MARK_ATTR);
    const sev = existingSev
      ? S.worstSeverity([{ severity: existingSev }, { severity: "medium" }])
      : "medium";
    if (!el.dataset.piscanId) el.dataset.piscanId = `pi-${nextElementId++}`;
    elementById.set(el.dataset.piscanId, el);
    highlightElement(el, colorFor(sev), sev);
    makeHighlightVisible(el);
    items.push({
      type: "css-hidden",
      severity: "medium",
      reasons,
      context: snippet(ownText),
      targetId: el.dataset.piscanId,
    });
  }
});
```

Replace with (also destructure `elementIsA11yHidden` at the top of the file alongside the other helpers):

```js
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
```

**Step 3: Surface why it's LOW in the popup label**

In `popup.js`'s `render()`, find the `css-hidden` case:

```js
: item.type === "css-hidden"
  ? `Visually hidden text (${item.reasons.join(", ")})`
```

Replace with:

```js
: item.type === "css-hidden"
  ? `Visually hidden text (${item.reasons.join(", ")})${item.likelyA11y ? " — looks like accessibility markup, downgraded" : ""}`
```

**Step 4: Update the README note this task otherwise contradicts**

Find (in the Limitations section):

```markdown
You'll also get **false positives** from legitimate zero-width joiners in
Arabic/Indic scripts, `.sr-only` accessibility text, and any article discussing
prompt injection (including this README).
```

Replace with:

```markdown
You'll also get **false positives** from legitimate zero-width joiners in
Arabic/Indic scripts and any article discussing prompt injection (including
this README). `.sr-only`/`aria-hidden` accessibility text is still flagged
(it uses the same CSS techniques a real hidden payload would) but downgraded
to LOW/informational severity rather than suppressed, since the markers are
attacker-controllable and full suppression would be a detection-evasion
shortcut.
```

**Step 5: Add a fixture + e2e test**

The original draft had no automated coverage for this behavior at all (manual-only). Add:

- `__tests__/fixtures/a11y-hidden.html`: one `<span aria-hidden="true">` with off-screen/opacity-hidden text, one `<p class="sr-only">` likewise, and one _ordinary_ (non-a11y-marked) CSS-hidden element for contrast.
- A test asserting: the a11y-marked elements produce `css-hidden` findings with `severity: "low"` and `likelyA11y: true`; the ordinary element still produces `severity: "medium"` with no `likelyA11y` flag; `result.worst` reflects that the page's worst finding is only LOW if that's the only kind present (i.e. downgrade actually reduces the badge-relevant severity, not just cosmetic labeling).

**Step 6: Run linter and tests**

```bash
pnpm lint && pnpm test && pnpm test:e2e
```

Expected: all pass, including the new a11y test. Also re-run the existing `css-hidden.html` e2e test mentally — it doesn't use any a11y markers/classes, so its MEDIUM-severity assertions should be unaffected; confirm this holds rather than assuming it.

**Step 7: Commit**

```bash
git add scan-helpers.js scan.js popup.js README.md __tests__/fixtures/a11y-hidden.html __tests__/e2e/scan.spec.js
git commit -m "fix(scan): downgrade css-hidden severity for a11y-marked elements instead of skipping"
```

---

### Task 4: Fold repeated near-duplicate findings in the popup list (presentation-only)

**Status: not yet implemented.** This is new — found after Tasks 1-3 shipped, not part of the original three-task scope.

**Files:**

- Modify: `scan.js` — `runScan()`'s dedup block (the `findingIdentityKey` function from Task 2)
- Modify: `popup.js` — `render()`'s row-building loop

**Background:** Task 2's dedup only collapses findings that share type + fingerprint + surrounding `context`. That's correct and deliberately conservative — `context` is what stops two genuinely different findings (e.g. two unrelated hidden payloads that both happen to use `opacity:0`) from wrongly merging — but it means a page with, say, 15 incidental zero-width spaces scattered across 15 _different_ paragraphs (common in text pasted from Word/Google Docs) doesn't dedup at all, since each paragraph's context differs. The popup ends up listing 15 nearly-identical "Invisible character: ZERO WIDTH SPACE" rows — exactly the fatigue this whole plan is about.

**A first attempt at fixing this was implemented and reverted in the same session it was tried.** It dropped `context` from `findingIdentityKey` entirely for `invisible` and the decoded-payload types (base64/percent/hex-escape/spaced-hex/variation-selector/sneaky-bits), reasoning that their fingerprint (`hex` or `decoded`) was already content-specific enough on its own. Running the full test suite immediately disproved that: it broke 4 e2e tests, most tellingly `shadow-and-frames.spec.js`'s test for a ZWS inside a nested shadow root — with `context` dropped, that finding silently merged with two _other_, deliberately-separate ZWS findings elsewhere on the same fixture page (an open shadow root and a closed one), and the test could no longer find an item whose context mentioned "nested shadow root" because that distinguishing text had been discarded in favor of whichever occurrence was scanned first. `many-findings.html`'s "caps findings at 200 items" test failed the same way at a larger scale (250 paragraphs' worth of ZWS findings collapsed to 1). **Conclusion: the real distinguishing signal isn't finding type, it's volume.** A handful (2-4) of same-type findings in different locations are usually genuinely separate and worth seeing individually — a large cluster (5+) is almost always incidental repetition. There's no cheap way to tell those apart from the finding data alone without a volume threshold.

**Decision: don't touch `scan.js`'s dedup semantics again.** Fold repeats purely at render time in `popup.js` instead. This is materially lower-risk than another attempt at the data-model level: `result.items`/`result.count`/badge math/highlighting/`matchCount`/click-cycling all stay exactly as they are today (already correct, already tested — including by the tests that just caught the reverted attempt), so nothing currently passing can regress. The only `scan.js` change is additive: one new field per item, which doesn't change which items exist or survive dedup.

**Design decisions (already confirmed):** fold threshold is **5 or more** same-`groupKey` items (matches the "6+ groups" minimum-run convention `PERCENT_RUN`/`HEX_ESCAPE_RUN` already use elsewhere in `detectors.js` for a similar "is this really a pattern or just noise" judgment call — close enough to reuse the same intuition). Clicking a folded row **cycles through every underlying occurrence**, reusing the exact click-cycling mechanism Task 2's addendum already built for `matchCount`-only rows, rather than introducing a new expand/collapse UI pattern this popup doesn't have anywhere else.

**Step 1: Expose a presentation-only grouping key from `scan.js`**

In the existing `findingIdentityKey` function (see Task 2, Step 1 — by now also has the `unicode-tag` fix noted there), factor the `fingerprint` expression out so the _type+fingerprint_ portion (without `context`) is available separately from the full dedup key:

```js
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
```

Update the dedup loop to use `.full` for the actual dedup decision (unchanged behavior) and attach `.group` to each surviving item as `item.groupKey` (in the same place `item.targetIds` is already being set):

```js
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
```

No change to which items survive, no change to counts, highlighting, or badging — `groupKey` is inert data until `popup.js` reads it.

**Step 2: Group and fold in `popup.js`'s `render()`**

Before the `for (const item of r.items)` loop that builds rows, group by `groupKey` and branch on group size:

```js
const FOLD_THRESHOLD = 5;
const groups = new Map(); // groupKey -> item[]
for (const item of r.items) {
  const arr = groups.get(item.groupKey) || [];
  arr.push(item);
  groups.set(item.groupKey, arr);
}
```

For each group with `< FOLD_THRESHOLD` members: render each item exactly as today — this is what keeps the common case (2-4 distinct locations, like the shadow-DOM fixture) fully individually visible, no behavior change.

For each group with `>= FOLD_THRESHOLD` members: render **one** row for the whole group instead of N:

- Label: build it the same way as today, against the group's _first_ item (same per-type ternary, same wording), but with the `×N` suffix showing the summed count across the group — `group.reduce((n, i) => n + (i.matchCount || 1), 0)`, not just `group.length`, since a folded group can itself contain members that Task 2's dedup already gave their own `matchCount`.
- Context: the first item's `context` (representative example), same as today.
- Click target: merge `targetIds` (or `[targetId]`) across every item in the group into one combined array; reuse `clickCycles`, keyed by the group's `groupKey` string (since this synthetic row has no single backing `item.index`).
- Position: keep the existing severity-sort order — a folded group's row takes the position of its first-seen member, grouping shouldn't reorder anything.

The existing per-item label/context/click-cycling code should become a small helper that both the ungrouped path (called once per item) and the folded path (called once per group, with a synthetic merged item) invoke, rather than duplicating the label ternary a second time.

**Step 3: Run linter and tests**

```bash
pnpm lint && pnpm test && pnpm test:e2e
```

Expected: all pass unchanged — this task's `scan.js` change is additive-only (a new field, nothing removed or altered), so every existing assertion about `result.items`/`result.count`/highlighting/badging (including the ones that caught the reverted first attempt) should be unaffected. No new automated test is possible for the fold-and-cycle rendering itself, for the same pre-existing reason Tasks 1-3 couldn't get one either (popup.js has no e2e harness in this repo) — manual verification only, see Step 4.

**Step 4: Manual verification**

1. Load as a temporary add-on.
2. Visit (or construct locally) a page with 5+ paragraphs each containing an incidental ZWS with different surrounding text — confirm the popup shows one folded row with the correct total `×N` count instead of 5+ individual rows, and clicking it cycles through each occurrence on successive clicks.
3. Visit a page with only 2-4 same-type findings in different locations — confirm they still render as individual, separately-clickable rows (not folded).
4. Re-run the `a11y-hidden.html` / `repeated-findings.html` manual scenarios from Tasks 2-3 to confirm folding doesn't interact badly with the a11y-downgrade or matchCount work already shipped.

**Step 5: Commit**

```bash
git add scan.js popup.js
git commit -m "fix(popup): fold 5+ same-signal findings into one row at render time"
```

---

### Manual verification (before release)

1. Load as temporary add-on in Firefox.
2. Visit a page with `sr-only` text (e.g. any Bootstrap/Tailwind site with a skip-link) — confirm it's still highlighted and listed, but as a LOW-severity finding labeled "looks like accessibility markup, downgraded," not absent.
3. Visit a page with several repeated identical elements (e.g. a nav with the same CTA text in every item, artificially rigged with a hidden payload if none exists naturally) — confirm the popup lists it once with a "(×N)" count, and every repeated element on the page is still highlighted with matching badge numbers.
4. Visit the prompt-injection OWASP page — verify the popup shows a manageable number of findings and the badge only shows HIGH+MEDIUM count.
5. Visit a page with only LOW findings — confirm no badge appears at all, and decide if that's actually the desired behavior (flagged as a design call in Task 1) before shipping.
6. Visit a page with actual non-a11y hidden text (a local HTML file with `opacity:0` and a ZWS, no aria-hidden/sr-only markers) — verify it's still detected at MEDIUM severity and highlighted.
7. Visit (or construct) a page with 5+ scattered incidental invisible characters in different paragraphs — confirm Task 4's folding kicks in and the popup stays scannable.
