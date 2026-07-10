"use strict";

const { test, expect } = require("@playwright/test");
const path = require("path");
const fs = require("fs");

const FIXTURES = path.resolve(__dirname, "..", "fixtures");
const DETECTORS_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "..", "detectors.js"),
  "utf-8"
);
const HELPERS_SRC = fs.readFileSync(
  path.resolve(__dirname, "..", "..", "scan-helpers.js"),
  "utf-8"
);
const SCAN_SRC = fs.readFileSync(path.resolve(__dirname, "..", "..", "scan.js"), "utf-8");

async function injectAndScan(page, fixtureName) {
  await page.goto(`file://${path.join(FIXTURES, fixtureName)}`);
  await page.evaluate(DETECTORS_SRC);
  await page.evaluate(HELPERS_SRC);
  await page.evaluate(SCAN_SRC);
  return page.evaluate(() => window.__PIScanResult);
}

// Markers are drawn into a single .piscan-overlay layer, not injected into
// page elements. Each marker (outline box + candle/badge chip) carries
// data-piscan-for="<the element's data-piscan-id>", so this resolves the
// overlay candle chip belonging to a given page element.
async function candleFor(page, elementLocator) {
  const id = await elementLocator.getAttribute("data-piscan-id");
  return page.locator(`.piscan-overlay .piscan-candle[data-piscan-for="${id}"]`);
}

test("baseline page has no findings", async ({ page }) => {
  const result = await injectAndScan(page, "baseline.html");
  expect(result.count).toBe(0);
  expect(result.worst).toBeNull();
  expect(result.items).toEqual([]);
});

test("plaintext page produces no css-hidden false positives", async ({ page }) => {
  const result = await injectAndScan(page, "plaintext-gpl.html");
  expect(result.count).toBe(0);
  expect(result.worst).toBeNull();
  expect(result.items).toEqual([]);
});

test("dark mode plaintext page does not flip text color", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  const result = await injectAndScan(page, "plaintext-dark.html");
  // Pass 1 should find instruction phrases in the content
  expect(result.count).toBeGreaterThan(0);
  expect(result.bySeverity.low).toBeGreaterThan(0);
  // No CSS-hidden findings from Pass 2
  const cssHidden = result.items.filter((i) => i.type === "css-hidden");
  expect(cssHidden.length).toBe(0);
  // The pre element should not have its color overridden
  const preColor = await page.evaluate(() => {
    const pre = document.querySelector("pre");
    return { saved: pre.dataset.piscanSaved || "", inline: pre.style.color };
  });
  // parse piscanSaved if set, make sure 'color' is not among saved overrides
  if (preColor.saved) {
    const saved = JSON.parse(preColor.saved);
    expect(saved.color).toBeUndefined();
  }
});

test("app-themed dark page on a light browser: no color=background false positive", async ({
  page,
}) => {
  // Default (light) color scheme — deliberately NOT emulating dark, so the
  // browser canvas is white while the page paints itself dark. This is the
  // exact real-world case that mangled 18 legitimately-visible elements.
  const result = await injectAndScan(page, "app-dark-light-browser.html");
  const cssHidden = result.items.filter((i) => i.type === "css-hidden");

  // The white-on-transparent paragraph must NOT be flagged as css-hidden and
  // must NOT have its color/anything overridden.
  const appText = page.locator('[data-testid="app-dark-text"]');
  // No reveal or override was recorded, and the page's own inline color is
  // untouched (still the fixture's #e8e8e8, not flipped to a contrasting one).
  expect(await appText.getAttribute("data-piscan-saved")).toBeNull();
  expect(await appText.evaluate((el) => el.style.color)).toBe("rgb(232, 232, 232)");
  expect(cssHidden.some((i) => i.context.includes("summarize this listing"))).toBe(false);

  // The Pass-1 instruction phrase in that same paragraph is still found.
  expect(result.items.some((i) => i.type === "instruction-phrase")).toBe(true);

  // True positive preserved: light text on a REAL dark background is flagged.
  const realHidden = cssHidden.filter((i) =>
    i.reasons.includes("text color = background")
  );
  expect(realHidden.length).toBe(1);
  expect(realHidden[0].context).toContain("real dark background");
});

test("detects invisible characters with correct severity", async ({ page }) => {
  const result = await injectAndScan(page, "invisible-chars.html");
  const invis = result.items.filter((i) => i.type === "invisible");
  expect(invis.length).toBe(4);

  const zws = invis.find((i) => i.name === "ZERO WIDTH SPACE");
  expect(zws).toBeTruthy();
  expect(zws.severity).toBe("medium");

  const bidi = invis.find((i) => i.name === "RIGHT-TO-LEFT OVERRIDE");
  expect(bidi).toBeTruthy();
  expect(bidi.severity).toBe("high");

  const bom = invis.find((i) => i.name.includes("BOM"));
  expect(bom).toBeTruthy();
  expect(bom.severity).toBe("medium");

  const zwj = invis.find((i) => i.name === "ZERO WIDTH JOINER");
  expect(zwj).toBeTruthy();
  expect(zwj.severity).toBe("low");
});

test("detects unicode tags block", async ({ page }) => {
  const result = await injectAndScan(page, "unicode-tags.html");
  const tags = result.items.filter((i) => i.type === "unicode-tag");
  expect(tags.length).toBeGreaterThanOrEqual(4);
  for (const t of tags) {
    expect(t.severity).toBe("high");
  }
});

test("detects base64 encoded blobs", async ({ page }) => {
  const result = await injectAndScan(page, "base64-blob.html");
  const encoded = result.items.filter((i) => i.type === "encoded-base64");
  expect(encoded.length).toBe(1);
  expect(encoded[0].severity).toBe("medium");
  expect(encoded[0].decoded).toMatch(/hidden instruction/i);
});

test("detects instruction phrases as low severity", async ({ page }) => {
  const result = await injectAndScan(page, "instruction-phrases.html");
  const instructions = result.items.filter((i) => i.type === "instruction-phrase");
  expect(instructions.length).toBeGreaterThanOrEqual(6);
  for (const inst of instructions) {
    expect(inst.severity).toBe("low");
  }
  // A page that ONLY contains instruction-phrase matches (no invisible/encoded
  // findings) must never escalate overall severity — mirrors why OWASP LLM01,
  // Simon Willison's writeups, etc. quoting these phrases stay informational.
  expect(result.worst).toBe("low");
});

test("detects variation-selector smuggling hidden after an emoji", async ({ page }) => {
  const result = await injectAndScan(page, "variation-selectors.html");
  const findings = result.items.filter((i) => i.type === "variation-selector-smuggling");
  expect(findings.length).toBe(1);
  expect(findings[0].severity).toBe("high");
  expect(findings[0].decoded).toBe("hidden msg");
  // The lone ❤️ presentation selector on the page must not also be flagged —
  // already implied by findings.length === 1 above (only the emoji payload).
});

test("detects Sneaky Bits invisible-times/invisible-plus smuggling", async ({ page }) => {
  const result = await injectAndScan(page, "sneaky-bits.html");
  const findings = result.items.filter((i) => i.type === "sneaky-bits-smuggling");
  expect(findings.length).toBe(1);
  expect(findings[0].severity).toBe("high");
  expect(findings[0].decoded).toBe("hidden msg");
});

test("detects percent-encoded and hex-escaped smuggling", async ({ page }) => {
  const result = await injectAndScan(page, "encoded-percent-hex.html");
  const percent = result.items.filter((i) => i.type === "encoded-percent");
  const hexEscape = result.items.filter((i) => i.type === "encoded-hex-escape");
  expect(percent.length).toBe(1);
  expect(percent[0].severity).toBe("medium");
  expect(percent[0].decoded).toBe("hidden percent payload");
  expect(hexEscape.length).toBe(1);
  expect(hexEscape[0].severity).toBe("medium");
  expect(hexEscape[0].decoded).toBe("hidden hex escape payload");
});

test("downgrades a real JWT to low severity instead of flagging as medium", async ({
  page,
}) => {
  const result = await injectAndScan(page, "jwt-decoy.html");
  const encoded = result.items.filter((i) => i.type === "encoded-base64");
  expect(encoded.length).toBeGreaterThanOrEqual(2); // header + payload segments
  for (const finding of encoded) {
    expect(finding.severity).toBe("low");
    expect(finding.likelyJwt).toBe(true);
  }
});

test("reveals content split by a zero-width space via the normalized re-scan pass", async ({
  page,
}) => {
  const result = await injectAndScan(page, "zero-width-split.html");
  const phrase = result.items.find(
    (i) => i.type === "instruction-phrase" && i.normalized
  );
  expect(phrase).toBeTruthy();
  const blob = result.items.find((i) => i.type === "encoded-base64" && i.normalized);
  expect(blob).toBeTruthy();
  expect(blob.decoded).toBe("hidden instruction payload");
});

test("detects CSS-hidden text and skips display:none", async ({ page }) => {
  const result = await injectAndScan(page, "css-hidden.html");
  const hidden = result.items.filter((i) => i.type === "css-hidden");
  // 6 findings: tiny-font, opacity:0, off-screen, negative text-indent,
  // white-on-white (real bg), and white-on-near-white (real ancestor bg).
  // white-on-default-bg is NOT flagged: its only "background" is the browser
  // canvas, which we no longer guess (that's the dark-page false-positive gate).
  expect(hidden.length).toBe(6);
  expect(hidden.some((h) => h.context.includes("Should NOT"))).toBe(false);
  expect(hidden.some((h) => h.context.includes("White on default page bg"))).toBe(false);

  // Reveals still make genuinely-hidden text visible (color is NOT touched).
  await expect(page.locator("[data-testid=font-size-hidden]")).toHaveCSS(
    "font-size",
    "16px"
  );
  await expect(page.locator("[data-testid=opacity-hidden]")).toHaveCSS("opacity", "0.5");
  await expect(page.locator("[data-testid=off-screen-hidden]")).toHaveCSS(
    "position",
    "static"
  );
  await expect(page.locator("[data-testid=text-indent-hidden]")).toHaveCSS(
    "text-indent",
    "0px"
  );

  // Markers live in the overlay layer — one candle + one badge per finding —
  // and nothing is injected into the page elements themselves.
  await expect(page.locator(".piscan-overlay .piscan-candle")).toHaveCount(6);
  const badges = page.locator(".piscan-overlay .piscan-badge");
  await expect(badges).toHaveCount(6);
  const firstBadge = await badges.first().textContent();
  expect(parseInt(firstBadge)).toBeGreaterThan(0);
});

test("only direct text-holding parent gets highlighted", async ({ page }) => {
  await injectAndScan(page, "nested-highlight.html");
  const inner = page.locator("#inner");
  await expect(inner).toHaveAttribute("data-piscan-mark");
  await expect(await candleFor(page, inner)).toBeAttached();
  const outer = page.locator("#outer");
  await expect(outer).not.toHaveAttribute("data-piscan-mark");
  const middle = page.locator("#middle");
  await expect(middle).not.toHaveAttribute("data-piscan-mark");
  // Only the innermost text-holder is marked, so the overlay has exactly one
  // marker for the whole nested structure.
  await expect(page.locator(".piscan-overlay .piscan-candle")).toHaveCount(1);
});

test("CSS-hidden does not downgrade high-severity candle icon color", async ({
  page,
}) => {
  const result = await injectAndScan(page, "overlapping.html");
  expect(result.worst).toBe("high");
  const el = page.locator("#overlap");
  await expect(el).toHaveAttribute("data-piscan-mark", "high");
  const icon = await candleFor(page, el);
  await expect(icon).toBeAttached();
  const iconColor = await icon.evaluate((n) => getComputedStyle(n).color);
  expect(iconColor).toBe("rgb(229, 72, 77)");
});

test("downgrades a11y-marked CSS-hidden elements to LOW severity", async ({ page }) => {
  const result = await injectAndScan(page, "a11y-hidden.html");
  const cssHidden = result.items.filter((i) => i.type === "css-hidden");
  const a11yItems = cssHidden.filter((i) => i.likelyA11y);
  const ordinary = cssHidden.filter((i) => !i.likelyA11y);
  // Both a11y-marked elements produce LOW-severity findings
  expect(a11yItems.length).toBe(2);
  for (const item of a11yItems) {
    expect(item.severity).toBe("low");
  }
  // The ordinary css-hidden element remains MEDIUM with no likelyA11y flag
  expect(ordinary.length).toBe(1);
  expect(ordinary[0].severity).toBe("medium");
  expect(ordinary[0].likelyA11y).toBeUndefined();
  // All 3 elements still get an overlay marker.
  await expect(
    await candleFor(page, page.locator('[data-testid="a11y-offscreen"]'))
  ).toBeAttached();
  await expect(
    await candleFor(page, page.locator('[data-testid="a11y-sronly"]'))
  ).toBeAttached();
  await expect(
    await candleFor(page, page.locator('[data-testid="ordinary-css-hidden"]'))
  ).toBeAttached();
});

test("result has correct summary structure", async ({ page }) => {
  const result = await injectAndScan(page, "invisible-chars.html");
  expect(result).toHaveProperty("url");
  expect(result.url).toMatch(/invisible-chars\.html$/);
  expect(result).toHaveProperty("count");
  expect(result).toHaveProperty("worst");
  expect(result).toHaveProperty("bySeverity");
  expect(result.bySeverity).toHaveProperty("high");
  expect(result.bySeverity).toHaveProperty("medium");
  expect(result.bySeverity).toHaveProperty("low");
  expect(Array.isArray(result.items)).toBe(true);
  if (result.items.length > 0) {
    expect(result.items[0]).toHaveProperty("index");
    expect(typeof result.items[0].index).toBe("number");
    expect(result.items[0]).toHaveProperty("targetId");
    expect(result.items[0].targetId).toMatch(/^pi-/);
  }
});

test("caps findings at 200 items", async ({ page }) => {
  const result = await injectAndScan(page, "many-findings.html");
  expect(result.count).toBe(200);
  expect(result.items.length).toBe(200);
});

test("css-hidden re-scan preserves finding count", async ({ page }) => {
  const r1 = await injectAndScan(page, "css-hidden.html");
  const css1 = r1.items.filter((i) => i.type === "css-hidden").length;
  expect(css1).toBeGreaterThan(0);
  const r2 = await injectAndScan(page, "css-hidden.html");
  const css2 = r2.items.filter((i) => i.type === "css-hidden").length;
  expect(css2).toBe(css1);
});

test("re-scanning preserves marks on same page", async ({ page }) => {
  await injectAndScan(page, "invisible-chars.html");
  const marked1 = await page.locator("[data-piscan-mark]").count();
  const candles1 = await page.locator(".piscan-overlay .piscan-candle").count();
  expect(marked1).toBeGreaterThan(0);
  expect(candles1).toBeGreaterThan(0);
  await injectAndScan(page, "invisible-chars.html");
  const marked2 = await page.locator("[data-piscan-mark]").count();
  const candles2 = await page.locator(".piscan-overlay .piscan-candle").count();
  // Re-scan clears the old overlay + marks first, so counts stay stable
  // (no accumulation of duplicate markers).
  expect(marked2).toBe(marked1);
  expect(candles2).toBe(candles1);
  // One candle (box) per element, one badge per finding — so at least as many
  // badges as candles.
  const badges2 = await page.locator(".piscan-overlay .piscan-badge").count();
  expect(badges2).toBeGreaterThanOrEqual(candles2);
});

test("dedup collapses identical findings across repeated elements", async ({ page }) => {
  const result = await injectAndScan(page, "repeated-findings.html");
  // The 3 repeated elements each produce an invisible-ZWSP finding and a
  // normalized instruction-phrase finding — the ZWSP findings should be
  // deduped into 1 with matchCount=3, and the instruction-phrase findings
  // deduped into 1 with matchCount=3.
  const invisFindings = result.items.filter((i) => i.type === "invisible");
  const phraseFindings = result.items.filter(
    (i) => i.type === "instruction-phrase" && i.normalized
  );
  // At least one deduped item exists with matchCount 3
  const dedupedInvis = invisFindings.filter((i) => i.matchCount === 3);
  const dedupedPhrases = phraseFindings.filter((i) => i.matchCount === 3);
  expect(dedupedInvis.length).toBeGreaterThanOrEqual(1);
  expect(dedupedPhrases.length).toBeGreaterThanOrEqual(1);
  // The distinct finding is separate and has no matchCount (or matchCount=1)
  const distinct = result.items.find(
    (i) => i.type === "instruction-phrase" && !i.normalized && !i.matchCount
  );
  expect(distinct).toBeTruthy();
  expect(distinct.context).toMatch(/you are now a duck/);
  // All 3 repeated elements still get overlay markers and marks. Because the
  // findings are deduped, each repeated element is a separate targetId of the
  // SAME items, so each carries the same set of badge numbers.
  const rep1 = page.locator('[data-testid="repeated-1"]');
  const rep2 = page.locator('[data-testid="repeated-2"]');
  const rep3 = page.locator('[data-testid="repeated-3"]');
  await expect(await candleFor(page, rep1)).toBeAttached();
  await expect(await candleFor(page, rep2)).toBeAttached();
  await expect(await candleFor(page, rep3)).toBeAttached();
  const badgesForEl = async (elLocator) => {
    const id = await elLocator.getAttribute("data-piscan-id");
    return page
      .locator(`.piscan-overlay .piscan-badge[data-piscan-for="${id}"]`)
      .allTextContents();
  };
  const badges1 = await badgesForEl(rep1);
  const badges2 = await badgesForEl(rep2);
  const badges3 = await badgesForEl(rep3);
  expect(badges1.length).toBeGreaterThanOrEqual(1);
  expect(badges1).toEqual(badges2);
  expect(badges2).toEqual(badges3);
});

test("never scans its own overlay markers, and re-scanning stays stable", async ({
  page,
}) => {
  // The overlay's candle/badge glyphs would themselves look like findings on a
  // mid-gray page, but markers live in the .piscan-overlay layer which is torn
  // down at the start of every scan (clearMarks) and only rebuilt at the end —
  // so a re-scan never ingests them.
  const r1 = await injectAndScan(page, "decoration-rescan.html");
  const css1 = r1.items.filter((i) => i.type === "css-hidden");
  expect(css1.length).toBe(0);
  expect(r1.items.some((i) => i.type === "instruction-phrase")).toBe(true);

  const r2 = await injectAndScan(page, "decoration-rescan.html");
  expect(r2.count).toBe(r1.count);
  expect(r2.items.filter((i) => i.type === "css-hidden").length).toBe(0);

  // No overlay node was ever marked (no mark nested inside a marker), and the
  // target keeps exactly one marker after two scans.
  await expect(page.locator(".piscan-overlay [data-piscan-mark]")).toHaveCount(0);
  await expect(await candleFor(page, page.locator("#target"))).toHaveCount(1);
});

test("clearMarks removes marks and candles when switching to clean page", async ({
  page,
}) => {
  await injectAndScan(page, "invisible-chars.html");
  expect(await page.locator("[data-piscan-mark]").count()).toBeGreaterThan(0);
  expect(await page.locator(".piscan-candle").count()).toBeGreaterThan(0);
  await injectAndScan(page, "baseline.html");
  expect(await page.locator("[data-piscan-mark]").count()).toBe(0);
  expect(await page.locator(".piscan-overlay").count()).toBe(0);
  expect(await page.locator(".piscan-candle").count()).toBe(0);
  expect(await page.locator(".piscan-badge").count()).toBe(0);
});

test("aria-label and title attributes are scanned for hidden text", async ({ page }) => {
  const result = await injectAndScan(page, "attribute-injection.html");
  const attrPhrases = result.items.filter((i) => i.attrName);
  expect(attrPhrases.length).toBe(2);
  for (const item of attrPhrases) {
    expect(item.attrName).toMatch(/^aria-label$|^title$/);
    expect(item.context).toMatch(/^\[(aria-label|title)\]/);
  }
});

test("css-hidden-extras: transform/clip-path hiding techniques are detected", async ({
  page,
}) => {
  const result = await injectAndScan(page, "css-hidden-extras.html");
  const cssHidden = result.items.filter((i) => i.type === "css-hidden");
  expect(cssHidden.length).toBe(3);
  expect(cssHidden.some((i) => i.reasons.includes("transform off-screen"))).toBe(true);
  expect(cssHidden.some((i) => i.reasons.includes("transform scale(0)"))).toBe(true);
  expect(cssHidden.some((i) => i.reasons.includes("clip-path hides content"))).toBe(true);
  for (const item of cssHidden) expect(item.severity).toBe("medium");
});

test("typoglycemia: reveals instructions with scrambled inner letters", async ({
  page,
}) => {
  const result = await injectAndScan(page, "typoglycemia.html");
  expect(result.items.filter((i) => i.type === "instruction-phrase").length).toBe(1);
});

test("unicode-escape: detects \\uXXXX-encoded instructions", async ({ page }) => {
  const result = await injectAndScan(page, "unicode-escape.html");
  expect(result.items.filter((i) => i.type === "encoded-unicode-escape").length).toBe(1);
});

test("html-entities: detects hex HTML entity-encoded instructions", async ({ page }) => {
  const result = await injectAndScan(page, "html-entities.html");
  expect(result.items.filter((i) => i.type === "encoded-html-entity").length).toBe(1);
});

test("combining-marks: flags excessive diacritical marks", async ({ page }) => {
  const result = await injectAndScan(page, "combining-marks.html");
  expect(result.items.filter((i) => i.type === "excessive-combining-marks").length).toBe(
    1
  );
});

test("homoglyphs: detects instructions obfuscated by Cyrillic/Greek homoglyphs", async ({
  page,
}) => {
  const result = await injectAndScan(page, "homoglyphs.html");
  expect(result.items.filter((i) => i.type === "instruction-phrase").length).toBe(1);
});

test("fancy-unicode: detects instructions in math-bold, fullwidth, and regional-indicator text", async ({
  page,
}) => {
  const result = await injectAndScan(page, "fancy-unicode.html");
  const phrases = result.items.filter((i) => i.type === "instruction-phrase");
  expect(phrases.length).toBe(3);
});
