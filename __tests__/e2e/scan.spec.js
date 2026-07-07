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

test("baseline page has no findings", async ({ page }) => {
  const result = await injectAndScan(page, "baseline.html");
  expect(result.count).toBe(0);
  expect(result.worst).toBeNull();
  expect(result.items).toEqual([]);
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
  expect(hidden.length).toBe(7);
  const flaggedNone = hidden.some((h) => h.context.includes("Should NOT"));
  expect(flaggedNone).toBe(false);

  // Verify candle icons exist and CSS overrides make them visible
  await expect(page.locator(".piscan-candle")).toHaveCount(7);
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
  await expect(page.locator("[data-testid=white-on-default-bg]")).toHaveCSS(
    "color",
    "rgb(0, 0, 0)"
  );
  await expect(page.locator("[data-testid=wix-nested]")).toHaveCSS(
    "color",
    "rgb(0, 0, 0)"
  );

  // Verify numbered badges exist
  const badges = page.locator(".piscan-badge");
  await expect(badges).toHaveCount(7);
  const firstBadge = await badges.first().textContent();
  expect(parseInt(firstBadge)).toBeGreaterThan(0);
});

test("only direct text-holding parent gets highlighted", async ({ page }) => {
  await injectAndScan(page, "nested-highlight.html");
  const inner = page.locator("#inner");
  await expect(inner).toHaveAttribute("data-piscan-mark");
  await expect(inner.locator(".piscan-candle")).toBeAttached();
  const outer = page.locator("#outer");
  await expect(outer).not.toHaveAttribute("data-piscan-mark");
  await expect(outer.locator("> .piscan-candle")).not.toBeAttached();
  const middle = page.locator("#middle");
  await expect(middle).not.toHaveAttribute("data-piscan-mark");
  await expect(middle.locator("> .piscan-candle")).not.toBeAttached();
});

test("CSS-hidden does not downgrade high-severity candle icon color", async ({
  page,
}) => {
  const result = await injectAndScan(page, "overlapping.html");
  expect(result.worst).toBe("high");
  const el = page.locator("#overlap");
  await expect(el).toHaveAttribute("data-piscan-mark", "high");
  const icon = el.locator(".piscan-candle");
  await expect(icon).toBeAttached();
  const iconColor = await icon.evaluate((el) => getComputedStyle(el).color);
  expect(iconColor).toBe("rgb(229, 72, 77)");
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
  const candles1 = await page.locator(".piscan-candle").count();
  expect(marked1).toBeGreaterThan(0);
  expect(candles1).toBe(marked1);
  await injectAndScan(page, "invisible-chars.html");
  const marked2 = await page.locator("[data-piscan-mark]").count();
  const candles2 = await page.locator(".piscan-candle").count();
  expect(marked2).toBe(marked1);
  expect(candles2).toBe(marked2);
  const badges2 = await page.locator(".piscan-badge").count();
  expect(badges2).toBe(marked2);
});

test("clearMarks removes marks and candles when switching to clean page", async ({
  page,
}) => {
  await injectAndScan(page, "invisible-chars.html");
  expect(await page.locator("[data-piscan-mark]").count()).toBeGreaterThan(0);
  expect(await page.locator(".piscan-candle").count()).toBeGreaterThan(0);
  await injectAndScan(page, "baseline.html");
  expect(await page.locator("[data-piscan-mark]").count()).toBe(0);
  expect(await page.locator(".piscan-candle").count()).toBe(0);
  expect(await page.locator(".piscan-badge").count()).toBe(0);
});
