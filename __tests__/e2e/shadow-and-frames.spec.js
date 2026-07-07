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

test("detects a finding inside an open shadow root, highlighted and badged", async ({
  page,
}) => {
  const result = await injectAndScan(page, "shadow-dom.html");
  const zws = result.items.filter(
    (i) => i.type === "invisible" && i.name === "ZERO WIDTH SPACE"
  );
  // one in the open host, one in the nested-inner host, one in the closed
  // host that must NOT be found (asserted separately below) — so exactly 2
  // here, not 3.
  expect(zws.length).toBe(2);

  const openHost = page.locator("#open-host");
  const markedInOpenShadow = await openHost.evaluate(
    (host) =>
      !!host.shadowRoot.getElementById("open-zws").getAttribute("data-piscan-mark")
  );
  expect(markedInOpenShadow).toBe(true);
  const candleInOpenShadow = await openHost.evaluate(
    (host) =>
      host.shadowRoot.getElementById("open-zws").querySelector(".piscan-candle") !== null
  );
  expect(candleInOpenShadow).toBe(true);
  const badgeInOpenShadow = await openHost.evaluate(
    (host) =>
      host.shadowRoot.getElementById("open-zws").querySelector(".piscan-badge") !== null
  );
  expect(badgeInOpenShadow).toBe(true);
});

test("detects a CSS-hidden finding inside an open shadow root", async ({ page }) => {
  const result = await injectAndScan(page, "shadow-dom.html");
  const hidden = result.items.find(
    (i) => i.type === "css-hidden" && i.context === "Hidden in open shadow root"
  );
  expect(hidden).toBeTruthy();
});

test("detects a finding inside a shadow root nested inside another shadow root", async ({
  page,
}) => {
  const result = await injectAndScan(page, "shadow-dom.html");
  const found = result.items.some(
    (i) => i.context && i.context.includes("Zero width space in nested shadow root")
  );
  expect(found).toBe(true);
});

test("does not detect content inside a closed shadow root", async ({ page }) => {
  const result = await injectAndScan(page, "shadow-dom.html");
  const found = result.items.some(
    (i) => i.context && i.context.includes("Zero width space in closed shadow root")
  );
  expect(found).toBe(false);
});

test("detects a finding inside a same-origin iframe", async ({ page }) => {
  const result = await injectAndScan(page, "iframe-same-origin.html");
  const found = result.items.some(
    (i) => i.context && i.context.includes("Zero width space in iframe")
  );
  expect(found).toBe(true);

  const frame = page.locator("#frame");
  const marked = await frame.evaluate(
    (el) =>
      !!el.contentDocument.getElementById("iframe-zws").getAttribute("data-piscan-mark")
  );
  expect(marked).toBe(true);
});

test("detects a CSS-hidden finding inside a same-origin iframe", async ({ page }) => {
  const result = await injectAndScan(page, "iframe-same-origin.html");
  const hidden = result.items.find(
    (i) => i.type === "css-hidden" && i.context === "Hidden in iframe"
  );
  expect(hidden).toBeTruthy();
});

test("detects a finding inside a shadow root nested inside a same-origin iframe", async ({
  page,
}) => {
  const result = await injectAndScan(page, "iframe-same-origin.html");
  const found = result.items.some(
    (i) =>
      i.context && i.context.includes("Zero width space in shadow root nested in iframe")
  );
  expect(found).toBe(true);
});

test("clearMarks removes marks/candles/badges from a shadow root and an iframe on re-scan", async ({
  page,
}) => {
  await injectAndScan(page, "shadow-dom.html");
  const openHost = page.locator("#open-host");
  const markedBefore = await openHost.evaluate(
    (host) => host.shadowRoot.querySelectorAll("[data-piscan-mark]").length
  );
  expect(markedBefore).toBeGreaterThan(0);

  await injectAndScan(page, "shadow-dom.html");
  const markedAfter = await openHost.evaluate(
    (host) => host.shadowRoot.querySelectorAll("[data-piscan-mark]").length
  );
  expect(markedAfter).toBe(markedBefore);
  const candlesAfter = await openHost.evaluate(
    (host) => host.shadowRoot.querySelectorAll(".piscan-candle").length
  );
  expect(candlesAfter).toBe(markedAfter);
});

test("deepQuerySelector finds an element by data-piscan-id inside a shadow root and an iframe", async ({
  page,
}) => {
  await injectAndScan(page, "shadow-dom.html");
  const foundInShadow = await page.evaluate(() => {
    const id = document.getElementById("open-host").shadowRoot.getElementById("open-zws")
      .dataset.piscanId;
    const el = window.__PIScannerHelpers.deepQuerySelector(
      document,
      `[data-piscan-id="${id}"]`
    );
    return el && el.id === "open-zws";
  });
  expect(foundInShadow).toBe(true);

  await injectAndScan(page, "iframe-same-origin.html");
  const foundInIframe = await page.evaluate(() => {
    const frameDoc = document.getElementById("frame").contentDocument;
    const id = frameDoc.getElementById("iframe-zws").dataset.piscanId;
    const el = window.__PIScannerHelpers.deepQuerySelector(
      document,
      `[data-piscan-id="${id}"]`
    );
    return el && el.id === "iframe-zws";
  });
  expect(foundInIframe).toBe(true);
});
