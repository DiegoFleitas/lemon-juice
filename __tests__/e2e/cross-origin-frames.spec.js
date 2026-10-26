"use strict";

// Cross-origin iframe scanning (issue #17) — two real HTTP origins.
//
// Playwright can evaluate in every frame regardless of origin, which is what the
// extension's `scripting.executeScript({ allFrames: true })` does for Firefox
// under `activeTab`. That lets this spec exercise the per-frame scanning mode and
// the merge end to end without installing the extension: each frame is flagged
// `__PISCAN_PER_FRAME__`, the scanner is injected into each, and the results are
// merged exactly as popup.js does.
//
// What this cannot cover: whether Firefox's activeTab really reaches a
// cross-origin frame (the plan's load-bearing assumption, bug 1653408) and
// Chrome's graceful degradation. Both need a manual temporary-add-on run; see
// docs/limitations.md and the plan's unticked verification task.

const http = require("http");
const fs = require("fs");
const path = require("path");
const { test, expect } = require("@playwright/test");

const FIXTURES = path.resolve(__dirname, "..", "fixtures", "cross-origin-frames");
const ROOT = path.resolve(__dirname, "..", "..");
const DETECTORS_SRC = fs.readFileSync(path.join(ROOT, "detectors.js"), "utf-8");
const HELPERS_SRC = fs.readFileSync(path.join(ROOT, "scan-helpers.js"), "utf-8");
const SCAN_SRC = fs.readFileSync(path.join(ROOT, "scan.js"), "utf-8");

// popup.js is a browser script; stub just enough to require it in Node, the same
// way __tests__/popup.test.js does, so the merge used here is the real one.
const popupStub = {
  textContent: "",
  className: "",
  addEventListener() {},
  replaceChildren() {},
};
globalThis.document = { getElementById: () => popupStub };
globalThis.browser = {
  tabs: { query: async () => [] },
  scripting: { executeScript: async () => [] },
  action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
};
const { mergeFrameResults } = require("../../popup.js");

let servers = [];
let originA = "";
let originB = "";

function serve(transform) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const rel =
        decodeURIComponent(new URL(req.url, "http://localhost").pathname).replace(
          /^\/+/,
          ""
        ) || "host.html";
      const file = path.resolve(FIXTURES, rel);
      if (!file.startsWith(FIXTURES) || !fs.existsSync(file)) {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      const body = transform
        ? transform(fs.readFileSync(file, "utf-8"))
        : fs.readFileSync(file, "utf-8");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(body);
    });
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function originOf(server) {
  return `http://127.0.0.1:${server.address().port}`;
}

test.beforeAll(async () => {
  // The second origin's port is only known after listening, so the host page is
  // templated at request time.
  const serverB = await serve();
  originB = originOf(serverB);
  const serverA = await serve((html) =>
    html.replaceAll("{{CROSS_ORIGIN_ORIGIN}}", originB)
  );
  originA = originOf(serverA);
  servers = [serverA, serverB];
});

test.afterAll(async () => {
  await Promise.all(
    servers.map((server) => new Promise((resolve) => server.close(resolve)))
  );
});

// Mirrors popup.js's per-frame flow: flag every reachable frame, inject the
// scanner into each, then read each frame's own summary back.
async function scanPerFrame(page) {
  for (const frame of page.frames()) {
    await frame.evaluate(() => {
      window.__PISCAN_PER_FRAME__ = true;
    });
    await frame.evaluate(DETECTORS_SRC);
    await frame.evaluate(HELPERS_SRC);
    await frame.evaluate(SCAN_SRC);
  }
  const perFrame = [];
  let frameId = 0;
  for (const frame of page.frames()) {
    const result = await frame.evaluate(() => window.__PIScanResult || null);
    perFrame.push({ frameId: frameId++, result });
  }
  return perFrame;
}

async function openHostPage(page) {
  await page.goto(`${originA}/host.html`);
  for (const frame of page.frames()) await frame.waitForLoadState("load");
  expect(page.frames()).toHaveLength(3); // top + same-origin + cross-origin
}

test("per-frame scanning finds the cross-origin payload exactly once", async ({
  page,
}) => {
  await openHostPage(page);
  const merged = mergeFrameResults(await scanPerFrame(page));

  const crossOrigin = merged.items.filter((i) =>
    i.context?.includes("Cross-origin frame payload")
  );
  expect(crossOrigin).toHaveLength(1);
  // It came from a child frame, not the top document.
  expect(crossOrigin[0].frameId).toBeGreaterThan(0);
  // Target ids are frame-qualified so a click addresses the owning frame.
  expect(crossOrigin[0].targetId.startsWith(`${crossOrigin[0].frameId}:`)).toBe(true);
});

test("same-origin iframe content is not double-scanned in per-frame mode", async ({
  page,
}) => {
  await openHostPage(page);
  const merged = mergeFrameResults(await scanPerFrame(page));

  const sameOrigin = merged.items.filter((i) =>
    i.context?.includes("Same-origin frame payload")
  );
  // Exactly one: the frame reported it, the top document did not also traverse
  // into it. Two would mean the skipIframes mode regressed.
  expect(sameOrigin).toHaveLength(1);
  expect(sameOrigin[0].frameId).toBeGreaterThan(0);
});

test("control: the top document alone reaches the same-origin frame but not the cross-origin one", async ({
  page,
}) => {
  await openHostPage(page);
  // Legacy single-frame path: inject into the top frame only, with the flag off.
  await page.evaluate(() => {
    window.__PISCAN_PER_FRAME__ = false;
  });
  await page.evaluate(DETECTORS_SRC);
  await page.evaluate(HELPERS_SRC);
  await page.evaluate(SCAN_SRC);
  const topOnly = await page.evaluate(() => window.__PIScanResult);

  // Same-origin document is reachable via contentDocument, which is exactly why
  // a per-frame scan must not also walk it (the double-report above).
  expect(
    topOnly.items.some((i) => i.context?.includes("Same-origin frame payload"))
  ).toBe(true);
  // The cross-origin document is not reachable from the top document at all —
  // this is the gap issue #17 exists to close.
  expect(
    topOnly.items.some((i) => i.context?.includes("Cross-origin frame payload"))
  ).toBe(false);
});

test("each frame keeps its own overlay, drawn inside its own document", async ({
  page,
}) => {
  await openHostPage(page);
  await scanPerFrame(page);

  const overlays = [];
  for (const frame of page.frames()) {
    overlays.push(
      await frame.evaluate(() => document.querySelectorAll(".piscan-overlay").length)
    );
  }
  // Every frame that produced a finding drew its marker into its own document;
  // none of them leaked an overlay into the top document for the other frame.
  expect(overlays[0]).toBe(0);
  expect(overlays[1]).toBe(1);
  expect(overlays[2]).toBe(1);
});
