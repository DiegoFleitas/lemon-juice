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

test("detects an instruction phrase hidden in an HTML comment, flagged as inComment", async ({
  page,
}) => {
  const result = await injectAndScan(page, "html-comments.html");
  const found = result.items.find(
    (i) => i.type === "instruction-phrase" && i.inComment === true
  );
  expect(found).toBeTruthy();
});

test("detects LLM control tokens hidden in an HTML comment, flagged as inComment", async ({
  page,
}) => {
  const result = await injectAndScan(page, "html-comments.html");
  const controlTokens = result.items.filter(
    (i) => i.type === "control-token" && i.inComment === true
  );
  expect(controlTokens.length).toBeGreaterThanOrEqual(2); // <|im_start|> and <|im_end|>
});

test("does not flag inComment on findings from ordinary visible/normal text", async ({
  page,
}) => {
  const result = await injectAndScan(page, "html-comments.html");
  const nonCommentFindings = result.items.filter((i) => !i.inComment);
  // The ordinary developer comment and the visible paragraph produce no
  // findings at all, so every finding on this fixture should be inComment.
  expect(nonCommentFindings.length).toBe(0);
});

test("highlights the element containing a comment-hidden finding", async ({ page }) => {
  await injectAndScan(page, "html-comments.html");
  const nearCommentDiv = page.locator("#near-comment");
  await expect(nearCommentDiv).toHaveAttribute("data-piscan-mark");
  await expect(nearCommentDiv.locator(".piscan-candle")).toBeAttached();
});
