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

test("a fake reasoning frame concealed in a comment is promoted by placement", async ({
  page,
}) => {
  const result = await injectAndScan(page, "fake-reasoning-comment.html");
  const frame = result.items.find(
    (i) => i.type === "fake-reasoning-frame" && i.inComment === true
  );
  expect(frame).toBeTruthy();
  expect(["suspicious", "likely-injection"]).toContain(result.verdict);
});

test("distinct generic control tokens in one text node stay separate findings", async ({
  page,
}) => {
  const result = await injectAndScan(page, "fake-syntax-tokens.html");
  const tokens = result.items.filter((i) => i.type === "control-token");
  expect(tokens).toHaveLength(6);
  expect(tokens.map((i) => i.match).sort()).toEqual(
    [
      "<|tool calls end|>",
      "<|user message begin|>",
      "<sop>",
      "<start_of_turn>",
      "<｜begin▁of▁sentence｜>",
      "[gMASK]",
    ].sort()
  );
});
