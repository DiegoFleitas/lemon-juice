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

async function injectAndScan(page, fixturePath) {
  await page.goto(`file://${fixturePath}`);
  await page.evaluate(DETECTORS_SRC);
  await page.evaluate(HELPERS_SRC);
  await page.evaluate(SCAN_SRC);
  return page.evaluate(() => window.__PIScanResult);
}

const VECTORS = {
  contextSwitch: "context-switch",
  compoundInstructions: "instruction-phrase",
  payloadSplitting: null,
  fillInBlank: null,
};

for (const [vector, expectedType] of Object.entries(VECTORS)) {
  for (const polarity of ["positive", "negative"]) {
    const dir = path.join(FIXTURES, vector, polarity);
    let files;
    try {
      files = fs.readdirSync(dir).filter((f) => f.endsWith(".html"));
    } catch {
      continue;
    }
    for (const file of files) {
      test(`${vector}/${polarity}/${file}`, async ({ page }) => {
        const fixturePath = path.join(dir, file);
        const result = await injectAndScan(page, fixturePath);

        if (expectedType === null) {
          expect(result.count).toBe(0);
        } else if (polarity === "positive") {
          const typed = result.items.filter((i) => i.type === expectedType);
          expect(typed.length).toBeGreaterThanOrEqual(1);
          for (const item of typed) {
            expect(item.severity).toBe("low");
          }
        } else {
          const typed = result.items.filter((i) => i.type === expectedType);
          expect(typed.length).toBe(0);
        }
      });
    }
  }
}
