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
            // These detectors emit LOW on their own — they are informational
            // and never convict alone. Contextual promotion may legitimately
            // raise one (a fullwidth-Unicode role label is only readable after
            // normalization; a fabricated dialogue inside an HTML comment is
            // invisible to a human but not to an LLM). So allow a promotion,
            // but require it to be EXPLAINED: an unexplained climb above LOW
            // means something promoted without recording why, which is the
            // shape a scoring regression takes.
            if (item.severity === "low") continue;
            expect(
              (item.contextual || []).length + (item.corroboration || []).length,
              `${file}: ${item.type} promoted to ${item.severity} with no recorded reason`
            ).toBeGreaterThan(0);
            expect(item.promotedFrom).toBe("low");
          }
        } else {
          const typed = result.items.filter((i) => i.type === expectedType);
          expect(typed.length).toBe(0);
        }
      });
    }
  }
}

// --- corroboration scoring (docs/plans/2026-08-03-corroboration-scoring.md) ---

test("corroborated payload in a comment reads as a likely injection attempt", async ({
  page,
}) => {
  const result = await injectAndScan(
    page,
    path.join(FIXTURES, "corroborated-payload.html")
  );
  expect(result.verdict).toBe("likely-injection");
  expect(result.corroborationCount).toBeGreaterThan(0);
  const blob = result.items.find((i) => i.type === "encoded-base64");
  expect(blob.severity).toBe("high");
  expect(blob.promotedFrom).toBe("medium");
});

// The noise tier's positive control: a MEDIUM invisible character with no
// corroboration must NOT reach suspicious. This is the false-positive-fatigue
// win — one stray zero-width space should not light up the badge.
test("a lone zero-width space is noise, not suspicious", async ({ page }) => {
  const result = await injectAndScan(page, path.join(FIXTURES, "lone-zero-width.html"));
  expect(result.verdict).toBe("noise");
  expect(result.corroborationCount).toBe(0);
});

// Pages that merely *discuss* prompt injection, or that use hidden text
// legitimately, must not climb. If promotion pushes any of these to
// suspicious, the rule in applyContextualPromotion is wrong — fix the rule,
// not this expectation.
const MUST_STAY_QUIET = [
  "instruction-phrases.html",
  "baseline.html",
  "plaintext-gpl.html",
  "jwt-decoy.html",
  // Regression fixtures: both of these scored HIGH under same-element
  // co-location before it required proven concealment of the content.
  "accessible-chat.html",
  "docs-prompt-format.html",
];

for (const fixture of MUST_STAY_QUIET) {
  test(`${fixture} does not reach suspicious`, async ({ page }) => {
    const result = await injectAndScan(page, path.join(FIXTURES, fixture));
    expect(["clean", "noise"]).toContain(result.verdict);
  });
}

// Known and ACCEPTED false positive: a page teaching prompt injection by
// showing an encoded payload scores the same as one carrying it, because the
// bytes an LLM ingests are identical and "showcase vs. carry" is not
// mechanically decidable. It reaches likely-injection, not merely suspicious,
// because the decoded payload contains a control token — convicting
// corroboration — which takes the blob to HIGH, and a corroborated HIGH is the
// top tier. Documented in README.md. If this starts failing because the
// verdict dropped, someone added intent-guessing heuristics — that is a design
// change, not a fix.
test("a security writeup showing an encoded payload does promote (accepted FP)", async ({
  page,
}) => {
  const result = await injectAndScan(page, path.join(FIXTURES, "encoded-showcase.html"));
  expect(result.verdict).toBe("likely-injection");
  const blob = result.items.find((i) => i.type === "encoded-base64");
  expect(blob.severity).toBe("high");
  expect(blob.corroboration.some((c) => c.type === "control-token")).toBe(true);
});
