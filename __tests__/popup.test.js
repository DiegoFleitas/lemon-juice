"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

// Minimal stubs so popup.js can load under Node without a DOM or browser API.
const stub = { textContent: "", addEventListener() {}, replaceChildren() {} };
globalThis.document = { getElementById: () => stub };
globalThis.browser = {
  tabs: { query: async () => [] },
  scripting: { executeScript: async () => [] },
  action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
};

const { typeLabel } = require("../popup.js");

test("typeLabel: unicode-tag", () => {
  const result = typeLabel({ type: "unicode-tag", decoded: "hello" });
  assert.match(result, /Invisible ASCII-smuggling character/);
  assert.match(result, /hello/);
});

test("typeLabel: unicode-tag without decoded", () => {
  const result = typeLabel({ type: "unicode-tag" });
  assert.match(result, /Invisible ASCII-smuggling character/);
  assert.doesNotMatch(result, /decodes to/);
});

test("typeLabel: invisible", () => {
  const result = typeLabel({
    type: "invisible",
    name: "ZERO WIDTH SPACE",
    hex: "U+200B",
  });
  assert.match(result, /Invisible character/);
  assert.match(result, /ZERO WIDTH SPACE/);
  assert.match(result, /U\+200B/);
});

test("typeLabel: encoded-base64", () => {
  const result = typeLabel({ type: "encoded-base64", decoded: "ignore" });
  assert.match(result, /Encoded blob/);
  assert.match(result, /ignore/);
});

test("typeLabel: encoded-base64 with JWT", () => {
  const result = typeLabel({
    type: "encoded-base64",
    decoded: "header.payload.sig",
    likelyJwt: true,
  });
  assert.match(result, /looks like a JWT/);
});

test("typeLabel: encoded-percent", () => {
  const result = typeLabel({ type: "encoded-percent", decoded: "hello" });
  assert.match(result, /Percent-encoded blob/);
});

test("typeLabel: encoded-hex-escape", () => {
  const result = typeLabel({ type: "encoded-hex-escape", decoded: "hello" });
  assert.match(result, /Hex-escaped blob/);
});

test("typeLabel: encoded-spaced-hex", () => {
  const result = typeLabel({ type: "encoded-spaced-hex", decoded: "hello" });
  assert.match(result, /Space-separated hex byte blob/);
});

test("typeLabel: encoded-unicode-escape", () => {
  const result = typeLabel({ type: "encoded-unicode-escape", decoded: "ignore" });
  assert.match(result, /\\uXXXX-escaped blob/);
});

test("typeLabel: encoded-html-entity", () => {
  const result = typeLabel({ type: "encoded-html-entity", decoded: "ignore" });
  assert.match(result, /HTML-entity-encoded blob/);
});

test("typeLabel: variation-selector-smuggling", () => {
  const result = typeLabel({ type: "variation-selector-smuggling", decoded: "evil" });
  assert.match(result, /Hidden variation-selector payload/);
});

test("typeLabel: sneaky-bits-smuggling", () => {
  const result = typeLabel({ type: "sneaky-bits-smuggling", decoded: "data" });
  assert.match(result, /Hidden invisible-bit-encoded payload/);
});

test("typeLabel: control-token", () => {
  const result = typeLabel({ type: "control-token", match: "<|im_start|>" });
  assert.match(result, /LLM chat-template control token/);
  assert.match(result, /\|im_start\|/);
});

test("typeLabel: css-hidden", () => {
  const result = typeLabel({
    type: "css-hidden",
    reasons: ["font-size 0.5px", "opacity:0"],
  });
  assert.match(result, /Visually hidden text/);
  assert.match(result, /font-size 0\.5px/);
  assert.match(result, /opacity:0/);
});

test("typeLabel: css-hidden with a11y downgrade", () => {
  const result = typeLabel({
    type: "css-hidden",
    reasons: ["opacity:0"],
    likelyA11y: true,
  });
  assert.match(result, /accessibility markup/);
});

test("typeLabel: instruction-phrase", () => {
  const result = typeLabel({
    type: "instruction-phrase",
    match: "ignore all previous instructions",
  });
  assert.match(result, /Instruction-like phrase/);
  assert.match(result, /ignore all previous instructions/);
});

test("typeLabel: instruction-phrase normalized", () => {
  const result = typeLabel({
    type: "instruction-phrase",
    match: "ignore",
    normalized: true,
  });
  assert.match(result, /revealed after removing/);
});

test("typeLabel: instruction-phrase in attribute", () => {
  const result = typeLabel({
    type: "instruction-phrase",
    match: "ignore",
    attrName: "aria-label",
  });
  assert.match(result, /in aria-label/);
});

test("typeLabel: excessive-combining-marks", () => {
  const result = typeLabel({
    type: "excessive-combining-marks",
    count: 12,
  });
  assert.match(result, /Excessive combining diacritical marks/);
  assert.match(result, /12/);
});

test("typeLabel: unknown type falls back to raw type string", () => {
  const result = typeLabel({ type: "something-new", attrName: "title" });
  assert.match(result, /something-new/);
  assert.match(result, /in title/);
});

test("typeLabel: unknown type without attrName", () => {
  const result = typeLabel({ type: "something-new" });
  assert.strictEqual(result, "something-new");
});
