"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { snippet, colorFor, luminance } = require("../scan-helpers.js");

test("snippet: short text is returned as-is", () => {
  assert.equal(snippet("hello world"), "hello world");
});

test("snippet: trims whitespace", () => {
  assert.equal(snippet("  hello  "), "hello");
});

test("snippet: collapses internal whitespace", () => {
  assert.equal(snippet("a    b\tc\n\nd"), "a b c d");
});

test("snippet: truncates text longer than 90 chars", () => {
  const long = "x".repeat(100);
  const result = snippet(long);
  assert.equal(result.length, 91);
  assert.equal(result, "x".repeat(90) + "\u2026");
});

test("colorFor: high severity returns red", () => {
  assert.equal(colorFor("high"), "#e5484d");
});

test("colorFor: medium severity returns amber", () => {
  assert.equal(colorFor("medium"), "#f5a623");
});

test("colorFor: low severity returns blue", () => {
  assert.equal(colorFor("low"), "#3b82f6");
});

test("luminance: pure white returns 255", () => {
  assert.equal(luminance("rgb(255,255,255)"), 255);
});

test("luminance: pure black returns 0", () => {
  assert.equal(luminance("rgb(0,0,0)"), 0);
});

test("luminance: near-white and white are within threshold", () => {
  const white = luminance("rgb(255,255,255)");
  const nearWhite = luminance("rgb(245,245,245)");
  assert.ok(Math.abs(white - nearWhite) < 30);
});

test("luminance: black and white differ by more than threshold", () => {
  assert.ok(Math.abs(luminance("rgb(0,0,0)") - luminance("rgb(255,255,255)")) >= 30);
});
