"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  snippet,
  colorFor,
  luminance,
  isTransparentBg,
  elementIsA11yHidden,
  collectRoots,
  deepQuerySelector,
} = require("../scan-helpers.js");

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

test("isTransparentBg: rgba(0,0,0,0) with spaces", () => {
  assert.equal(isTransparentBg("rgba(0, 0, 0, 0)"), true);
});

test("isTransparentBg: rgba(0,0,0,0) without spaces", () => {
  assert.equal(isTransparentBg("rgba(0,0,0,0)"), true);
});

test("isTransparentBg: 'transparent' keyword", () => {
  assert.equal(isTransparentBg("transparent"), true);
});

test("isTransparentBg: CSS Color 4 modern rgb(0 0 0 / 0) syntax", () => {
  assert.equal(isTransparentBg("rgb(0 0 0 / 0)"), true);
  assert.equal(isTransparentBg("rgba(0 0 0 / 0)"), true);
  assert.equal(isTransparentBg("rgb(0 0 0 / 0.0)"), true);
});

test("isTransparentBg: null/undefined/empty", () => {
  assert.equal(isTransparentBg(null), true);
  assert.equal(isTransparentBg(undefined), true);
  assert.equal(isTransparentBg(""), true);
});

test("isTransparentBg: decimal alpha format rgba(0,0,0,0.0)", () => {
  assert.equal(isTransparentBg("rgba(0, 0, 0, 0.0)"), true);
  assert.equal(isTransparentBg("rgba(0,0,0,0.0)"), true);
  assert.equal(isTransparentBg("rgba(0,0,0,0.00)"), true);
});

test("isTransparentBg: opaque colors return false", () => {
  assert.equal(isTransparentBg("rgb(0, 0, 0)"), false);
  assert.equal(isTransparentBg("rgb(255, 255, 255)"), false);
  assert.equal(isTransparentBg("rgba(0, 0, 0, 0.5)"), false);
  assert.equal(isTransparentBg("rgba(255, 0, 0, 0)"), false);
});

// elementIsA11yHidden only touches getAttribute and classList.contains, so a
// two-method stub covers it without a DOM harness.
function stubEl(className, ariaHidden) {
  const classes = className ? className.split(" ") : [];
  return {
    nodeType: 1,
    className: className || "",
    getAttribute: (name) => (name === "aria-hidden" ? (ariaHidden ?? null) : null),
    classList: { contains: (c) => classes.includes(c) },
  };
}

test("elementIsA11yHidden: aria-hidden", () => {
  assert.equal(elementIsA11yHidden(stubEl("", "true")), true);
  assert.equal(elementIsA11yHidden(stubEl("", "false")), false);
});

test("elementIsA11yHidden: framework screen-reader-only classes", () => {
  // These are what stop an accessible chat transcript
  // (<span class="element-invisible">Assistant:</span>) from corroborating
  // itself into a HIGH finding via applyContextualPromotion.
  for (const c of [
    "sr-only",
    "visually-hidden",
    "visuallyhidden",
    "element-invisible",
    "assistive-text",
    "a11y-hidden",
    "hidden-visually",
    "screen-reader-text",
  ])
    assert.equal(elementIsA11yHidden(stubEl(c)), true, c);
});

test("elementIsA11yHidden: ordinary classes are not a11y-hidden", () => {
  assert.equal(elementIsA11yHidden(stubEl("container prose")), false);
});

test("elementIsA11yHidden: hashed CSS-module visually-hidden classes", () => {
  // GitHub's class is prc-src-InternalVisuallyHidden-2YaI6.
  assert.equal(elementIsA11yHidden(stubEl("prc-src-InternalVisuallyHidden-2YaI6")), true);
});

test("elementIsA11yHidden: checks ancestor wrappers", () => {
  const wrapper = stubEl("sr-only");
  const inner = stubEl("");
  inner.parentElement = wrapper;
  assert.equal(elementIsA11yHidden(inner), true);

  const ariaWrapper = stubEl("", "true");
  const inner2 = stubEl("");
  inner2.parentElement = ariaWrapper;
  assert.equal(elementIsA11yHidden(inner2), true);

  const ordinary = stubEl("container");
  const inner3 = stubEl("");
  inner3.parentElement = ordinary;
  assert.equal(elementIsA11yHidden(inner3), false);
});

// collectRoots touches only nodeType, body, querySelectorAll("*"), shadowRoot,
// tagName and contentDocument, so a hand-rolled graph keeps this file DOM-free
// like the rest of it. `Node.DOCUMENT_NODE` is the one browser global it reads.
if (!globalThis.Node) globalThis.Node = { DOCUMENT_NODE: 9 };

function fakeEl(tagName, opts = {}) {
  return {
    nodeType: 1,
    tagName,
    shadowRoot: opts.shadowRoot || null,
    contentDocument: opts.contentDocument || null,
    querySelector: opts.querySelector || (() => null),
    querySelectorAll: () => opts.children || [],
  };
}

function fakeDoc(children = [], opts = {}) {
  return {
    nodeType: 9,
    body: fakeEl("BODY", { children }),
    querySelector: opts.querySelector || (() => null),
    querySelectorAll: () => children,
  };
}

function fakeShadowRoot(children = []) {
  return { nodeType: 11, querySelectorAll: () => children };
}

test("collectRoots: descends into same-origin iframe documents by default", () => {
  const frameDoc = fakeDoc([fakeEl("P")]);
  const doc = fakeDoc([fakeEl("IFRAME", { contentDocument: frameDoc })]);
  const roots = collectRoots(doc);
  assert.equal(roots.length, 2);
  assert.equal(roots[0], doc);
  assert.equal(roots[1], frameDoc);
});

test("collectRoots: skipIframes collects only the frame's own document", () => {
  const frameDoc = fakeDoc([fakeEl("P")]);
  const doc = fakeDoc([fakeEl("IFRAME", { contentDocument: frameDoc })]);
  const roots = collectRoots(doc, { skipIframes: true });
  assert.deepEqual(roots, [doc]);
});

test("collectRoots: skipIframes still collects open shadow roots", () => {
  const inner = fakeShadowRoot([fakeEl("P")]);
  const doc = fakeDoc([fakeEl("DIV", { shadowRoot: inner })]);
  const roots = collectRoots(doc, { skipIframes: true });
  assert.equal(roots.length, 2);
  assert.equal(roots[1], inner);
});

test("collectRoots: shadow roots are collected in both modes", () => {
  const inner = fakeShadowRoot([fakeEl("P")]);
  const doc = fakeDoc([fakeEl("DIV", { shadowRoot: inner })]);
  assert.equal(collectRoots(doc).length, collectRoots(doc, { skipIframes: true }).length);
});

test("collectRoots: an unreadable cross-origin frame is skipped, not thrown", () => {
  const frame = fakeEl("IFRAME");
  Object.defineProperty(frame, "contentDocument", {
    get() {
      throw new Error("SecurityError: cross-origin");
    },
  });
  const doc = fakeDoc([frame]);
  assert.deepEqual(collectRoots(doc), [doc]);
  assert.deepEqual(collectRoots(doc, { skipIframes: true }), [doc]);
});

test("collectRoots: options in the second position match the third-position form", () => {
  const frameDoc = fakeDoc([fakeEl("P")]);
  const doc = fakeDoc([fakeEl("IFRAME", { contentDocument: frameDoc })]);
  assert.deepEqual(
    collectRoots(doc, { skipIframes: true }),
    collectRoots(doc, [], { skipIframes: true })
  );
});

test("collectRoots: the pre-per-frame accumulator form still works", () => {
  const doc = fakeDoc([fakeEl("P")]);
  const acc = [];
  const roots = collectRoots(doc, acc);
  assert.equal(roots, acc);
  assert.deepEqual(roots, [doc]);
});

test("deepQuerySelector: still finds an id inside a same-origin iframe", () => {
  const marker = fakeEl("SPAN");
  const frameDoc = fakeDoc([], {
    querySelector: (sel) => (sel === "[data-piscan-id=pi-1]" ? marker : null),
  });
  const doc = fakeDoc([fakeEl("IFRAME", { contentDocument: frameDoc })]);
  assert.equal(deepQuerySelector(doc, "[data-piscan-id=pi-1]"), marker);
});
