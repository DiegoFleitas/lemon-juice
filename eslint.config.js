"use strict";

const js = require("@eslint/js");

const browserExtensionGlobals = {
  browser: "readonly",
  chrome: "readonly",
  document: "readonly",
  window: "readonly",
  globalThis: "readonly",
  location: "readonly",
  getComputedStyle: "readonly",
  CSS: "readonly",
  Node: "readonly",
  NodeFilter: "readonly",
  ShadowRoot: "readonly",
  URL: "readonly",
  Blob: "readonly",
  setTimeout: "readonly",
  atob: "readonly",
  TextDecoder: "readonly",
  module: "writable",
};

const nodeGlobals = {
  module: "writable",
  require: "readonly",
  Buffer: "readonly",
  console: "readonly",
  process: "readonly",
  __dirname: "readonly",
};

module.exports = [
  js.configs.recommended,
  {
    // Generated output and local test artifacts. `dist/` holds copies of the
    // source with a generated manifest; linting those copies would also flag
    // browser globals the per-file config below does not cover.
    ignores: [
      "assets/**",
      "icons/**",
      "dist/**",
      "coverage/**",
      "test-results/**",
      "playwright-report/**",
    ],
  },
  {
    files: ["detectors.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...browserExtensionGlobals, ...nodeGlobals },
    },
  },
  {
    files: ["scan-helpers.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...browserExtensionGlobals, ...nodeGlobals },
    },
  },
  {
    files: ["scan.js", "popup.js"],
    languageOptions: {
      sourceType: "script",
      globals: browserExtensionGlobals,
    },
  },
  {
    files: ["__tests__/**/*.js", "!__tests__/e2e/**"],
    languageOptions: {
      sourceType: "commonjs",
      globals: nodeGlobals,
    },
  },
  {
    files: ["__tests__/e2e/**/*.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { ...nodeGlobals, ...browserExtensionGlobals },
    },
  },
  {
    files: ["eslint.config.js", "playwright.config.js", "scripts/**/*.js"],
    languageOptions: {
      sourceType: "commonjs",
      globals: nodeGlobals,
    },
  },
];
