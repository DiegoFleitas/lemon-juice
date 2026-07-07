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
    ignores: ["assets/**", "icons/**"],
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
