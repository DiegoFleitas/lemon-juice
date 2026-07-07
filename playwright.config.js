"use strict";

const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testMatch: "**/__tests__/e2e/**/*.spec.js",
  use: {
    browserName: "firefox",
  },
});
