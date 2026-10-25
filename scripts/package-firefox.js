"use strict";

// Stages the Firefox build in dist/firefox. The manifest is copied unchanged;
// this directory is what `web-ext lint` checks and what the zip step packs, so
// the linter validates the same file set that ships.
const path = require("path");

const packaging = require("./packaging.js");

function main() {
  const out = path.join(packaging.ROOT, "dist", "firefox");
  packaging.stage(out, packaging.readJson(path.join(packaging.ROOT, "manifest.json")));
  console.log(`Firefox extension staged at ${path.relative(packaging.ROOT, out)}`);
}

module.exports = { main };

if (require.main === module) main();
