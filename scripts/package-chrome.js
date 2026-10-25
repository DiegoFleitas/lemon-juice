"use strict";

// Stages a Chrome-flavoured copy of the extension in dist/chrome: the shared
// source files plus a manifest derived from manifest.json, so the two browsers
// cannot drift on permissions, CSP or version. The derivation lives in
// scripts/packaging.js and is also what scripts/check-packages.js verifies.
const path = require("path");

const packaging = require("./packaging.js");

function main() {
  const out = path.join(packaging.ROOT, "dist", "chrome");
  packaging.stage(out, packaging.chromeManifest());
  console.log(`Chrome extension staged at ${path.relative(packaging.ROOT, out)}`);
  console.log(
    "Load it unpacked from chrome://extensions, or zip that directory for the Chrome Web Store."
  );
}

module.exports = { ...packaging, main };

if (require.main === module) main();
