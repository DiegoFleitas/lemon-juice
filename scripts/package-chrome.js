"use strict";

// Stages a Chrome-flavoured copy of the extension in dist/chrome: the shared
// source files plus a manifest derived from manifest.json. Keeping one source
// manifest means the two browsers cannot drift on permissions, CSP or version.
//
// Chrome does not understand the Gecko-only browser_specific_settings block, so
// that block is dropped. The description is replaced because manifest.json
// describes the Firefox build.
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const OUT = path.join(ROOT, "dist", "chrome");

const FILES = ["popup.html", "popup.js", "detectors.js", "scan-helpers.js", "scan.js"];
const DIRS = ["icons"];

const CHROME_DESCRIPTION =
  "Chrome extension that finds SOME hidden text and prompt-injection payloads on web pages before you hand them to an AI.";

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

function chromeManifest() {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  delete manifest.browser_specific_settings;
  manifest.description = CHROME_DESCRIPTION;
  return manifest;
}

function main() {
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(
    path.join(OUT, "manifest.json"),
    JSON.stringify(chromeManifest(), null, 2) + "\n"
  );
  for (const file of FILES) fs.copyFileSync(path.join(ROOT, file), path.join(OUT, file));
  for (const dir of DIRS) copyDir(path.join(ROOT, dir), path.join(OUT, dir));

  console.log(`Chrome extension staged at ${path.relative(ROOT, OUT)}`);
  console.log(
    "Load it unpacked from chrome://extensions, or zip that directory for the Chrome Web Store."
  );
}

module.exports = { CHROME_DESCRIPTION, DIRS, FILES, chromeManifest, copyDir, main };

if (require.main === module) main();
