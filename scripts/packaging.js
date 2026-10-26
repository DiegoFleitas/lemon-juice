"use strict";

// Shared packaging surface for both browser builds: the files that make up the
// extension, the directory walk used by scripts/check-packages.js, and staging
// into dist/<browser>. Keeping the file list here means the packagers and the
// checker cannot disagree about what an artifact should contain.
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

const FILES = ["popup.html", "popup.js", "detectors.js", "scan-helpers.js", "scan.js"];
const DIRS = ["icons"];

const CHROME_DESCRIPTION =
  "Chrome extension that finds SOME hidden text and prompt-injection payloads on web pages before you hand them to an AI.";

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(src, dst);
    else fs.copyFileSync(src, dst);
  }
}

// Chrome does not understand the Gecko-only browser_specific_settings block, so
// that block is dropped. The description is replaced because manifest.json
// describes the Firefox build.
function chromeManifest() {
  const manifest = readJson(path.join(ROOT, "manifest.json"));
  delete manifest.browser_specific_settings;
  manifest.description = CHROME_DESCRIPTION;
  return manifest;
}

function stage(outDir, manifest) {
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n"
  );
  for (const file of FILES)
    fs.copyFileSync(path.join(ROOT, file), path.join(outDir, file));
  for (const dir of DIRS) copyDir(path.join(ROOT, dir), path.join(outDir, dir));
}

// Relative POSIX-ish paths of every file under dir, for artifact comparisons.
function walk(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      for (const child of walk(abs)) files.push(`${entry.name}/${child}`);
    } else {
      files.push(entry.name);
    }
  }
  return files;
}

module.exports = {
  CHROME_DESCRIPTION,
  DIRS,
  FILES,
  ROOT,
  chromeManifest,
  copyDir,
  readJson,
  stage,
  walk,
};
