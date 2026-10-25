"use strict";

// Verifies the packaged artifacts instead of trusting the packaging scripts:
// one version across package.json/manifest.json, each staged build matching the
// manifest it was derived from, and exact file sets in dist/firefox, dist/chrome
// and the Firefox zip. Run after the package steps.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const packaging = require("./packaging.js");

const ROOT = packaging.ROOT;
const DIST = path.join(ROOT, "dist");
const FIREFOX_DIR = path.join(DIST, "firefox");
const FIREFOX_ZIP = path.join(DIST, "lemon-juice.zip");
const CHROME_DIR = path.join(DIST, "chrome");

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

function expectedFiles() {
  const files = ["manifest.json", ...packaging.FILES];
  for (const dir of packaging.DIRS) {
    for (const child of packaging.walk(path.join(ROOT, dir)))
      files.push(`${dir}/${child}`);
  }
  return files.sort();
}

function difference(expected, actual) {
  const want = new Set(expected);
  const have = new Set(actual);
  return {
    missing: expected.filter((file) => !have.has(file)),
    unexpected: actual.filter((file) => !want.has(file)),
  };
}

function compareFiles(label, actual) {
  const { missing, unexpected } = difference(expectedFiles(), actual.slice().sort());
  check(missing.length === 0, `${label} is missing: ${missing.join(", ")}`);
  check(
    unexpected.length === 0,
    `${label} has unexpected files: ${unexpected.join(", ")}`
  );
}

// Minimal central-directory reader; listing names needs no decompression.
function readZipEntries(file) {
  const buf = fs.readFileSync(file);
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i >= buf.length - 65557; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error(`${path.basename(file)} is not a zip archive`);
  const entries = [];
  const count = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i += 1) {
    if (buf.readUInt32LE(offset) !== 0x02014b50) {
      throw new Error("corrupt zip central directory");
    }
    const nameLength = buf.readUInt16LE(offset + 28);
    const extraLength = buf.readUInt16LE(offset + 30);
    const commentLength = buf.readUInt16LE(offset + 32);
    entries.push(buf.toString("utf8", offset + 46, offset + 46 + nameLength));
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries.filter((name) => !name.endsWith("/"));
}

// 1. One version everywhere.
const pkg = packaging.readJson(path.join(ROOT, "package.json"));
const sourceManifest = packaging.readJson(path.join(ROOT, "manifest.json"));
check(
  sourceManifest.version === pkg.version,
  `version drift: manifest.json ${sourceManifest.version} vs package.json ${pkg.version}`
);
check(
  /^\d+\.\d+\.\d+$/.test(pkg.version),
  `package.json version is not X.Y.Z: ${pkg.version}`
);

// 2. Firefox staging is the source manifest plus exactly the source files.
if (!fs.existsSync(path.join(FIREFOX_DIR, "manifest.json"))) {
  failures.push("dist/firefox/manifest.json missing - run `pnpm run package` first");
} else {
  const staged = packaging.readJson(path.join(FIREFOX_DIR, "manifest.json"));
  try {
    assert.deepEqual(staged, sourceManifest);
  } catch {
    failures.push("dist/firefox/manifest.json no longer matches manifest.json");
  }
  compareFiles("dist/firefox", packaging.walk(FIREFOX_DIR));
}

// 3. Chrome staging matches the derived manifest and carries exactly the source files.
if (!fs.existsSync(path.join(CHROME_DIR, "manifest.json"))) {
  failures.push(
    "dist/chrome/manifest.json missing - run `pnpm run package:chrome` first"
  );
} else {
  const staged = packaging.readJson(path.join(CHROME_DIR, "manifest.json"));
  try {
    assert.deepEqual(staged, packaging.chromeManifest());
  } catch {
    failures.push(
      "dist/chrome/manifest.json no longer matches the manifest derived from manifest.json"
    );
  }
  check(
    !("browser_specific_settings" in staged),
    "Chrome manifest still contains browser_specific_settings"
  );
  check(
    !("host_permissions" in staged),
    "Chrome manifest unexpectedly declares host_permissions"
  );
  check(
    JSON.stringify(staged.permissions) === JSON.stringify(sourceManifest.permissions),
    "Chrome permissions differ from the Firefox manifest"
  );
  check(
    staged.version === sourceManifest.version,
    "Chrome manifest version differs from the source manifest"
  );
  compareFiles("dist/chrome", packaging.walk(CHROME_DIR));
}

// 4. Firefox zip carries exactly the same file set.
if (!fs.existsSync(FIREFOX_ZIP)) {
  failures.push("dist/lemon-juice.zip missing - run `pnpm run package` first");
} else {
  let entries = [];
  try {
    entries = readZipEntries(FIREFOX_ZIP);
  } catch (error) {
    failures.push(error.message);
  }
  if (entries.length) compareFiles("lemon-juice.zip", entries);
}

if (failures.length) {
  console.error("Packaging checks failed:");
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}
console.log(
  "Packaging checks passed: version sync, staged manifests, file sets, Firefox zip."
);
