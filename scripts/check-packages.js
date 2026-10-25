"use strict";

// Verifies the packaged artifacts instead of trusting the packaging scripts:
// one version across package.json/manifest.json, the derived Chrome manifest
// matching what the source manifest says, and exact file sets in both the
// Chrome staging directory and the Firefox zip. Run after both package steps.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { DIRS, FILES, chromeManifest } = require("./package-chrome.js");

const ROOT = path.resolve(__dirname, "..");
const DIST = path.join(ROOT, "dist");
const CHROME_DIR = path.join(DIST, "chrome");
const FIREFOX_ZIP = path.join(DIST, "lemon-juice.zip");

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

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

function expectedFiles() {
  const files = ["manifest.json", ...FILES];
  for (const dir of DIRS) {
    for (const child of walk(path.join(ROOT, dir))) files.push(`${dir}/${child}`);
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
const pkg = readJson(path.join(ROOT, "package.json"));
const sourceManifest = readJson(path.join(ROOT, "manifest.json"));
check(
  sourceManifest.version === pkg.version,
  `version drift: manifest.json ${sourceManifest.version} vs package.json ${pkg.version}`
);
check(
  /^\d+\.\d+\.\d+$/.test(pkg.version),
  `package.json version is not X.Y.Z: ${pkg.version}`
);

// 2. Chrome staging matches the derived manifest and carries exactly the source files.
if (!fs.existsSync(path.join(CHROME_DIR, "manifest.json"))) {
  failures.push(
    "dist/chrome/manifest.json missing - run `pnpm run package:chrome` first"
  );
} else {
  const staged = readJson(path.join(CHROME_DIR, "manifest.json"));
  try {
    assert.deepEqual(staged, chromeManifest());
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
  const { missing, unexpected } = difference(expectedFiles(), walk(CHROME_DIR).sort());
  check(missing.length === 0, `dist/chrome is missing: ${missing.join(", ")}`);
  check(
    unexpected.length === 0,
    `dist/chrome has unexpected files: ${unexpected.join(", ")}`
  );
}

// 3. Firefox zip carries exactly the source files.
if (!fs.existsSync(FIREFOX_ZIP)) {
  failures.push("dist/lemon-juice.zip missing - run `pnpm run package` first");
} else {
  let entries = [];
  try {
    entries = readZipEntries(FIREFOX_ZIP).sort();
  } catch (error) {
    failures.push(error.message);
  }
  if (entries.length) {
    const { missing, unexpected } = difference(expectedFiles(), entries);
    check(missing.length === 0, `lemon-juice.zip is missing: ${missing.join(", ")}`);
    check(
      unexpected.length === 0,
      `lemon-juice.zip has unexpected files: ${unexpected.join(", ")}`
    );
  }
}

if (failures.length) {
  console.error("Packaging checks failed:");
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}
console.log(
  "Packaging checks passed: version sync, Chrome manifest, Chrome staging, Firefox zip."
);
