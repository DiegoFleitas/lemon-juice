#!/usr/bin/env node
"use strict";

/**
 * Deterministic input export for the NVIDIA guardrail benchmark.
 *
 *   node bench/nvidia-guardrails/export-inputs.js
 *
 * Writes `inputs/inputs.jsonl`, one row per case, in a fixed order, with a
 * sha256 of the exact text each system sees. The guardrail runner and the
 * Lemon Juice scorer both read this file, so the comparison is on identical
 * bytes. `inputs/manifest.json` records counts and the file hash, so a
 * regenerated export can be diffed instead of trusted.
 *
 * Inputs are the same as the existing runners:
 *   - main:   `bench/lib/corpus.js` buildAttackCases() (84 attack cases)
 *   - garak:  `bench/garak/corpus.jsonl` payloads in file order (111 cases)
 *   - benign: `bench/corpora/benign/*.txt` sorted (26 pages), shared controls
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { buildAttackCases, loadBenign } = require("../lib/corpus");

const outDir = path.join(__dirname, "inputs");
const outPath = path.join(outDir, "inputs.jsonl");
const manifestPath = path.join(outDir, "manifest.json");

function sha256(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function makeRow({
  track,
  id,
  label,
  family,
  split = "",
  technique = "",
  payloadClass = "",
  probe,
  text,
}) {
  return {
    track,
    id,
    label,
    family,
    split,
    technique,
    payload_class: payloadClass,
    probe: probe || "",
    chars: text.length,
    sha256: sha256(text),
    text,
  };
}

function buildRows() {
  const rows = [];

  for (const c of buildAttackCases()) {
    rows.push(
      makeRow({
        track: "main",
        id: c.id,
        label: "attack",
        family: c.category,
        technique: c.technique,
        payloadClass: c.payloadClass,
        text: c.text,
      })
    );
  }

  const garakPath = path.join(__dirname, "..", "garak", "corpus.jsonl");
  const garak = fs
    .readFileSync(garakPath, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));

  for (const c of garak) {
    rows.push(
      makeRow({
        track: "garak",
        id: c.id,
        label: "attack",
        family: c.family,
        split: c.split,
        probe: c.probe,
        // The garak axis scores the raw payload, exactly as bench/garak.js does.
        text: c.payload,
      })
    );
  }

  for (const b of loadBenign()) {
    rows.push(
      makeRow({
        track: "benign",
        id: b.id,
        label: "benign",
        family: "benign",
        text: b.text,
      })
    );
  }

  return rows;
}

const rows = buildRows();
fs.mkdirSync(outDir, { recursive: true });

const body = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
const bodyHash = crypto.createHash("sha256").update(body, "utf8").digest("hex");
fs.writeFileSync(outPath, body, "utf8");

const countBy = (key) => {
  const counts = {};
  for (const r of rows) counts[r[key]] = (counts[r[key]] || 0) + 1;
  return counts;
};

const manifest = {
  generated_by: "bench/nvidia-guardrails/export-inputs.js",
  cases: rows.length,
  by_track: countBy("track"),
  by_label: countBy("label"),
  garak_by_family: rows
    .filter((r) => r.track === "garak")
    .reduce((acc, r) => ((acc[r.family] = (acc[r.family] || 0) + 1), acc), {}),
  garak_by_split: rows
    .filter((r) => r.track === "garak")
    .reduce((acc, r) => ((acc[r.split] = (acc[r.split] || 0) + 1), acc), {}),
  sha256: bodyHash,
  note:
    "Deterministic: the same repository commit produces the same file. " +
    "Lemon Juice and the guardrail are scored on the text field of these rows.",
};
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");

console.log(
  `wrote ${path.relative(process.cwd(), outPath)} (${rows.length} cases, sha256 ${bodyHash.slice(0, 16)})`
);
console.log(`tracks: ${JSON.stringify(manifest.by_track)}`);
