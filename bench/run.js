#!/usr/bin/env node
"use strict";

/**
 * Lemon Juice detection benchmark.
 *
 *   node bench/run.js [--seed=42] [--tag=baseline]
 *
 * Runs the pure detector (`detectors.js`) over a synthetic attack matrix and a
 * benign corpus, writes a CSV of every case plus a markdown summary, and prints
 * the summary to stdout. No network, no DOM, no browser: this measures the
 * detection layer, which is what `scanText` is.
 */

const fs = require("fs");
const path = require("path");
const { buildAttackCases, loadBenign } = require("./lib/corpus");
const { scan } = require("./lib/detect");
const { summarize, toMarkdown } = require("./lib/metrics");

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split("=").slice(1).join("=") : fallback;
}

const seed = Number(arg("seed", "42"));
const now = new Date();
const date = now.toISOString().slice(0, 10);
// Default tag is a timestamp, so a plain `node bench/run.js` can never clobber a
// committed run. An explicit tag still refuses to overwrite unless --force,
// because the before/after pair is the evidence and silent replacement would
// destroy the delta.
const stamp = now.toISOString().slice(11, 19).replace(/:/g, "");
const tag = arg("tag", `run-${stamp}`);
const force = process.argv.includes("--force");

const rows = [];

for (const c of buildAttackCases()) {
  const r = scan(c.text);
  rows.push({
    kind: "attack",
    id: c.id,
    category: c.category,
    technique: c.technique,
    payload: c.payload,
    payload_class: c.payloadClass,
    chars: c.chars,
    findings: r.findings,
    high: r.high,
    medium: r.medium,
    low: r.low,
    worst: r.worst || "",
    verdict: r.verdict,
    flagged_any: r.flaggedAny,
    flagged_medium: r.flaggedMedium,
    flagged_verdict: r.flaggedVerdict,
    recovered: r.recovered,
    ms: Math.round(r.elapsedMs * 1000) / 1000,
    types: r.types.join("|"),
  });
}

for (const b of loadBenign()) {
  const r = scan(b.text);
  rows.push({
    kind: "benign",
    id: b.id,
    category: "benign",
    technique: "none",
    payload: "",
    payload_class: "",
    chars: b.text.length,
    findings: r.findings,
    high: r.high,
    medium: r.medium,
    low: r.low,
    worst: r.worst || "",
    verdict: r.verdict,
    flagged_any: r.flaggedAny,
    flagged_medium: r.flaggedMedium,
    flagged_verdict: r.flaggedVerdict,
    recovered: false,
    ms: Math.round(r.elapsedMs * 1000) / 1000,
    types: r.types.join("|"),
  });
}

const summary = summarize(rows);
const headers = [
  "kind",
  "id",
  "category",
  "technique",
  "payload",
  "payload_class",
  "chars",
  "findings",
  "high",
  "medium",
  "low",
  "worst",
  "verdict",
  "flagged_any",
  "flagged_medium",
  "flagged_verdict",
  "recovered",
  "ms",
  "types",
];

function csvCell(v) {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const outDir = path.join(__dirname, "results");
fs.mkdirSync(outDir, { recursive: true });
const base = `${date}-${tag}`;
const csvPath = path.join(outDir, `${base}.csv`);
const mdPath = path.join(outDir, `${base}.md`);

if (!force && (fs.existsSync(csvPath) || fs.existsSync(mdPath))) {
  console.error(
    `refusing to overwrite ${path.relative(process.cwd(), csvPath)}\n` +
      `pick a new name with --tag=<name>, or pass --force to replace it.\n` +
      `committed runs are evidence: 2026-10-20-before-smallcaps, 2026-10-20-after-smallcaps`
  );
  process.exit(1);
}

fs.writeFileSync(
  csvPath,
  [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => csvCell(r[h])).join(",")),
  ].join("\n") + "\n"
);

const meta = { date, seed, tag, rows: rows.length };
const md = toMarkdown(summary, meta);
fs.writeFileSync(mdPath, md + "\n");

console.log(md);
console.log("");
console.log(`CSV:  ${path.relative(process.cwd(), csvPath)}`);
console.log(`MD:   ${path.relative(process.cwd(), mdPath)}`);
