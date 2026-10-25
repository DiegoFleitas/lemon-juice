#!/usr/bin/env node
"use strict";

/**
 * Detection axis built from garak probe structure.
 *
 *   node bench/garak.js [--tag=baseline] [--force]
 *
 * The corpus is extracted once by bench/garak/extract.py and committed, so this
 * runner needs no Python, garak, or network. It scores the pure detector against
 * probe-derived encoding concealment and adversarial suffixes, and includes the
 * shared benign pages as false-positive controls.
 */

const fs = require("fs");
const path = require("path");
const { scan } = require("./lib/detect");

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split("=").slice(1).join("=") : fallback;
}

const corpusPath = path.join(__dirname, "garak", "corpus.jsonl");
const cases = fs
  .readFileSync(corpusPath, "utf8")
  .split("\n")
  .filter((line) => line.trim())
  .map((line) => JSON.parse(line));

const benignDir = path.join(__dirname, "corpora", "benign");
const benign = fs
  .readdirSync(benignDir)
  .filter((f) => f.endsWith(".txt"))
  .sort()
  .map((f) => ({
    id: `B-${f.replace(/\.txt$/, "")}`,
    text: fs.readFileSync(path.join(benignDir, f), "utf8"),
  }));

const rows = cases.map((c) => {
  const r = scan(c.payload);
  return {
    ...c,
    findings: r.findings,
    high: r.high,
    medium: r.medium,
    low: r.low,
    verdict: r.verdict,
    flagged_any: r.flaggedAny,
    flagged_medium: r.flaggedMedium,
    flagged_verdict: r.flaggedVerdict,
    recovered: r.recovered,
    ms: Math.round(r.elapsedMs * 1000) / 1000,
  };
});

const benignRows = benign.map((b) => {
  const r = scan(b.text);
  return {
    id: b.id,
    findings: r.findings,
    medium: r.medium,
    verdict: r.verdict,
    flagged_any: r.flaggedAny,
    flagged_medium: r.flaggedMedium,
    flagged_verdict: r.flaggedVerdict,
  };
});

const pct = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);
const rate = (list, key) => pct(list.filter((r) => r[key]).length, list.length);

function summary(list) {
  return {
    n: list.length,
    any: rate(list, "flagged_any"),
    medium: rate(list, "flagged_medium"),
    verdict: rate(list, "flagged_verdict"),
    recovered: rate(list, "recovered"),
  };
}

const families = [...new Set(rows.map((r) => r.family))].sort();
const byFamily = families.map((family) => {
  const list = rows.filter((r) => r.family === family);
  return { family, ...summary(list) };
});
const bySplit = ["dev", "holdout"].map((split) => ({
  split,
  ...summary(rows.filter((r) => r.split === split)),
}));
const overall = summary(rows);
const benignSummary = {
  n: benignRows.length,
  any: rate(benignRows, "flagged_any"),
  medium: rate(benignRows, "flagged_medium"),
  verdict: rate(benignRows, "flagged_verdict"),
};

const now = new Date();
const date = now.toISOString().slice(0, 10);
const stamp = now.toISOString().slice(11, 19).replace(/:/g, "");
const tag = arg("tag", `run-${stamp}`);
const force = process.argv.includes("--force");

const outDir = path.join(__dirname, "results");
fs.mkdirSync(outDir, { recursive: true });
const base = `${date}-garak-${tag}`;
const csvPath = path.join(outDir, `${base}.csv`);
const mdPath = path.join(outDir, `${base}.md`);

if (!force && (fs.existsSync(csvPath) || fs.existsSync(mdPath))) {
  console.error(
    `refusing to overwrite ${path.relative(process.cwd(), csvPath)}; use --tag= or --force`
  );
  process.exit(1);
}

const headers = [
  "family",
  "id",
  "probe",
  "split",
  "findings",
  "high",
  "medium",
  "low",
  "verdict",
  "flagged_any",
  "flagged_medium",
  "flagged_verdict",
  "recovered",
  "ms",
];
const csvCell = (v) => {
  const s = String(v ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
fs.writeFileSync(
  csvPath,
  [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => csvCell(r[h])).join(",")),
  ].join("\n") + "\n"
);

const lines = [];
lines.push(`# garak-derived axis — ${date}`);
lines.push("");
lines.push(`${overall.n} cases extracted from garak 0.17.1 probe structure.`);
lines.push("Same signals as the encoding matrix; benign pages included as controls.");
lines.push("");
lines.push("| Signal | Result |");
lines.push("|---|---|");
lines.push(`| Any finding | ${overall.any}% |`);
lines.push(`| Medium+ | ${overall.medium}% |`);
lines.push(`| Verdict suspicious+ | ${overall.verdict}% |`);
lines.push(`| **Instruction recovered** | **${overall.recovered}%** |`);
lines.push("");
lines.push("| Family | n | medium+ | recovered | verdict |");
lines.push("|---|---|---|---|---|");
for (const f of byFamily) {
  lines.push(`| ${f.family} | ${f.n} | ${f.medium}% | ${f.recovered}% | ${f.verdict}% |`);
}
lines.push("");
lines.push("| Split | n | recovered |");
lines.push("|---|---|---|");
for (const s of bySplit) lines.push(`| ${s.split} | ${s.n} | ${s.recovered}% |`);
lines.push("");
lines.push(
  `Benign controls: ${benignSummary.n} pages, any ${benignSummary.any}%, medium+ ${benignSummary.medium}%, verdict ${benignSummary.verdict}%`
);
lines.push("");
lines.push(
  "> Extracted offline from garak probe definitions; no garak or model at runtime."
);
const md = lines.join("\n") + "\n";
fs.writeFileSync(mdPath, md);

console.log(md);
console.log(`CSV: ${path.relative(process.cwd(), csvPath)}`);
console.log(`MD:  ${path.relative(process.cwd(), mdPath)}`);
