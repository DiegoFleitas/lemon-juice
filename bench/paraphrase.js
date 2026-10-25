#!/usr/bin/env node
"use strict";

/**
 * Paraphrase axis for the detection benchmark.
 *
 *   node bench/paraphrase.js [--tag=baseline] [--force]
 *
 * The 14-technique matrix measures concealment. This measures phrasing: can the
 * scanner recognise an instruction when the words change? 24 payloads, four
 * families, half held out. Scoring reuses the same three signals, so a "0%"
 * here is directly comparable to the matrix's "recovered" column.
 */

const fs = require("fs");
const path = require("path");
const { CASES } = require("./corpora/attacks/paraphrase");
const { scan } = require("./lib/detect");

function arg(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split("=").slice(1).join("=") : fallback;
}

const now = new Date();
const date = now.toISOString().slice(0, 10);
const stamp = now.toISOString().slice(11, 19).replace(/:/g, "");
const tag = arg("tag", `run-${stamp}`);
const force = process.argv.includes("--force");

const rows = CASES.map((c) => {
  const r = scan(c.text);
  return {
    id: c.id,
    family: c.family,
    set: c.set,
    chars: c.text.length,
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
    text: c.text,
  };
});

const pct = (n, d) => (d ? Math.round((1000 * n) / d) / 10 : 0);
const rate = (subset, key) => pct(subset.filter((r) => r[key]).length, subset.length);

const summary = (subset) => ({
  n: subset.length,
  any: rate(subset, "flagged_any"),
  medium: rate(subset, "flagged_medium"),
  verdict: rate(subset, "flagged_verdict"),
  recovered: rate(subset, "recovered"),
});

const families = [...new Set(rows.map((r) => r.family))];
const overall = summary(rows);
const byFamily = families.map((f) => ({
  family: f,
  ...summary(rows.filter((r) => r.family === f)),
}));
const bySet = ["dev", "holdout"].map((s) => ({
  set: s,
  ...summary(rows.filter((r) => r.set === s)),
}));

const outDir = path.join(__dirname, "results");
fs.mkdirSync(outDir, { recursive: true });
const base = `${date}-paraphrase-${tag}`;
const csvPath = path.join(outDir, `${base}.csv`);
const mdPath = path.join(outDir, `${base}.md`);

if (!force && (fs.existsSync(csvPath) || fs.existsSync(mdPath))) {
  console.error(
    `refusing to overwrite ${path.relative(process.cwd(), csvPath)}; use --tag= or --force`
  );
  process.exit(1);
}

const headers = [
  "id",
  "family",
  "set",
  "chars",
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
lines.push(`# Paraphrase axis — ${date}`);
lines.push("");
lines.push(
  `${overall.n} payloads, four families, half held out. Same signals as the encoding matrix.`
);
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
for (const s of bySet) lines.push(`| ${s.set} | ${s.n} | ${s.recovered}% |`);
lines.push("");
lines.push("> Held-out rows are the ones a future heuristic must not be tuned on.");
const md = lines.join("\n") + "\n";
fs.writeFileSync(mdPath, md);

console.log(md);
console.log(`CSV: ${path.relative(process.cwd(), csvPath)}`);
console.log(`MD:  ${path.relative(process.cwd(), mdPath)}`);
