"use strict";

function pct(n, d) {
  return d ? Math.round((1000 * n) / d) / 10 : 0;
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return Math.round(sorted[idx] * 100) / 100;
}

function summarize(rows) {
  const attacks = rows.filter((r) => r.kind === "attack");
  const benign = rows.filter((r) => r.kind === "benign");

  const groups = new Map();
  for (const r of attacks) {
    if (!groups.has(r.category)) groups.set(r.category, []);
    groups.get(r.category).push(r);
  }

  const perCategory = [...groups.entries()]
    .map(([category, list]) => ({
      category,
      n: list.length,
      any: pct(list.filter((r) => r.flagged_any).length, list.length),
      medium: pct(list.filter((r) => r.flagged_medium).length, list.length),
      recovered: pct(list.filter((r) => r.recovered).length, list.length),
      verdict: pct(list.filter((r) => r.flagged_verdict).length, list.length),
    }))
    .sort((a, b) => a.category.localeCompare(b.category));

  const overall = {
    n: attacks.length,
    any: pct(attacks.filter((r) => r.flagged_any).length, attacks.length),
    medium: pct(attacks.filter((r) => r.flagged_medium).length, attacks.length),
    recovered: pct(attacks.filter((r) => r.recovered).length, attacks.length),
    verdict: pct(attacks.filter((r) => r.flagged_verdict).length, attacks.length),
  };

  const classes = ["canonical", "paraphrase"];
  const perClass = classes.map((cls) => {
    const list = attacks.filter((r) => r.payload_class === cls);
    return {
      class: cls,
      n: list.length,
      medium: pct(list.filter((r) => r.flagged_medium).length, list.length),
      recovered: pct(list.filter((r) => r.recovered).length, list.length),
      verdict: pct(list.filter((r) => r.flagged_verdict).length, list.length),
    };
  });

  const benignStats = {
    n: benign.length,
    any: pct(benign.filter((r) => r.flagged_any).length, benign.length),
    medium: pct(benign.filter((r) => r.flagged_medium).length, benign.length),
    verdict: pct(benign.filter((r) => r.flagged_verdict).length, benign.length),
    pages: benign.map((r) => ({
      id: r.id,
      findings: r.findings,
      verdict: r.verdict,
      worst: r.worst,
    })),
  };

  const latency = attacks.map((r) => Number(r.ms));

  return {
    perCategory,
    perClass,
    overall,
    benign: benignStats,
    latency: {
      p50: percentile(latency, 50),
      p95: percentile(latency, 95),
      max: Math.max(...latency),
    },
  };
}

function toMarkdown(summary, meta) {
  const lines = [];
  lines.push(`# Benchmark summary — ${meta.date}`);
  lines.push("");
  lines.push(
    `Seed \`${meta.seed}\`, ${summary.overall.n} attack cases, ${summary.benign.n} benign pages.`
  );
  lines.push("");
  lines.push("## Detection by technique");
  lines.push("");
  lines.push("`medium+` = a HIGH or MEDIUM finding (the mechanism was spotted).");
  lines.push("`recovered` = the instruction itself was recognised (instruction-phrase,");
  lines.push("control-token or context-switch). `verdict` = the page verdict reached");
  lines.push("suspicious or likely-injection.");
  lines.push("");
  lines.push("| Technique | n | any finding | medium+ | recovered | verdict |");
  lines.push("|---|---|---|---|---|---|");
  for (const c of summary.perCategory) {
    lines.push(
      `| ${c.category} | ${c.n} | ${c.any}% | ${c.medium}% | ${c.recovered}% | ${c.verdict}% |`
    );
  }
  lines.push(
    `| **overall** | **${summary.overall.n}** | **${summary.overall.any}%** | **${summary.overall.medium}%** | **${summary.overall.recovered}%** | **${summary.overall.verdict}%** |`
  );
  lines.push("");
  lines.push("## Payload phrasing");
  lines.push("");
  lines.push("| Class | n | medium+ | recovered | verdict |");
  lines.push("|---|---|---|---|---|");
  for (const c of summary.perClass) {
    lines.push(
      `| ${c.class} | ${c.n} | ${c.medium}% | ${c.recovered}% | ${c.verdict}% |`
    );
  }
  lines.push("");
  lines.push("## Benign pages (false positives)");
  lines.push("");
  lines.push(
    `Any finding: ${summary.benign.any}% · medium+: ${summary.benign.medium}% · flagged verdict: ${summary.benign.verdict}%`
  );
  lines.push("");
  lines.push("| Page | Findings | Verdict | Worst |");
  lines.push("|---|---|---|---|");
  for (const p of summary.benign.pages) {
    lines.push(`| ${p.id} | ${p.findings} | ${p.verdict} | ${p.worst || "-"} |`);
  }
  lines.push("");
  lines.push("## Latency (attack scans)");
  lines.push("");
  lines.push(
    `p50 ${summary.latency.p50} ms · p95 ${summary.latency.p95} ms · max ${summary.latency.max} ms`
  );
  lines.push("");
  lines.push(
    "> Detection is a *finding*, not a verdict. A LOW informational hit on a page"
  );
  lines.push(
    "> that merely discusses injection is expected and is not a false positive in"
  );
  lines.push("> the product sense — see the verdict column.");
  return lines.join("\n");
}

module.exports = { summarize, toMarkdown };
