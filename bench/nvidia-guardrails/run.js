#!/usr/bin/env node
"use strict";

/**
 * NVIDIA guardrail benchmark — single deterministic entry point.
 *
 *   node bench/nvidia-guardrails/run.js [options]
 *
 * Steps, in order (each skippable):
 *   1. export the frozen inputs          (require ./export-inputs.js)
 *   2. run guardrail_runner.py for any input case missing a raw result
 *   3. analyze: re-score with Lemon Juice, validate, write the result CSVs + RESULTS.md
 *
 * The guardrail is a local model (NeMo Guardrails self-check-input on Gemma 3 4B
 * through a llama.cpp router); step 2 needs that stack to be running. Analysis
 * never needs it: `--skip-guardrail` and `--analyze-only` consume recorded raw
 * results and are byte-identical on re-run.
 *
 * Environment:
 *   NEMO_PYTHON      Python interpreter used for guardrail_runner.py (default "py")
 *   NEMO_PYTHONPATH  directory prepended to PYTHONPATH so the runner can import
 *                    nemoguardrails; default <workspace>/.nemo-deps
 *
 * No new dependencies, no network beyond the local guardrail router.
 */

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const analyze = require("./analyze.js");

const BENCH_DIR = __dirname;
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const WORKSPACE_ROOT = path.resolve(REPO_ROOT, "..");
const RESULTS_DIR = path.join(BENCH_DIR, "results");
const INPUTS_PATH = path.join(BENCH_DIR, "inputs", "inputs.jsonl");
const RUNNER_PATH = path.join(BENCH_DIR, "guardrail_runner.py");

const HELP = [
  "Usage: node bench/nvidia-guardrails/run.js [options]",
  "",
  "  --tag=<tag>         artifact tag; results are written as results/<tag>-*.csv and",
  "                      RESULTS.md, raw guardrail output under results/raw/<tag>/",
  "                      (default: run-<UTC timestamp>)",
  "  --force             overwrite existing <tag> artifacts and reset the raw guardrail",
  "                      results (passed to guardrail_runner.py). RESULTS.md is a single shared",
  "                      file, so a fresh tag also needs --force once any RESULTS.md exists",
  "  --skip-guardrail    export inputs and analyze, but never invoke the guardrail",
  "  --analyze-only      skip input export and the guardrail; analyze existing raw results",
  "  --remeasure         take fresh Lemon Juice timings instead of reusing cases.csv",
  "  --inputs=<path>     advanced/testing: inputs.jsonl used by the analyze step",
  "  --raw-dir=<path>    advanced/testing: raw guardrail results dir for this tag",
  "  --out-dir=<path>    advanced/testing: artifact output dir (default results/)",
  "  --help              this text",
  "",
  "Env:",
  '  NEMO_PYTHON         Python interpreter for guardrail_runner.py (default "py")',
  "  NEMO_PYTHONPATH     dir prepended to PYTHONPATH for the runner",
  "                      (default <workspace>/.nemo-deps)",
  "",
  "Examples:",
  "  node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b",
  "  node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b --analyze-only --force",
].join("\n");

function argValue(argv, name, fallback) {
  const hit = argv.find((argument) => argument.startsWith(`--${name}=`));
  return hit ? hit.slice(`--${name}=`.length) : fallback;
}

function parseArgs(argv) {
  const options = {
    tag: null,
    force: false,
    skipGuardrail: false,
    analyzeOnly: false,
    remeasure: false,
    inputsPath: null,
    rawDir: null,
    outDir: null,
    help: false,
  };
  for (const argument of argv.slice(2)) {
    if (argument === "--help" || argument === "-h") options.help = true;
    else if (argument === "--force") options.force = true;
    else if (argument === "--skip-guardrail") options.skipGuardrail = true;
    else if (argument === "--analyze-only") options.analyzeOnly = true;
    else if (argument === "--remeasure") options.remeasure = true;
    else if (argument.startsWith("--tag=")) options.tag = argValue(argv, "tag", null);
    else if (argument.startsWith("--inputs="))
      options.inputsPath = argValue(argv, "inputs", null);
    else if (argument.startsWith("--raw-dir="))
      options.rawDir = argValue(argv, "raw-dir", null);
    else if (argument.startsWith("--out-dir="))
      options.outDir = argValue(argv, "out-dir", null);
    else throw new Error(`unknown argument: ${argument}`);
  }
  if (!options.tag) {
    const stamp = new Date()
      .toISOString()
      .replace(/[-:]/g, "")
      .slice(0, 15)
      .replace("T", "-");
    options.tag = `run-${stamp}`;
  }
  if (!/^[A-Za-z0-9._-]+$/.test(options.tag)) {
    throw new Error(
      `invalid tag ${JSON.stringify(options.tag)}: use letters, digits, dot, dash, underscore`
    );
  }
  if (options.analyzeOnly) options.skipGuardrail = true;
  return options;
}

function relative(target) {
  return path.relative(process.cwd(), target) || target;
}

function artifactPaths(tag, outDir) {
  return [
    path.join(outDir, `${tag}-cases.csv`),
    path.join(outDir, `${tag}-metrics.csv`),
    path.join(outDir, `${tag}-families.csv`),
    path.join(outDir, `${tag}-latency.csv`),
    path.join(outDir, "RESULTS.md"),
  ];
}

function readInputIds(inputsPath) {
  const rows = fs
    .readFileSync(inputsPath, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "");
  return rows.map((line) => JSON.parse(line).id);
}

function readRawIds(rawPath) {
  if (!fs.existsSync(rawPath)) return new Set();
  const ids = new Set();
  for (const line of fs.readFileSync(rawPath, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      if (typeof row.id === "string") ids.add(row.id);
    } catch {
      // a malformed line is caught by analyze.js validation later
    }
  }
  return ids;
}

function exportInputs() {
  process.stdout.write(
    "run: exporting inputs (bench/nvidia-guardrails/export-inputs.js)\n"
  );
  // export-inputs.js is a script: requiring it runs it and writes inputs.jsonl +
  // manifest.json deterministically from the committed corpus.
  require("./export-inputs.js");
}

function guardrailEnv() {
  const env = { ...process.env };
  const nemoPath = process.env.NEMO_PYTHONPATH || path.join(WORKSPACE_ROOT, ".nemo-deps");
  env.PYTHONPATH = env.PYTHONPATH
    ? `${nemoPath}${path.delimiter}${env.PYTHONPATH}`
    : nemoPath;
  // The runner reconfigures stdout itself, but keep the child UTF-8 clean.
  env.PYTHONIOENCODING = env.PYTHONIOENCODING || "utf-8";
  return env;
}

function runGuardrail({ tag, force }) {
  if (!fs.existsSync(RUNNER_PATH)) {
    throw new Error(
      `guardrail runner not found: ${relative(RUNNER_PATH)}; ` +
        "run with --skip-guardrail/--analyze-only if raw results already exist"
    );
  }
  if (force) {
    process.stdout.write(
      "run: --force is set, so the guardrail runner will delete and rebuild the raw " +
        "results from scratch — that is a full local model pass (~15 min for 221 cases).\n"
    );
  }
  const python = process.env.NEMO_PYTHON || "py";
  const rawDir = path.join(RESULTS_DIR, "raw", tag);
  const args = [RUNNER_PATH, "--inputs", INPUTS_PATH, "--out-dir", rawDir];
  if (force) args.push("--force");
  const commandText = `${python} ${args.map((part) => relative(part)).join(" ")}`;
  process.stdout.write(`run: guardrail runner\n  ${commandText}\n`);
  const result = spawnSync(python, args, {
    cwd: REPO_ROOT,
    env: guardrailEnv(),
    // Piped stdio is unavailable in this sandbox; let the runner own the terminal.
    stdio: "inherit",
  });
  if (result.error) {
    throw new Error(
      `failed to start ${python}: ${result.error.message} (set NEMO_PYTHON to the Python interpreter)`
    );
  }
  if (result.status !== 0) {
    const signal = result.signal ? `, signal ${result.signal}` : "";
    throw new Error(`guardrail_runner.py exited with status ${result.status}${signal}`);
  }
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}\n`);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    process.stdout.write(`${HELP}\n`);
    return;
  }

  const tag = options.tag;
  const inputsPath = path.resolve(options.inputsPath || INPUTS_PATH);
  const outDir = path.resolve(options.outDir || RESULTS_DIR);
  const rawDir = path.resolve(options.rawDir || path.join(RESULTS_DIR, "raw", tag));
  const existing = artifactPaths(tag, outDir).filter((target) => fs.existsSync(target));

  if (!options.force && existing.length) {
    process.stderr.write(
      `refusing to overwrite ${existing.map(relative).join(", ")}\n` +
        "pick a new tag with --tag=<name>, or pass --force to replace the evidence.\n" +
        "committed runs are evidence; analysis-only re-runs are byte-identical with --force.\n"
    );
    process.exitCode = 1;
    return;
  }

  try {
    if (!options.analyzeOnly) exportInputs();

    if (!options.skipGuardrail) {
      const inputIds = readInputIds(inputsPath);
      const have = readRawIds(path.join(rawDir, "guardrail.jsonl"));
      const missing = inputIds.filter((id) => !have.has(id));
      if (missing.length === 0) {
        process.stdout.write(
          `run: raw guardrail results already cover all ${inputIds.length} cases; skipping the model run\n`
        );
      } else {
        process.stdout.write(
          `run: ${missing.length}/${inputIds.length} case(s) lack raw guardrail results; ` +
            "invoking guardrail_runner.py\n"
        );
        runGuardrail({ tag, force: options.force });
        const after = readRawIds(path.join(rawDir, "guardrail.jsonl"));
        const stillMissing = inputIds.filter((id) => !after.has(id));
        if (stillMissing.length) {
          throw new Error(
            `${stillMissing.length} case(s) still have no guardrail row after the run: ` +
              `${stillMissing.slice(0, 10).join(", ")}`
          );
        }
      }
    } else if (options.analyzeOnly) {
      process.stdout.write(
        `run: analyze-only; using recorded raw results in ${relative(rawDir)}\n`
      );
    }

    const summary = analyze.run({
      tag,
      inputs: inputsPath,
      rawDir,
      outDir,
      remeasure: options.remeasure,
    });

    process.stdout.write(
      `run: analyzed ${summary.cases} cases ` +
        `(${summary.attacks} attacks, ${summary.benign} benign controls), ` +
        `${summary.guardrailErrors} guardrail per-case error(s), raw sha256 ` +
        `${summary.rawSha256.slice(0, 16)}…\n`
    );
    const audit = summary.audit;
    process.stdout.write(
      `run: semantics audit — refusal mismatches ${audit.refusalMismatches.length}, ` +
        `decision mismatches ${audit.firstWordMismatches.length}, ` +
        `decision_normalized mismatches ${audit.decisionNormalizedMismatches.length}\n`
    );
    for (const artifact of summary.artifacts) {
      process.stdout.write(`  ${relative(artifact)}\n`);
    }
    process.stdout.write(
      "\nrun: done. Re-analysis from the same raw results is byte-identical; " +
        "pass --analyze-only --force to regenerate without touching the raw results.\n"
    );
  } catch (error) {
    process.stderr.write(`run failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = { parseArgs, artifactPaths };
