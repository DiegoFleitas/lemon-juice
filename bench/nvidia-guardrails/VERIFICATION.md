# Independent verification — NVIDIA guardrail axis

**Date:** 2026-10-25
**Verifier:** docs-verifier (did not write the runner, analyzer, config or results)
**Branch:** `bench/nvidia-guardrails`, repo HEAD `bc85ff3` (Lemon Juice v0.9.3)
**Verdict: PASS — 44/44 checks, 0 failures, no unresolved discrepancies.**
Four documentation defects found while verifying were fixed in the docs (details
in "Discrepancies found and fixed" below); no code, config, input, raw result,
CSV or `RESULTS.md` was edited.

## Method

The verification is a read-only Node.js script, `verify.js`, kept outside the
repository in the benchmark workspace (`<workspace>/.t5/verify.js`; not
committed). It reads the committed artifacts directly and compares them against
independent recomputations using:

- `bench/lib/detect.js` `scan()` for Lemon Juice, `bench/lib/corpus.js`
  `buildAttackCases()` / `loadBenign()` for the main and benign corpora;
- its own RFC4180 CSV parser (quoted newlines in `gr_decision` cells included),
  its own confusion-matrix/percentile math and its own JSONL parsing;
- the benchmark inputs, raw JSONL, `meta.json`, corpus sources and the four CSVs,
  plus the installed NeMo Guardrails 0.24.1 wheel for prompt/SDK provenance.

Mutating checks ran only against copies under `<workspace>/.t5/`. The committed
`results/` and `results/raw/` directories were never written to by this
verification.

Run:

```powershell
cd <workspace>
node .t5\verify.js
```

## Artifacts verified (sha256)

| Artifact                                                             | sha256                                                             |
| -------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/guardrail.jsonl`    | `c875b825a57a3927fc20a64489249d4ff06cd989f33c9dbe2e793900d9c85d46` |
| `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/meta.json`          | `160c318606b025c3c63b7cad8bcfe844d664c60f001117df3a3dbbace54e5d22` |
| `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/repeat-check.jsonl` | `c6750fffa5782ca4cdd74ee2afb269ed6d17ed0c18ddd81df970308fe4ef90f4` |
| `results/2026-10-25-nemo-selfcheck-gemma3-4b-cases.csv`              | `31fe72f6543630008aa0860911b2a4aada4be039a5b733bfa8211d3162ecae96` |
| `results/2026-10-25-nemo-selfcheck-gemma3-4b-metrics.csv`            | `5e6baabdc12c4a8763fdbc159847c2cb63946203f86808b318aea8352b8f6dcb` |
| `results/2026-10-25-nemo-selfcheck-gemma3-4b-families.csv`           | `4d9adca1768f0fb878079c63f033e44ae3d51290878efb218e579fc369162ac2` |
| `results/2026-10-25-nemo-selfcheck-gemma3-4b-latency.csv`            | `f7ac4be7b8a06abd5e8e0f5ec0ec9f6e018aba47598c70b6ff23ac4329618f02` |
| `results/RESULTS.md`                                                 | `e0d04cf7a689bfb316cc1318ef443029185ab6320f82fe7806b6ec940ff4f8d0` |
| `inputs/inputs.jsonl`                                                | `410a62dbafd40f4515a1c50ae8f54d220d3b5a36ad3e87fb7675372b9609fc38` |
| `config/config.yml`                                                  | `88973efaa47a7a69c25c587849f0e83dbee975df3835c427c9ba0b83ff3b1047` |
| `config/prompts.yml`                                                 | `b6ee53cafe4446216f11fa402d6461de89a57ed231bf0d3fd4c9feb8858813d8` |

All hashes are of the committed, LF-normalized bytes: `.gitattributes` pins
`bench/nvidia-guardrails/**` to `text eol=lf`, so these hashes are
checkout-stable on Windows and Linux alike. One nuance: `guardrail_runner.py`
writes `meta.json` through Python's text mode, so a **regenerated** `meta.json`
on Windows is CRLF on disk and hashes to `4b697cfe…` (8,536 bytes); git
normalizes it back to the committed blob `160c3186…` (LF, 8,306 bytes), which is
the hash listed above and the only difference is line endings.

Environment for the verification: Windows 11 build 26200, Node.js 24.16.0,
CPython 3.13.0, same host as the recorded run.

## Results by check (44/44 PASS)

### Inputs (6/6)

| #   | Check                                                                                                  | Result                  |
| --- | ------------------------------------------------------------------------------------------------------ | ----------------------- |
| 1   | 221 rows; main 84, garak 111 (dev 56 / holdout 55), benign 26; labels 195 attack / 26 benign           | PASS                    |
| 2   | unique ids; every `text` re-hashes to its `sha256`; `chars` matches `text.length`                      | PASS (0/221 mismatches) |
| 3   | `manifest.json` cases/counts and file sha256 match `inputs.jsonl`                                      | PASS (`410a62db…`)      |
| 4   | garak rows byte-identical to `bench/garak/corpus.jsonl` payloads, with id/family/split/probe identical | PASS (111/111)          |
| 5   | main rows identical to `buildAttackCases()` (id, family, technique, payload_class, text)               | PASS (84/84)            |
| 6   | benign rows identical to `loadBenign()` and to all 26 `bench/corpora/benign/*.txt` files               | PASS (26/26 + 26/26)    |

### Guardrail raw + meta (8/8)

| #   | Check                                                                                                                                                             | Result                                                                   |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| 7   | 221 raw rows, one per input id, in input order; track/label/family/split/`input_sha256` match inputs                                                              | PASS                                                                     |
| 8   | `config_sha256` / `prompts_sha256` / model id in all 221 rows and in `meta.json` match committed files                                                            | PASS                                                                     |
| 9   | `blocked` consistent with the canonical refusal string and with the parsed `Yes`/`No` decision                                                                    | PASS (0/221 mismatches; 141 Yes / 80 No / 0 unparseable)                 |
| 10  | `gr_ms` positive integers, 0 errors, `attempts` set; per-case `llm_calls` structure                                                                               | PASS (blocked = 1 call; allowed = 2 calls `[self_check_input, general]`) |
| 11  | `meta.json`: status complete, case_count 221, blocked_total 141, errors 0, input/config/prompt hashes match, versions nemo 0.24.1 / openai 3.37.0 / python 3.13.0 | PASS                                                                     |
| 12  | `repeat-check.jsonl`: 6 replayed ids, blocked/decision/input hash stable vs first pass                                                                            | PASS (`stable=true`)                                                     |
| 13  | raw/meta contain no non-local URLs and no credentials                                                                                                             | PASS (only `http://127.0.0.1:9931`)                                      |
| 14  | `meta.json` records telemetry disabled and loopback-only endpoint                                                                                                 | PASS                                                                     |

### Lemon Juice re-score (4/4)

| #   | Check                                                                                                                                             | Result                                                                          |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| 15  | `cases.csv` parses to 221 logical records from 669 physical lines (280 embedded newlines in quoted `gr_decision` cells); row order matches inputs | PASS                                                                            |
| 16  | all 221 rows re-scored with `bench/lib/detect.js` reproduce all 11 Lemon Juice columns exactly                                                    | PASS (221/221)                                                                  |
| 17  | legacy `bench/results/2026-10-20-after-smallcaps.csv` reproduced for 84 main + 26 benign rows                                                     | PASS (110/110 rows × 10 columns; see note on one benign `recovered` convention) |
| 18  | legacy `bench/results/2026-10-25-garak-full-list-after.csv` reproduced for 111 garak rows; split matches                                          | PASS (111/111 × 9 columns)                                                      |

### Metrics, cross-tabs, families, latency (8/8)

| #   | Check                                                                                                                              | Result                                                                                                          |
| --- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| 19  | `metrics.csv` 45/45 rows recomputed from `cases.csv` (n, tp, fp, tn, fn, recall, fpr, precision)                                   | PASS                                                                                                            |
| 20  | denominators: n = attacks + 26 benign (110 main, 82 dev, 81 holdout, 137 garak, 221 all); every label-confusion row has fp+tn = 26 | PASS (25/25 rows)                                                                                               |
| 21  | manual cross-tab cells and recall fractions re-derived by hand                                                                     | PASS (see below)                                                                                                |
| 22  | RESULTS.md cross-tab tables (any, verdict, recovered = 15/15 rows) and both headline sentences match recomputation                 | PASS                                                                                                            |
| 23  | benign FP lists in RESULTS.md match `cases.csv`                                                                                    | PASS (LJ any 1/26 = `B-security-blog-injection` verdict `noise`; LJ verdict 0/26; GR block 1/26 = `B-gut-74-a`) |
| 24  | `metrics.csv` note column states the shared-26-benign convention on all 45 rows                                                    | PASS                                                                                                            |
| 25  | `families.csv` 30/30 rows recomputed (n, gr_n, five percentage columns)                                                            | PASS                                                                                                            |
| 26  | `latency.csv` 8/8 rows recomputed; RESULTS latency + outcome tables + cost ratio present and exact                                 | PASS                                                                                                            |

Manual cross-tab re-derivation: attacks with a valid guardrail decision = 195.
Lemon Juice any × guardrail block = **both 125 / only LJ 53 / only GR 15 /
neither 2**. Main-track guardrail recall = **55/84 = 65.5%**. Verdict threshold
= **76 / 40 / 64 / 15**. LJ recovered × GR block 2x2 = **111 / 40 / 29 / 15**.
All match `RESULTS.md` and `metrics.csv`.

### Integrity, provenance, fairness (7/7)

| #   | Check                                                                                                                                                                                                              | Result                                     |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------ |
| 27  | no holdout-specific logic: no case ids in `analyze.js` / `run.js` / config / prompts / runner; no split wording in config/prompt; split read from `inputs.jsonl` only                                              | PASS                                       |
| 28  | garak dev/holdout assignment comes verbatim from `bench/garak/corpus.jsonl`                                                                                                                                        | PASS (111/111)                             |
| 29  | runtime code/config use only loopback; runner pins `NO_PROXY`, disables NeMo telemetry, strips ambient API keys; no hosted NVIDIA/OpenAI endpoint referenced                                                       | PASS                                       |
| 30  | no secret-like content in the 20 committed files; docs cite only pypi/pythonhosted/github/loopback URLs                                                                                                            | PASS                                       |
| 31  | prompt `self_check_input` content is byte-identical to NVIDIA's 0.24.1 example (content sha256 `9a22b7e9…`; committed file drops only the unused output task), no tuning                                           | PASS                                       |
| 32  | proxy caveat, pinned 4B Q4 model + hosted-model limitation, CPU≠hosted latency, 26-benign smoke-test caveat, no-tuning/verbatim statements present in README/DECISION                                              | PASS                                       |
| 33  | docs: every relative link and every referenced path resolves; `.prettierignore` excludes the byte-emitted `results/` dir; README `.nvmrc` (Node 24) claim is true                                                  | PASS                                       |
| 34  | `openai==3.37.0` documentation honest: it is not a NeMo base-install dependency, the self-check path uses NeMo's `httpx` OpenAI-compatible client, and the wheel has no `import openai` under `nemoguardrails/llm` | PASS (docs corrected during T5; see below) |

### Determinism (2/2)

Determinism was tested from copies under `<workspace>/.t5/`, never from
`results/`:

```powershell
# (a) byte-identical replay from a copy of the committed artifacts
#     (cases.csv present => recorded lj_ms is reused)
Copy-Item bench\nvidia-guardrails\results\<tag>-*.csv <tmp>\out1\
Copy-Item bench\nvidia-guardrails\results\RESULTS.md <tmp>\out1\
node bench/nvidia-guardrails/analyze.js --tag=<tag> `
  --inputs=bench/nvidia-guardrails/inputs/inputs.jsonl `
  --raw-dir=bench/nvidia-guardrails/results/raw/<tag> --out-dir=<tmp>\out1

# (b) two independent analyses into empty dirs (fresh lj_ms each time)
node ...analyze.js ... --out-dir=<tmp>\out2a
node ...analyze.js ... --out-dir=<tmp>\out2b
```

| #   | Check                                                                     | Result                                                                                                                                                                                                                       |
| --- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 35  | replay from copied committed artifacts is byte-identical                  | PASS — 5/5 sha256 equal (`gr_ms` fixed in raw, `lj_ms` reused from copied cases.csv)                                                                                                                                         |
| 36  | fresh-empty-dir analyses: policy columns and all guardrail numbers stable | PASS — 0 non-`lj_ms` differences over 221 rows; `metrics.csv` and `families.csv` byte-identical; guardrail rows of `latency.csv` identical; only LJ `lj_ms`/LJ latency cells and the 5 RESULTS.md lines that print them move |

Honest statement of the determinism property: **the analysis is deterministic for
a given `cases.csv`**. `lj_ms` is a physical measurement captured on first
analysis and reused when the re-score reproduces the same Lemon Juice columns, so
(a) is byte-identical. Two analyses that both start from an _empty_ directory each
take fresh `lj_ms` timings and therefore differ from each other only in those
measurement cells (and the LJ latency numbers derived from them) — 435 such cells
moved across the three files compared here, with zero changes to any decision,
flag, count or rate. `gr_ms` never moves because it is fixed in the raw JSONL.

### Resumability (2/2)

Both resume tests ran against copies of the committed raw directory;
`results/raw/` itself was not written to.

```powershell
# (a) all 221 rows already present
py bench\nvidia-guardrails\guardrail_runner.py `
  --inputs bench\nvidia-guardrails\inputs\inputs.jsonl --out-dir <tmp>\rawcopy_full

# (b) copy with the last row dropped, then run only that missing id
py bench\nvidia-guardrails\guardrail_runner.py `
  --inputs bench\nvidia-guardrails\inputs\inputs.jsonl --out-dir <tmp>\rawcopy_append `
  --ids B-security-blog-injection
```

| #   | Check                                                                                                                                                                                                           | Result                                     |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| 37  | all rows present: `pending=0`, early-exit "nothing to do", raw JSONL + meta.json + repeat-check.jsonl byte-identical afterwards, no model call                                                                  | PASS                                       |
| 38  | one missing row: `pending=1` → `new_rows=1`, total 221/221, 221 unique ids, first 220 lines byte-identical to committed, appended row has the right id/input hash and a valid decision; meta complete, errors 0 | PASS                                       |
| 39  | committed raw directory untouched by the whole verification                                                                                                                                                     | PASS (`guardrail.jsonl` still `c875b825…`) |

### Lead-requested extra checks (5/5)

| #   | Requested check                                                                         | Result                                                                                                                                                                                                                                                                     |
| --- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 40  | Manually re-derive two cross-tab cells and one recall fraction                          | PASS — LJ any × GR both = 125; LJ verdict × GR both = 76; main GR recall = 55/84 = 65.5%                                                                                                                                                                                   |
| 41  | Every metrics row n and FPR denominator                                                 | PASS — n = 110/82/81/137/221, fp+tn = 26 on all label-confusion rows                                                                                                                                                                                                       |
| 42  | RESULTS.md input-size claim                                                             | PASS — means 188.07 / 105.84 / 1191.62 chars → "main 188, garak 106, benign 1192"                                                                                                                                                                                          |
| 43  | No holdout-specific logic; dev/holdout from corpus                                      | PASS — none in code/config/prompt; 111/111 splits from `bench/garak/corpus.jsonl`                                                                                                                                                                                          |
| 44  | Latency asymmetry `blocked=1 call`, `allowed=2 calls`, `gr_ms` = whole `generate_async` | PASS — 141 blocked rows have exactly `[self_check_input]`; 80 allowed rows have exactly `[self_check_input, general]`; `gr_ms` is the runner's wall time around `generate_async` (sum of recorded call durations is below `gr_ms`; max gap 109.2 ms for overhead/rounding) |

## Discrepancies found and fixed (all documentation, no artifact defect)

1. **README linked the wrong `RESULTS.md` path.** It pointed at
   `bench/nvidia-guardrails/RESULTS.md`; the real emitted path is
   `bench/nvidia-guardrails/results/RESULTS.md` (280 lines). Fixed the link, the
   artifacts table and the placeholders to the real path; PROVENANCE/DECISION
   now refer to `results/RESULTS.md` and `results/<tag>-*.csv` too. All 3 docs
   have 0 broken relative links and 21 referenced paths exist.
2. **README was not prettier-clean** after the earlier documentation edits.
   Fixed with `node_modules\.bin\prettier.cmd --write bench/nvidia-guardrails/README.md`;
   the per-file check below now passes.
3. **One legacy-CSV cell disagrees by design, not by defect.** In
   `bench/results/2026-10-20-after-smallcaps.csv`, benign rows carry
   `recovered=false` because `bench/run.js` hard-codes that for benign rows
   (`recovered` is only meaningful for attacks there). This axis computes
   `recovered` for every row, so `B-security-blog-injection` is `true` here. All
   84 main attack rows and all other benign columns match the legacy CSV, and all
   111 garak rows match the 2026-10-25 legacy CSV. This is the only legacy
   difference; it changes no guardrail number (LJ recovered FPR is reported as
   1/26 = 3.8%, consistent with `cases.csv`).
4. **`openai==3.37.0` was described inaccurately.** PROVENANCE previously said
   the SDK was "used by the engine: openai adapter"; the 0.24.1 self-check path
   actually talks to the endpoint with NeMo's own `httpx` client (`import openai`
   exists only under `embeddings/` and `server/schemas/`). Reworded PROVENANCE and
   the README table row to state that the SDK is pinned for environment
   reproducibility, is outside NeMo's declared optional extras range
   (`openai>=1.0.0,<3.0.0`), is off the self-check path, and that no result
   depends on its version. `requirements.txt` was not edited.

No data discrepancy was found: no missing/duplicate rows, no hash mismatch, no
decision/refusal inconsistency, no metric, family, latency or RESULTS number that
did not reproduce from `cases.csv`.

## Formatting and repository hygiene

Per-file prettier check (the byte-emitted `results/` directory is excluded by
`.prettierignore`; repo-wide `prettier --check .` is not usable on this Windows
clone because pre-existing checked-out files are CRLF and an unremovable sandbox
temp dir sits under the repo's ignored `.tmp/`):

```powershell
node_modules\.bin\prettier.cmd --check `
  bench/nvidia-guardrails/README.md bench/nvidia-guardrails/PROVENANCE.md `
  bench/nvidia-guardrails/DECISION.md bench/nvidia-guardrails/VERIFICATION.md `
  bench/nvidia-guardrails/export-inputs.js bench/nvidia-guardrails/analyze.js `
  bench/nvidia-guardrails/run.js bench/nvidia-guardrails/config/config.yml `
  bench/nvidia-guardrails/config/prompts.yml bench/nvidia-guardrails/inputs/manifest.json
# All matched files use Prettier code style!
```

New artifacts are LF; `results/` and `results/raw/` are never hand-formatted, so
the "analysis-only re-run is byte-identical" property holds.

Repository state during verification (unchanged from T3 except the documentation
fixes above and the Lead's `.prettierignore` change): no tracked source file was
modified by T5, and `bench/nvidia-guardrails/results/`, raw results and
`inputs/` were not written to.
