# NVIDIA NeMo Guardrails — input-rail comparison

An external cross-check for the Text detection bench: how does the input rail of
NVIDIA's open-source NeMo Guardrails classify the **same page text** that Lemon
Juice is scored on? The answer is recorded here for one exact, pinned, local
configuration. It is a comparison of one guardrail configuration against one
scanner build on one corpus — not a product ranking and not a measurement of
NVIDIA's hosted guardrails.

## What this axis measures

- **Same inputs, same bytes.** All 221 rows of `inputs/inputs.jsonl` are fed
  unchanged to the guardrail as a single `user` message, and separately
  re-scored by Lemon Juice's text detector (`bench/lib/detect.js` `scan()` =
  `scanText` + `applyContextualPromotion`). The input export is committed so the
  two scorers cannot silently drift onto different text.
- **Corpus.** 84 main-matrix attacks (14 hiding techniques × 6 instruction
  payloads; 3 canonical and 3 paraphrase phrasings), 111 garak-derived attacks
  (56 dev / 55 holdout), and 26 benign pages shared as the negative class for
  both tracks.
- **Decision.** "Blocked" means the `self check input` rail returned `Yes` and
  the stock Colang 1.0 flow answered with its canonical refusal ("I'm sorry, I
  can't respond to that."); the runner records `blocked=true` when the response
  is exactly that refusal, and keeps the raw `Yes`/`No` completion alongside it.
  "Allowed" means the rail returned `No` and the stock dialog step produced a
  reply. Per-case raw completions, decisions, timings and token counts are kept
  in `results/raw/<tag>/guardrail.jsonl`.
- **Reported.** Guardrail block recall and false positives on the shared benign
  pages, Lemon Juice's `any` / `medium+` / `verdict suspicious+` / `recovered`
  signals on identical rows, where the two disagree (cross-tabs), per-family
  behaviour, dev vs holdout for garak, and latency. The numbers are in
  [`results/RESULTS.md`](results/RESULTS.md); the CSVs are the evidence, and
  [`VERIFICATION.md`](VERIFICATION.md) independently re-derives every number from
  them (44/44 checks PASS).

## What is committed, and what is regenerated

| Path                                                                                                      | Status    | Notes                                                                                              |
| --------------------------------------------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------- |
| `inputs/inputs.jsonl`, `inputs/manifest.json`                                                             | committed | Frozen 221-row export + counts and sha256. Regenerable deterministically, committed to lock bytes. |
| `config/config.yml`, `config/prompts.yml`                                                                 | committed | Rail configuration and NVIDIA's example `self_check_input` prompt, copied verbatim.                |
| `requirements.txt`                                                                                        | committed | Pinned Python environment (NeMo Guardrails 0.24.1, openai 3.37.0 and transitive pins).             |
| `guardrail_runner.py`                                                                                     | committed | Resumable, one `generate_async` per case; writes the raw JSONL and `meta.json`.                    |
| `export-inputs.js`                                                                                        | committed | Deterministic input export from the existing corpora.                                              |
| `analyze.js`, `run.js`                                                                                    | committed | Deterministic analysis and the single reproduce entry point.                                       |
| `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/` (`guardrail.jsonl`, `repeat-check.jsonl`, `meta.json`) | committed | The recorded run: one row per case, hashes, versions, counts, repeatability spot-check.            |
| `results/2026-10-25-nemo-selfcheck-gemma3-4b-*.csv`, `results/RESULTS.md`                                 | committed | Derived from the two above; byte-identical on analysis-only re-runs.                               |

The tag `2026-10-25-nemo-selfcheck-gemma3-4b` is the committed run; `run.js --tag=<tag>`
uses the same layout for a new tag. `results/RESULTS.md` is a single shared file,
not a per-tag file, which is why a new tag also needs `--force` once it exists.

The guardrail half needs the local model and the pinned Python environment; the
analysis half needs only Node.js and the committed inputs and raw JSONL. Neither
half installs anything at analysis time, and the analysis never calls a model.

## Pinned environment

| Component       | Version / pin                                                                                 |
| --------------- | --------------------------------------------------------------------------------------------- |
| Host            | Windows 11 (build 26200), AMD Ryzen 5 5600X (6 cores / 12 threads), CPU-only inference        |
| Node.js         | 24.16.0 (the repository's `.nvmrc` pins 24)                                                   |
| CPython         | 3.13.0 (64-bit Windows)                                                                       |
| NeMo Guardrails | 0.24.1 (PyPI wheel sha256 `4fcfc9d9456cdcbcc939fbd4ba884e9fc89b7f200bd9d8ed77836298bf31680f`) |
| openai SDK      | 3.37.0 (installed; not on the self-check path — see PROVENANCE.md for why)                    |
| llama.cpp       | 0.6.0-dev, build 11429, commit `d81235049`, Clang 22.1.8, Windows x86_64                      |
| Model           | `ggml-org/gemma-3-4b-it-GGUF:Q4_K_M` — Q4_K_M, 8192-token context, 2,489,757,856-byte GGUF    |
| Endpoint        | `http://127.0.0.1:9931` (loopback only; no hosted NVIDIA endpoint, no API key)                |

Hashes, licenses and provenance pointers are in [`PROVENANCE.md`](PROVENANCE.md).
The exact upstream prompt origin (NVIDIA's `nemoguardrails/examples/bots/abc/prompts.yml`)
and the verbatim-copy check are documented there too.

### Local model server

The guardrail only needs an OpenAI-compatible `/chat/completions` endpoint on
loopback that serves the pinned model under the alias
`ggml-org/gemma-3-4b-it-GGUF:Q4_K_M`. The recorded run used llama.cpp's router
server (build 11429) with this preset (as reported by `GET /v1/models`):

```ini
[ggml-org/gemma-3-4b-it-GGUF:Q4_K_M]
jinja = 1
ctx-size = 8192
cache-type-k = f16
cache-type-v = f16
hf-repo = ggml-org/gemma-3-4b-it-GGUF:Q4_K_M
```

A single-model server is equivalent for this benchmark, for example:

```powershell
# terminal 1 — leaves the guardrail config's 127.0.0.1:9931 untouched
llama-server -m <path>\gemma-3-4b-it-Q4_K_M.gguf --host 127.0.0.1 --port 9931 `
  --ctx-size 8192 --jinja --alias "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M"

# verify the alias and the loaded context before running any case
(Invoke-RestMethod http://127.0.0.1:9931/v1/models).data |
  Where-Object { $_.id -eq "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M" }
```

### Local API key (recommended)

A keyed loopback router is the recommended setup, and no secret is ever committed:
start the server with `--api-key` (or export `LLAMA_API_KEY`, which the llama.cpp
router reads itself), then export the same value in the shell that runs the
benchmark:

```powershell
# terminal 1 — the server enforces the key
llama-server -m <path>\gemma-3-4b-it-Q4_K_M.gguf --host 127.0.0.1 --port 9931 `
  --api-key $env:LLAMA_API_KEY --ctx-size 8192 --jinja `
  --alias "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M"

# terminal 2 — the runner forwards LLAMA_API_KEY as the bearer token
$env:LLAMA_API_KEY = Read-Host -MaskInput "local router API key"
node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b --analyze-only --force
```

The runner strips ambient `OPENAI_API_KEY` / `NVIDIA_API_KEY` and honours only
`LLAMA_API_KEY`, so it can never authenticate to a hosted service. `meta.json`
records `local_api_key_configured: true|false`; the key itself is never logged,
printed or written to any artifact. The committed raw results were recorded
against an unauthenticated loopback router — the key changes transport, not
decisions, so re-running against a keyed router yields the same block decisions.
Verified on this setup: a keyed one-case run records
`local_api_key_configured: true` with the same decision, and the same run without
the key fails at warm-up with `[401] Invalid API Key` instead of silently
allowing input.

Do not point `config/config.yml` at an endpoint you do not own. The config is
deliberately hard-coded to loopback, the runner pins `NO_PROXY` for loopback and
drops hosted credentials, and no credential is committed or stored anywhere in
this directory.

### Python environment

`requirements.txt` documents the interpreter and every installed distribution.
The run was made with an isolated set of packages (nothing installed system-wide,
nothing installed at run time). Recreate an equivalent environment in a venv
inside the repository (the directory is git-ignored):

```powershell
py -3.13 -m venv .venv-nvidia
.venv-nvidia\Scripts\python.exe -m pip install --disable-pip-version-check -r bench/nvidia-guardrails/requirements.txt
```

## Commands

Run everything from the repository root (PowerShell; the `.venv-nvidia` path is
git-ignored and optional — any interpreter that can import the pinned packages
works):

```powershell
# once, per the Python environment above: point the runner at the interpreter
$env:NEMO_PYTHON = "$PWD\.venv-nvidia\Scripts\python.exe"
# NEMO_PYTHONPATH is optional; run.js defaults it to <workspace>\.nemo-deps, the
# throwaway dependency directory the recorded run used.

# full pass: export inputs, run the 221 guardrail calls, then analyze.
# Needs the local model server above; with the pinned CPU setup this takes
# roughly 10-20 minutes (one model call for a block, two for an allow).
node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b --force

# analysis only: rebuild the four CSVs and RESULTS.md from the committed raw
# JSONL. No model, no Python. Byte-identical to the committed artifacts.
node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b --analyze-only --force

# equivalent analyzer call without run.js (writes into results/ in place)
node bench/nvidia-guardrails/analyze.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b

# validate the analysis math on a synthetic fixture (writes only to a
# workspace temp dir, never to results/; the fixture numbers are synthetic)
node bench/nvidia-guardrails/analyze.js --fixture

# deterministic input export (must reproduce the committed sha256)
node bench/nvidia-guardrails/export-inputs.js

# replay 6 evenly spaced recorded cases and append the stability result to
# results/raw/<tag>/meta.json (needs the model server and PYTHONPATH)
$env:PYTHONPATH = "$PWD\.nemo-deps"
py bench/nvidia-guardrails/guardrail_runner.py --repeat-check
```

`run.js` refuses to overwrite existing artifacts without `--force`, because the
committed CSVs and `RESULTS.md` are the evidence for the recorded run: with the
recorded tag, `--force` on a full pass first deletes the raw results and reruns
all cases. If you only want to inspect the numbers, do not re-run the model —
use the analysis-only command. The analysis validates first and writes nothing
if a raw row is missing, duplicated, or has an input hash that does not match
`inputs.jsonl`; a clean run is the gate, not a warning. Because
`results/RESULTS.md` is shared by every tag, even a fresh tag needs `--force`
once a `RESULTS.md` exists; that replaces it. To compute into a scratch location
instead, call the analyzer directly with `--out-dir=<workspace>\<tmp>` and leave
the committed results untouched.

## Rail configuration summary

`config/config.yml` (sha256 `88973efaa47a7a69c25c587849f0e83dbee975df3835c427c9ba0b83ff3b1047`)
and `config/prompts.yml` (sha256 `b6ee53cafe4446216f11fa402d6461de89a57ed231bf0d3fd4c9feb8858813d8`)
configure exactly one rail:

- `rails.input.flows: [self check input]` — the stock Colang 1.0 flow, with no
  output rail, no dialog rail and no custom actions. `dialog.single_call` is
  disabled.
- `models[0]`: `engine: openai`, the pinned model alias, `base_url` on loopback,
  `temperature: 0.0`, `max_tokens: 16`, `seed: 42` (an extra request-body field
  passed through to llama.cpp). `lowest_temperature: 0.0` pins the temperature
  the self-check action would otherwise set to NeMo's default 0.001.
- The prompt is NVIDIA's example `self_check_input` prompt **verbatim** — no
  policy edits, no added examples, no case-specific wording.

Two details matter when reading the raw rows:

- NeMo's self-check action overrides the per-call `max_tokens` with its task
  default (1024) and forces `temperature` to `lowest_temperature`. The config's
  `max_tokens: 16` therefore applies to the **dialog** call, not the self-check
  call; observed self-check completions do run past 16 tokens (some include a
  short "Reasoning" paragraph). The block decision is still parsed from the
  leading `Yes`/`No`.
- A **blocked** case stops after the self-check call and returns the canonical
  refusal. An **allowed** case continues into the stock `general` dialog call
  (recorded as a second LLM call) whose reply is not used for the benchmark
  decision. `gr_ms` is the wall time of the whole `generate_async` for that
  case — self-check only when blocked, self-check plus dialog generation when
  allowed — measured after a warmup, excluding process startup.

## What these numbers can and cannot conclude

- **Proxy, not deployment.** Page text is fed as a single user message. A real
  page reaches an assistant as retrieved content, tool output, a pasted message,
  or part of a larger prompt with system instructions and history; the rail sees
  a different boundary there. That is the right boundary for a like-for-like
  text comparison; it is not a deployment measurement.
- **One small local model.** A 4B Q4 model on CPU is far weaker than the hosted
  models NVIDIA recommends for NeMo Guardrails. Every number here describes this
  pinned configuration; it says nothing about NVIDIA's hosted guardrails or a
  production NeMo deployment with a capable model.
- **CPU latency is not hosted latency.** The guardrail timings include local
  model inference on one 6-core CPU and exclude network and serving overhead. Do
  not compare them to an API's latency.
- **Small corpus, shared controls.** 84 + 111 attack rows and 26 benign pages;
  the same 26 benign pages are the negative class for both tracks. Twenty-six
  pages catch gross regressions, not a statistically stable false-positive rate.
  No tuning was done on the garak holdout; dev/holdout are reported separately.
- **Not bit-deterministic.** Temperature 0 and a fixed seed reduce, but do not
  eliminate, run-to-run variation in CPU inference and in the model's yes/no
  formatting. The analysis is deterministic for a given raw JSONL; the model is
  not bit-guaranteed. Six evenly spaced cases were replayed (see the raw
  directory's `repeat-check.jsonl` and `meta.json`) as a stability spot-check,
  not as a guarantee.
- **Text layer only.** This axis scores Lemon Juice's text detection, matching
  the rest of `bench/`; the extension's DOM-based signals (CSS-hidden text,
  comments, attributes, shadow roots) are exercised by the e2e tests instead.
- **Synthetic English inputs.** Neutral payload text on its own line, English
  only; real traffic mixes languages, splits payloads across nodes, and embeds
  them mid-sentence. The corpus is shared with the rest of `bench/`, so its
  limitations carry over.
