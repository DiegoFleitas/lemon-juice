# Provenance

Everything committed under `bench/nvidia-guardrails/` is either reproducible
from this repository plus public upstream artifacts, or is a record of one
pinned run. This file lists the components, their exact versions and hashes, and
where the data came from. Nothing here was installed or downloaded at run time
by the committed code: the raw guardrail results were produced once on the
pinned environment below, and the analysis is pure Node.js.

## Guardrail: NeMo Guardrails 0.24.1

| Item               | Value                                                                                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Project            | NVIDIA NeMo Guardrails                                                                                                                              |
| Upstream           | <https://github.com/NVIDIA/NeMo-Guardrails>                                                                                                         |
| Version            | `0.24.1` (released on PyPI; Python `>=3.10,<3.14`)                                                                                                  |
| Artifact installed | `nemoguardrails-0.24.1-py3-none-any.whl`, 1,060,573 bytes                                                                                           |
| Wheel sha256       | `4fcfc9d9456cdcbcc939fbd4ba884e9fc89b7f200bd9d8ed77836298bf31680f`                                                                                  |
| Wheel URL          | <https://files.pythonhosted.org/packages/59/5c/e44694350e4867436bc897365b8e0d6383b9e990fa18b56fb4bf9fe35939/nemoguardrails-0.24.1-py3-none-any.whl> |
| PyPI record        | <https://pypi.org/project/nemoguardrails/0.24.1/>                                                                                                   |
| License            | Apache-2.0 (`License-Expression: Apache-2.0`; `LICENSE-Apache-2.0.txt` ships in the wheel)                                                          |

Version and hashes come from the PyPI JSON API for `nemoguardrails==0.24.1`
(retrieved 2026-10-25). The wheel was installed into a throwaway dependency
directory and consumed through `PYTHONPATH`; the full pinned environment is
`requirements.txt`. The environment also pins `openai==3.37.0`. That SDK is not
a base-install dependency of NeMo 0.24.1 (it is declared only under the optional
`all`/`server` extras as `openai>=1.0.0,<3.0.0`), and this run's
`engine: openai` path does not go through it: NeMo 0.24.1 talks to
OpenAI-compatible endpoints with its own `httpx`-based client, and the only
`import openai` sites in the wheel are the embeddings providers and server
schemas. The SDK is pinned for environment reproducibility; no result in this
directory depends on its version (see `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/meta.json`
for the recorded versions and the error count). Nothing is installed at analysis
time.

### Prompt

- Source file inside the installed wheel:
  `nemoguardrails/examples/bots/abc/prompts.yml`.
- `config/prompts.yml` reproduces the `self_check_input` task **verbatim**: the
  prompt content is byte-identical to NVIDIA's example (both hash to
  `9a22b7e9924d35ded07f654d649be410794cbd51634e659428a68403c4d9e353`). The
  unused `self_check_output` task from the same example file is dropped, so the
  committed file is not byte-identical to the upstream file (upstream file
  sha256 `f6e0a0f6b3582d574c4bccaffdaac6078cb45ae616b130d947205e02461c881e`;
  committed file sha256 `b6ee53cafe4446216f11fa402d6461de89a57ed231bf0d3fd4c9feb8858813d8`).
- No prompt tuning, no added few-shot examples, no case-specific wording.

### Config

- `config/config.yml`, sha256
  `88973efaa47a7a69c25c587849f0e83dbee975df3835c427c9ba0b83ff3b1047`
  (976 bytes): `engine: openai`, local `base_url`, model alias, temperature 0.0,
  `max_tokens: 16`, `seed: 42`, `rails.input.flows: [self check input]`,
  `rails.dialog.single_call.enabled: false`, `lowest_temperature: 0.0`.
- No API key, token, or hosted endpoint is configured. The only network
  destination is the loopback llama.cpp server below.

## Model and inference runtime

| Item         | Value                                                                              |
| ------------ | ---------------------------------------------------------------------------------- |
| Model repo   | `ggml-org/gemma-3-4b-it-GGUF` on Hugging Face                                      |
| Revision     | `d0976223747697cb51e056d85c532013931fe52e` (snapshot in the local HF cache)        |
| File         | `gemma-3-4b-it-Q4_K_M.gguf`, 2,489,757,856 bytes                                   |
| File sha256  | `882e8d2db44dc554fb0ea5077cb7e4bc49e7342a1f0da57901c0802ea21a0863`                 |
| Quantization | Q4_K_M (loader reports `ftype: Q4_K - Medium`, 3,880,099,328 parameters)           |
| Context      | 8192 tokens (`--ctx-size 8192`)                                                    |
| License      | Google Gemma Terms of Use (the weights are not redistributed in this repo)         |
| Server       | llama.cpp OpenAI-compatible router                                                 |
| llama.cpp    | `version: 0.6.0-dev (build 11429, commit d81235049)`, Clang 22.1.8, Windows x86_64 |
| Endpoint     | `http://127.0.0.1:9931` (loopback only)                                            |

The model is multimodal upstream but was used text-only. The weights were
fetched once into the local Hugging Face cache and served from that snapshot;
they are not part of this repository, and re-running the guardrail half requires
obtaining them under the Gemma Terms of Use. The loader's reported preset (from
`GET /v1/models`) was:

```ini
[ggml-org/gemma-3-4b-it-GGUF:Q4_K_M]
jinja = 1
ctx-size = 8192
cache-type-k = f16
cache-type-v = f16
hf-repo = ggml-org/gemma-3-4b-it-GGUF:Q4_K_M
```

## Inputs: the 221 scored cases

`inputs/inputs.jsonl` is deterministic and committed; `inputs/manifest.json`
records the counts and the sha256 of the exact file body
(`410a62dbafd40f4515a1c50ae8f54d220d3b5a36ad3e87fb7675372b9609fc38`). Both
systems are scored on the same `text` field of the same rows.

| Track    | Rows | Contents                                                                      |
| -------- | ---: | ----------------------------------------------------------------------------- |
| `main`   |   84 | `bench/lib/corpus.js` `buildAttackCases()`: 14 hiding techniques × 6 payloads |
| `garak`  |  111 | payloads from `bench/garak/corpus.jsonl` (56 dev, 55 holdout)                 |
| `benign` |   26 | `bench/corpora/benign/*.txt`, sorted, shared as false-positive controls       |

- The `main` matrix and the benign corpus are the same ones used by
  `bench/run.js`; their provenance is `bench/README.md` and
  `bench/corpora/benign/SOURCES.md` (6 pages authored for the bench under
  GPL-3.0, 20 public-domain Project Gutenberg excerpts). The 26 benign pages are
  the _same rows_ for both tracks, so there is one shared false-positive
  denominator, not two.
- The `garak` corpus is derived from garak 0.17.1 probe structure, offline; see
  `bench/garak/PROVENANCE.md`. Payload text is authored here, not copied from
  harmful probe base prompts, and web-injection domains use `example.invalid`.
- The export is reproducible from the repository: `node bench/nvidia-guardrails/export-inputs.js`.
  The committed file exists so that a raw result can be checked against the exact
  bytes that produced it.

## Results records

- Raw guardrail output: `results/raw/2026-10-25-nemo-selfcheck-gemma3-4b/`
  (`guardrail.jsonl`, `repeat-check.jsonl`, `meta.json`). One row per case, with
  the input sha256, block decision, raw self-check completion, wall time and
  per-LLM-call records; `meta.json` carries the config/prompt/input hashes,
  versions, model id and timestamps.
- Derived CSVs (`results/<tag>-*.csv`) and `results/RESULTS.md` are regenerated
  deterministically by `bench/nvidia-guardrails/analyze.js` from the committed
  inputs and raw JSONL.
- Every number in `results/RESULTS.md` was independently re-derived from these
  artifacts; the checks, commands and exact counts are in
  [`VERIFICATION.md`](VERIFICATION.md) (44/44 PASS).
- Run host: Windows 11 (build 26200), AMD Ryzen 5 5600X (6 cores / 12 threads),
  CPU-only inference; Node.js 24.16.0, CPython 3.13.0. Latency numbers are for
  this host and this configuration only.
- No secrets: no API keys, tokens, credentials, or personal data are needed or
  committed. The only host referenced is `127.0.0.1`. No NVIDIA-hosted endpoint
  was contacted for these results.
