# Decision: NeMo Guardrails `self check input` on a local model

**Date:** 2026-10-25
**Status:** accepted for this benchmark
**Context:** `bench/` already measures Lemon Juice's text layer against a fixed
corpus. This axis asks a different question: how does a decision-producing
NVIDIA guardrail surface classify the same page text? The answer has to be
produced under the constraints of this repository's benchmark — local and
offline, no hosted credentials, no network calls to an endpoint we do not own,
and no tuning against the corpus.

## What was chosen

**NeMo Guardrails 0.24.1, open source, with the stock `self check input` input
rail (Colang 1.0 flow) and NVIDIA's example `self_check_input` prompt copied
verbatim.** The rail's main model is an OpenAI-compatible client pointed at a
local llama.cpp server (`127.0.0.1`, loopback only) serving
`ggml-org/gemma-3-4b-it-GGUF:Q4_K_M`, pinned at temperature 0.0, seed 42, context 8192. Config and prompt are committed, hashed, and documented in
[`PROVENANCE.md`](PROVENANCE.md).

Why this surface:

- It is the actual input decision point of NeMo Guardrails, not a re-implementation.
  A block takes the stock Colang 1.0 path and returns the rail's own refusal
  string, so the "blocked" label is the framework's decision, parsed from its
  own model output.
- It runs entirely locally and open source: no NGC account, no NVIDIA-hosted
  endpoint, no API key. That makes the result reproducible on this machine and
  keeps the benchmark's no-outbound-network posture.
- It consumes exactly the same `text` bytes as the Lemon Juice scorer
  (`inputs/inputs.jsonl`), so the comparison is like-for-like on the input.
- The prompt is NVIDIA's own example, unmodified, and no configuration was
  changed after seeing any result. There is no tuning on the 55-case garak
  holdout; the split is only reported separately.

The model choice is deliberately small and local. It is **not** the model
NVIDIA recommends for production NeMo Guardrails deployments, which are hosted
LLMs far larger than a 4B Q4 model: every number this axis produces describes
this pinned configuration only, not NeMo Guardrails or NVIDIA's hosted
guardrails in general.

## Alternatives considered and rejected

| Alternative                                                         | Why it was not used                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hosted NVIDIA NIM jailbreak-detect endpoint                         | The closest hosted production surface, and the one NVIDIA's docs steer self-hosted deployments toward. It needs NGC credentials and outbound network access, which this benchmark does not have and did not receive approval to use. Not called at any point; nothing here says how it performs.                                                                                                                                                |
| NeMo `jailbreak_detection` rail — heuristics                        | Input rail, but the heuristics run in a separate server that requires `torch`/`transformers` and a local `gpt2-large` model download (the rail's own `jailbreak_detection/requirements.txt` pins `torch>=2.9.0`, `transformers>=5.3.0`). Not available offline here, and it measures perplexity heuristics rather than an LLM judge.                                                                                                            |
| NeMo `jailbreak_detection` rail — model path                        | Needs either the NemoGuard JailbreakDetect classifier download or a NIM endpoint (`nim_base_url` / API key). Not available offline, so it would have been the hosted path again.                                                                                                                                                                                                                                                                |
| NeMo `injection_detection` rail (YARA)                              | Local and deterministic, with no model dependency, but it is an **output**/tool-output rail, and its YARA rules target code import/shell (`code.yara`), SQL injection (`sqli.yara`), Jinja/template injection (`template.yara`) and Markdown XSS (`xss.yara`) — not indirect prompt-injection prose. Wrong direction and wrong target for this corpus. Kept as the documented alternative if the axis is ever changed to output-side injection. |
| `llama_guard` rail                                                  | Input/output Llama Guard model binding. Requires a separate Llama Guard model bound as the `llama_guard` model — in practice NVIDIA's hosted Llama Guard NIM, or a local Llama Guard GGUF served separately (weights under the Llama license, not present in this environment). It is a safety-policy classifier, not an injection detector. Not available here.                                                                                |
| `content_safety` rail                                               | Requires a content-safety model bound in the config (NVIDIA's examples target a hosted NIM model). Its policy categories are hate/violence/sexual/etc., not indirect prompt injection; binding the local Gemma model would measure that model's general judgment, not a dedicated safety classifier. Not used.                                                                                                                                  |
| garak                                                               | Not a guardrail. garak is an attack scanner that measures model compliance; it generates probes and scores a target model's answers. It cannot be plugged in as an input rail over a fixed text corpus. garak probe _structures_ are used as a separate corpus axis (`bench/garak/`), not as this comparison.                                                                                                                                   |
| Prompt-tuned self-check (custom policy, few-shot, rewritten prompt) | Would have measured prompt engineering on this corpus, not the shipped example rail, and would invite tuning against the holdout. The example prompt was copied verbatim instead; no prompt variant was tried.                                                                                                                                                                                                                                  |

## The proxy caveat

Feeding the page text to the rail as a single `user` message is a **proxy** for
the real pipeline. In a deployment, a page's text reaches an assistant as
retrieved content, tool output, a pasted message, or part of the system/developer
context; the guardrail would see it inside a larger prompt with instructions,
conversation history, and possibly a different role. Here it is a bare user turn.
That is the cleanest way to compare two text classifiers on identical bytes, and
it is also why these numbers must not be read as "Guardrails catches X% of
prompt injection on the web" — a deployed rail's boundary and context are
different. Lemon Juice has the matching limitation: this axis scores its text
layer only, not the DOM-based rendering information the extension also uses.

The alternatives above were checked against the installed 0.24.1 wheel (rail
manifests, action code, the YARA injection rules and the jailbreak-detection
requirements); no NVIDIA-hosted endpoint was contacted at any point.

## Lemon Juice signals used for comparison

Both systems are scored on the same 221 rows. For Lemon Juice, the analysis
reuses the signals already defined for the rest of `bench/` (`bench/README.md`,
`bench/lib/detect.js`) rather than inventing new ones for this comparison:

| Signal                  | Definition                                                             | Role in this comparison                        |
| ----------------------- | ---------------------------------------------------------------------- | ---------------------------------------------- |
| **any finding**         | `findings.length > 0`, including LOW informational hits                | Coverage diagnostic: did anything at all fire? |
| **medium+**             | at least one HIGH or MEDIUM finding                                    | Mechanism spotted (the "detection" claim)      |
| **verdict suspicious+** | `pageVerdict` is `suspicious` or `likely-injection`                    | What the product would actually show the user  |
| **recovered**           | the instruction itself was recognised, standalone or as a corroborator | Closest analogue to understanding the payload  |

The confusion matrices in `metrics.csv` report all four signals, both against the
case label and against the guardrail's block decision. The attack cross-tabs in
`results/RESULTS.md` summarise disagreement at **two thresholds** — `any finding` and
`verdict suspicious+` — because those answer the two different questions ("did
anything fire?" and "would the product warn?"); `medium+` is the mechanism-level
detection claim and `recovered` is the closest analogue to understanding the
instruction. The 26 benign pages are the shared negative set for both tracks;
they are not re-drawn per track, and they are a smoke test, not a stable FPR
estimate.

## Consequences and limits

- This axis cannot rank NeMo Guardrails against Lemon Juice as products. It
  compares one pinned local configuration of a guardrail against one pinned
  build of a scanner on one synthetic corpus, with the caveats above.
- It does not measure NVIDIA's hosted models, other NVIDIA rails, or the
  recommended production configuration. A hosted-model run would be a different
  experiment with a different (and likely stronger) result.
- The rail is a single pass per case at temperature 0.0 with a fixed seed; the
  recorded run made one attempt per case (`attempts` is recorded on every row;
  the runner only retries a transport/internal error) and did not re-prompt,
  threshold or post-process the decision. A case that is "allowed" is one pass
  of the stock flow.
- Reproducing the guardrail half requires the local model and the pinned Python
  environment (`requirements.txt`); the analysis half is pure Node.js from the
  committed inputs and raw JSONL. See [`README.md`](README.md) for the commands
  and [`PROVENANCE.md`](PROVENANCE.md) for hashes and licenses.
