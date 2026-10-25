# garak against the pipeline, not the model

Garak scans a chat endpoint. The interesting target is not `llama3.2` in
isolation — it is _page text → prompt → model_, because that is where indirect
prompt injection lives. `shim.py` exposes that pipeline as an OpenAI-compatible
endpoint, so garak probes the composition.

```
page.txt ──► shim.py (system or rag mode) ──► Ollama / any OpenAI-compatible model
                    │
                    └── shim.log.jsonl   (every prompt and response, reproducible)
```

## 1. Start the model, then the shim

Any OpenAI-compatible server works. With llama.cpp's unified CLI:

```sh
# terminal 1 — `llama serve` exposes /v1/chat/completions on :9931
llama serve -m ~/models/qwen2.5-3b-instruct-q4_k_m.gguf -c 4096 -ngl all

# terminal 2 — the shim ingests the page on every request
python bench/garak/shim.py --page bench/garak/pages/poisoned.txt \
                           --backend llamacpp
```

`rest.json` omits the model name on purpose: the shim fills it in, so the same
config works against a single-model server and against llama.cpp's router mode,
where the model must be named:

```sh
python bench/garak/shim.py --page bench/garak/pages/poisoned.txt \
  --backend llamacpp --model "unsloth/Qwen3-0.6B-GGUF:Q4_0"
```

The `llamacpp` backend defaults to `http://127.0.0.1:9931/v1` (llama.cpp's
default port); override with `--base-url`. Flags used above: `-c` context size,
`-ngl all` offloads every layer to the GPU, and `-a NAME` sets the model id the
API reports (not needed here).

Other backends: `--backend ollama` (native `/api/chat`, `OLLAMA_HOST`) and
`--backend openai --base-url http://127.0.0.1:1234/v1` for LM Studio, vLLM, or
anything else that speaks the OpenAI chat schema.

`--mode system` puts the page in the system prompt (browser-assistant style);
`--mode rag` inserts it as a user turn immediately before the question (RAG
style). `--backend openai` also reads `OPENAI_API_KEY` if you need it; llama.cpp
and LM Studio do not.

**If llama.cpp was started with `--api-key`**, the shim must forward it —
otherwise every request is a 401:

```sh
python bench/garak/shim.py --page ... --backend llamacpp --api-key "$env:LLAMA_KEY"
# or export SHIM_UPSTREAM_KEY / LLAMACPP_API_KEY and omit the flag
```

No model handy? `python bench/garak/shim.py --selftest` exercises the HTTP layer
with an echo backend and no network. Run it first; it takes a second and catches
port/JSON mistakes before you blame garak.

## 2. Confirm the pipeline answers

```sh
curl -s http://127.0.0.1:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"lemon-shim","messages":[{"role":"user","content":"What does the Starter plan cost?"}]}'
```

If the poisoned page is loaded, a compliant model repeats the injected claim.
That single exchange is the "why this matters" screenshot.

## 3. Run garak

`rest.json` in this directory is a generator definition for the shim. Per the
garak reference, `-G/--generator_option_file` loads it and `--target_type rest`
selects `RestGenerator`:

```sh
garak --target_type rest -G bench/garak/rest.json \
      --spec "probes.promptinject,probes.dan,probes.encoding" \
      --generations 1 \
      --report_prefix bench/garak/run1
```

Notes on the flags, checked against the reference docs (garak 0.17.x):

- `--spec` is the current selector syntax; `--probes` is deprecated. One
  selector per family, comma-separated.
- `response_json_field` is only treated as a JSONPath when it starts with `$`,
  hence `$.choices[0].message.content` in `rest.json`.
- `--target_name` is optional for `rest`; the URI lives in the config.
- `--report_prefix` writes `<prefix>.report.jsonl` and `<prefix>.report.html`.

Confirm the plugin still exists in your install:

```sh
garak --list_generators | grep -i rest
garak --version
```

**Caveat:** the command above follows the 0.17.x reference, but it has not been
executed in this workspace (no garak install here). Pin the version and keep the
console output with the report.

Keep the probe set small: a full sweep takes hours and mostly repeats the same
three findings. `promptinject` is the one that matters for this pipeline; `dan`
and `encoding` add breadth cheaply.

## 4. What to record

- garak version, model and quantisation, page file hash, probe list, date.
- Pass/fail counts per probe family from the report.
- Exactly three findings, each translated into a risk-register row and an
  Annex A control (prompt injection → R-01 → 8.26 / 8.28).
- One mitigation actually applied, then a re-run and the delta.

A baseline without a re-test is a screenshot. Baseline → fix → delta is evidence.

## 5. Honest caveats

- **Garak tests model compliance, not concealment.** Its payloads are mostly
  visible text. A high failure rate means "the model obeys page text", which is
  the point of the pipeline test — not evidence that Lemon Juice works.
- **Local models are easy to break.** Small quantised models fail many probes.
  Report the model and size, and do not generalise to production vendors.
- **Do not point garak at endpoints you do not own.** Free tiers and third-party
  APIs are not yours to fuzz; hammering them is a quick way to lose the account.
- **Pin the version.** Garak probe names and report fields change; an
  unpinned run is hard to reproduce six months later.

## 6. Where this plugs into the portfolio

`bench/results/*.csv` and the garak report are the two evidence artifacts. Cite
them from the ISMS portfolio as 8.29 (security testing in development) and 10.1
(corrective action), and put the delta — before and after — in the write-up.

## 7. Detector corpus (offline)

The same probe structure also seeds a detector benchmark. `extract.py` reads an
unpacked garak 0.17.1 wheel and writes `bench/garak/corpus.jsonl` (encoding
and adversarial-suffix cases, neutral payloads). The committed corpus is scored
by `node bench/garak.js`; runtime needs no garak, torch, or network.

```
python bench/garak/extract.py --garak-src ../.tmp/garak-src --out bench/garak/corpus.jsonl
```

See `PROVENANCE.md` for upstream version, sources, and licensing.
