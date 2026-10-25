# bench — measured detection, not vibes

Runs the pure detector (`detectors.js`) over a synthetic attack matrix and a
benign corpus, and writes a CSV plus a markdown summary. No DOM, no browser, no
network: this measures exactly what `scanText` + `applyContextualPromotion` do,
which is the detection core.

```
node bench/run.js                        # writes results/<date>-run-<HHMMSS>
node bench/run.js --tag=after-fix        # named run, refuses to overwrite
node bench/run.js --tag=before --force   # replace an existing run on purpose
```

A run never overwrites a committed one: the default tag is a timestamp, and an
explicit tag that already exists aborts unless you pass `--force`. The two
committed runs are the evidence for the delta, and silent replacement would
destroy it.

Outputs land in `bench/results/<date>-<tag>.csv` and `.md`. The CSV has one row
per case, so anything in the summary can be traced back to a payload. The two
committed runs are `2026-10-20-before-smallcaps` and `2026-10-20-after-smallcaps`
— keep both, they are the delta.

## What it measures

| Metric          | Definition                                                                                                                                        | Why it matters                                                |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **any finding** | `findings.length > 0`                                                                                                                             | Did anything at all fire, including informational?            |
| **medium+**     | any HIGH or MEDIUM finding                                                                                                                        | Was a _mechanism_ spotted (Tags block, bidi, base64, …)?      |
| **recovered**   | the instruction itself was recognised (`instruction-phrase`, `control-token`, `context-switch`), including as a corroborator of a decoded payload | Did the scanner understand the payload, not just the wrapper? |
| **verdict**     | `pageVerdict` reached `suspicious` or `likely-injection`                                                                                          | What the product would show the user                          |

Mechanism detection and payload recovery are separated on purpose: a scanner can
catch every Tags-block payload while never recognising the sentence inside it.

## Corpus

- **Attacks:** 14 techniques × 6 instruction payloads = **84 cases**. Each
  encoded run is embedded in benign prose on its own line, the way a payload
  appears on a real page.
- **Payload classes:** 3 `canonical` phrasings (the kind the README documents as
  covered) and 3 `paraphrases` (the kind the README lists under "known misses").
  Scored separately — otherwise a phrase-coverage gap and a concealment gap look
  like the same number.
- **Benign:** 26 pages (see `corpora/benign/SOURCES.md`), including a page that
  discusses prompt injection and quotes payloads.

Generators are reversible by construction: the runner asserts
`decode(encode(payload)) === payload` before scoring, so a miss is the detector's,
not a broken encoder.

## Results — 2026-10-20, seed 42

84 attack cases, 26 benign pages. Numbers below are **after** the small-caps fix;
the delta is in the next section.

| Technique           | n      | any finding | medium+ | recovered | verdict |
| ------------------- | ------ | ----------- | ------- | --------- | ------- |
| unicode-tags        | 6      | 100%        | 100%    | 50%       | 100%    |
| variation-selectors | 6      | 100%        | 100%    | 50%       | 100%    |
| sneaky-bits         | 6      | 100%        | 100%    | 50%       | 100%    |
| bidi-controls       | 6      | 100%        | 100%    | 50%       | 100%    |
| zero-width          | 6      | 100%        | 100%    | 50%       | 50%     |
| base64              | 6      | 100%        | 100%    | 50%       | 50%     |
| percent-encoded     | 6      | 100%        | 100%    | 50%       | 50%     |
| hex-escapes         | 6      | 100%        | 100%    | 50%       | 50%     |
| fullwidth-nfkc      | 6      | 50%         | 50%     | 50%       | 50%     |
| homoglyphs          | 6      | 100%        | 50%     | 50%       | 50%     |
| leetspeak           | 6      | 50%         | 50%     | 50%       | 50%     |
| plain-control       | 6      | 50%         | 0%      | 50%       | 0%      |
| spaced-letters      | 6      | 17%         | 17%     | 17%       | 17%     |
| small-caps          | 6      | 50%         | 50%     | 50%       | 50%     |
| **overall**         | **84** | **80%**     | **73%** | **48%**   | **58%** |

By payload class:

| Class      | n   | medium+ | recovered | verdict |
| ---------- | --- | ------- | --------- | ------- |
| canonical  | 42  | 95%     | 88%       | 88%     |
| paraphrase | 42  | 57%     | 0%        | 29%     |

Benign: any finding **3.8%** (1 page in 26), medium+ **0%**, verdict **0%**.
The one noisy page is the security blog that quotes injection phrases — expected,
and it lands on `noise`, not `suspicious`.

Latency on attack scans: p50 0.7 ms, p95 4.0 ms, max 27 ms.

### Delta: small caps (2026-10-20)

| Metric               | Before | After |
| -------------------- | ------ | ----- |
| small-caps recovered | 0%     | 50%   |
| small-caps verdict   | 0%     | 50%   |
| overall recovered    | 44%    | 48%   |
| canonical recovered  | 88%    | 88%   |
| benign verdict FPR   | 0%     | 0%    |

Only the six small-caps rows changed in the per-case diff (P1, P3, P6 improved;
P2, P4, P5 remain out of reach because the _phrasing_ is not covered, not the
encoding). 174 unit tests pass. The fix is a U+1D00-block fold in
`unicodeLetterToAscii`, not a new detector.

### Delta: structural strengthening (2026-10-25)

Driven by the NVIDIA guardrail cross-check: the guardrail let 55/195 attacks
through, and 15 of Lemon Juice's 17 misses were three payload _shapes_ rather
than new concealment. One detector change, same matrix and seed, 26 benign
pages, no new finding type or severity:

- generic spaced-token collapse (`collapseSpacedTokens`) after deobfuscation, so
  word-spaced payloads are readable before the instruction scan;
- five structural patterns: exfiltration with a URL destination, "repeat
  everything above verbatim", "then follow the new instructions", "disregard
  your guidelines", and a determiner-gated credential-access imperative.

| Metric                  | 2026-10-20 | 2026-10-25 | 2026-10-25 vs 2026-10-20 + guardrail? |
| ----------------------- | ---------: | ---------: | ------------------------------------- |
| any finding             |      79.8% |       100% | —                                     |
| medium+                 |      72.6% |      92.9% | —                                     |
| recovered               |      47.6% |       100% | —                                     |
| verdict suspicious+     |      58.3% |      92.9% | —                                     |
| benign any/medium/verd  |   3.8/0/0% |   3.8/0/0% | —                                     |
| spaced-letters (any)    |      16.7% |       100% | —                                     |
| plain-control (medium+) |         0% |         0% | by design                             |
| paraphrase axis dev     |        25% |        50% | —                                     |
| paraphrase axis holdout |         0% |       8.3% | held-out bar (≥40%) not met           |
| garak recovered         |       100% |       100% | no regression                         |

The main-matrix jump is **shape coverage, not generalisation**: those five
patterns were derived from the misses in this corpus, and the paraphrase axis's
held-out half only moves 0% → 8.3%. Read the gain as "the documented shapes are
now recognised", not "paraphrase is solved". Benign pages and the 90-test browser
suite are unchanged. Decision record:
`docs/decisions/2026-10-25-detection-strengthening.md`; committed runs:
`2026-10-25-after-strengthen`, `2026-10-25-garak-after-strengthen`,
`2026-10-25-paraphrase-after-strengthen`.

## What the numbers say

1. **Smuggling channels are the strong suit.** Tags, variation selectors,
   sneaky bits and bidi controls reach `likely-injection` on every case. That is
   the mechanism working as designed: these patterns essentially never appear in
   legitimate prose. It is also coverage of a **documented** list — the matrix is
   drawn from the techniques this repo implements and documents, so an encoding
   that exists only in the wild is absent from every number here and scores 0 by
   construction.
2. **Recognising the payload was the weak axis in the 2026-10-20 baseline.** At
   that point only half the canonical payloads were recovered, and _none_ of the
   paraphrases. The 2026-10-25 structural additions recover 100% of the matrix
   payloads, but that is shape coverage (see the delta above and the paraphrase
   holdout), not a general paraphrase capability.
3. **Small caps: fixed.** The 2026-10-20 fix took small caps 0% → 50%: the U+1D00
   block is not NFKC-foldable, so the normaliser left it alone. The 2026-10-25
   phrasing additions take the family to 100%; the remaining risk is letters
   outside the fold table.
4. **Spaced letters: fixed generically.** The 2026-10-20 baseline was 17% because
   `SPACED_INSTRUCTION_PATTERNS` only covered three override families. The
   generic collapse now handles any payload with 2+ spaces between words (100% on
   the matrix); payloads spaced with a single space between every letter _and_
   word still rely on those three patterns.
5. **Zero-width is the ambiguity case.** The mechanism is MEDIUM by design, and
   only contextual promotion (phrase revealed after stripping) lifts the verdict.
   That works for a canonical phrase and fails for a paraphrase — consistent with
   (2).
6. **Benign traffic is quiet.** 0% verdict FPR, one informational page. With 26
   pages this is a smoke test, not an estimate.
7. **The guardrail cross-check is the external check.** With the strengthened
   detector, Lemon Juice flags all 195 attacks and reaches verdict level on
   74.4%; every one of the guardrail's 55 escapes is now flagged and recovered,
   and the two attacks missed by both systems are gone. That is a statement about
   this corpus's known shapes, not a claim that the guardrail (or any policy
   check) is redundant.

## Paraphrase axis

The technique matrix measures **concealment**: can the scanner see through this
encoding? `bench/paraphrase.js` measures **phrasing**: can it recognise the
instruction when the words change? 24 payloads, four families (lexical,
structural, oblique, roleplay), half held out.

| Signal                |    2026-10-20 |      2026-10-25 |
| --------------------- | ------------: | --------------: |
| Instruction recovered |         12.5% |           29.2% |
| Medium+               |            0% |              0% |
| Verdict suspicious+   |            0% |              0% |
| Held-out split        | **0%** (0/12) | **8.3%** (1/12) |

At the 2026-10-20 baseline the three recovered rows were near-canonical phrasings
that happened to overlap the phrase list. The 2026-10-25 structural additions
move the dev half to 50% but the held-out half only to 8.3%, and none reaches a
verdict. That is a ceiling of phrase-list and shape matching, not proof of
paraphrase understanding: paraphrase is unbounded. The decision to keep it out of
scope, and the conditions that would reopen it, are in
`docs/decisions/2026-10-20-paraphrase-ceiling.md`; the strengthening decision is
in `docs/decisions/2026-10-25-detection-strengthening.md`.

```
node bench/paraphrase.js --tag=baseline
```

## garak-derived axis

A second, separate axis reuses the _structure_ of garak 0.17.1 probes. The
committed corpus (`bench/garak/corpus.jsonl`, 111 cases) is extracted offline;
neither garak nor a model is needed to run it:

```
node bench/garak.js --tag=baseline
```

Payload text is neutral, so no harmful probe base prompts are copied. Families:
`encoding` (base64, base32, ASCII85, plain hex, ROT13, Atbash), `smuggling`
(homoglyph, Unicode Tags, zero-width split), `suffix` (GCG suffix list on a
canonical instruction), `sysprompt_extraction` (garak's static attack
templates), and `web_injection` (Markdown/JS exfil commands with
`example.invalid` domains).

| Family               | Baseline recovered | After recovered | After verdict |
| -------------------- | -----------------: | --------------: | ------------: |
| encoding             |               100% |            100% |          100% |
| smuggling            |              66.7% |            100% |          100% |
| suffix               |               100% |            100% |            0% |
| sysprompt_extraction |              17.9% |            100% |          3.6% |
| web_injection        |                 0% |            100% |            0% |

Benign verdicts stayed at 0%. The suffix result is the interesting negative
one: appending an adversarial suffix does not hide the instruction from a text
scanner, so it does not change the verdict. The sysprompt and web rows recover
at LOW severity; they only reach a verdict when concealed.

Dataset-backed latent-injection generators and the PromptInject generator are
excluded: they need model/dataset dependencies that cannot be extracted
offline. See `bench/garak/PROVENANCE.md`.

## NVIDIA guardrails cross-check

A separate, pinned comparison — not a change to the scanner. The same page text
is fed to both systems on the existing corpora: 84 main-matrix attacks, the 111
garak-derived attacks (dev/holdout reported separately) and the 26 benign pages
as shared controls. The guardrail runs fully offline: NeMo Guardrails 0.24.1
driving `gemma-3-4b-it` Q4_K_M through a local llama.cpp server at temperature 0,
with NVIDIA's example self-check prompt copied verbatim. No cloud endpoint, no
credentials.

On the 195 attacks, Lemon Juice flagged 91.3% (any finding) and 59.5% at
`verdict` level; the guardrail blocked 71.8%. The overlap is partial: of the 151
attacks where Lemon Juice recovered the instruction, the guardrail blocked 111
(73.5%); the guardrail blocked 15 attacks Lemon Juice missed, while Lemon Juice
flagged 53 the guardrail allowed. Benign false positives were 1/26 each (Lemon
Juice `noise` only; one guardrail block). Latency: Lemon Juice p50 0.22 ms
in-process vs guardrail p50 1.4 s / p95 10.7 s on CPU.

> These are the pre-strengthening numbers (v0.9.3 detector), committed as the
> comparison snapshot. Re-scoring the same guardrail decisions with the
> 2026-10-25 detector change: Lemon Juice flags 100%, recovers 100% and reaches
> verdict level on 74.4% of the 195 attacks; all 55 guardrail escapes are flagged
> and recovered, and the two attacks missed by both systems are gone. The
> committed `results/` stay the baseline until re-analysed; see
> `docs/decisions/2026-10-25-detection-strengthening.md`.

This is a property of one pinned local configuration — a 4B quantised model is far
weaker than the models NVIDIA recommends for these rails — not a measurement of
NVIDIA's hosted guardrails, and a page fed directly into an input rail is a proxy
for the real page → prompt → model pipeline.

```
node bench/nvidia-guardrails/run.js --tag=2026-10-25-nemo-selfcheck-gemma3-4b --analyze-only --force
```

Setup, versions, per-family breakdown and limitations are in
[`nvidia-guardrails/README.md`](nvidia-guardrails/README.md), with the numbers in
[`nvidia-guardrails/results/RESULTS.md`](nvidia-guardrails/results/RESULTS.md).

## Threats to validity

- 84 attack cases, 26 benign pages. Directionally useful, not statistically
  stable; expand the benign set before quoting an FPR.
- Synthetic payloads, English only. Real campaigns mix languages and split
  payloads across nodes.
- Text-only layer. Comments, attributes, CSS-hidden text and shadow roots need
  the DOM and are out of scope here (that is what `__tests__/e2e/` is for).
- Payload on its own line. Control-token and role-label patterns are
  line-anchored, so this framing is generous to the detector; a mid-sentence
  payload may score lower.
- **Shape-coverage circularity.** The five structural patterns added on
  2026-10-25 were derived from this corpus's misses, so the main-matrix gain
  measures "documented shapes are recognised", not performance on unseen
  prose. The paraphrase axis's held-out half (0% → 8.3%) is the honest check.

## Adding a technique

1. Add an encoder/decoder pair in `generators/` with a reversible mapping.
2. Register it in `generators/index.js`.
3. Add the assertion case to the matrix automatically — the runner checks
   reversibility and will refuse to score a broken generator.
4. Re-run; the technique appears as its own row.

## Next step

The 2026-10-25 change recovered 100% of the main matrix, so that matrix can no
longer show a shape-coverage delta — the paraphrase holdout is the remaining
honest gap (8.3%). Next: one bounded structural experiment against the
paraphrase dev half, then evaluate once on the held-out half and keep it only if
it clears the ≥40% / ≤2% bar in `docs/decisions/2026-10-20-paraphrase-ceiling.md`.
Separately, refresh `bench/nvidia-guardrails/` results after this change and run
the guardrail comparison against a second local judge model before drawing any
conclusion about the rail itself.
