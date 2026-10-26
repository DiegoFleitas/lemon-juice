# Lemon Juice

**Status: archived (2026-10-26).** A detection experiment, kept public because the
negative result and the measurement know-how are more useful than the tool.

> It detects a property of the web, not a property of an attack.

This repository was built between July and October 2026 (177 commits): a Firefox
and Chrome extension that reveals concealed text on a page and flags
prompt-injection payload shapes before you hand that page to a model. It works as
described. What was never established — until the end — is whether the thing it
detects is worth detecting.

It is not. Here is the measurement, and here is what the work is still good for.

---

## The measurement

A 290-page sample of real agent-ingest text (Common Crawl plain-text extraction,
29 files, 275 domains, deterministic seed), plus a frozen protocol:

| Quantity | Value |
| --- | --- |
| Pages containing invisible characters | **11.7%** (34/290, 95% CI 8.5–15.9%) |
| Of those, benign mechanisms (BOM, CJK zero-width, emoji selectors, word joiner) | 33 of 34 |
| Pages the detector flagged at `suspicious` or worse | **0 of 290** (95% CI 0.0–1.3%) |
| Verdicts | 93 clean, 197 `noise` |
| Dominant finding | `mixed-script` (191/290) — i.e. "this page is not monolingual Latin" |

Concealment mechanisms are common on the web and almost always legitimate. The
detector, keyed on those mechanisms, therefore either stays silent or reports that
a page is multilingual. There is no operating point on real traffic.

Protocol, scripts and data: **[prompt-injection-base-rate](https://github.com/DiegoFleitas/prompt-injection-base-rate)**.

## Why the premise was wrong

1. **Base rate.** Hidden characters are a property of ordinary pages, not a
   signal of an attack. A detector whose mechanism fires on 11.7% of the web for
   benign reasons cannot distinguish the attack that shares the mechanism.
2. **Inverted surfaces.** The extension uniquely sees comments, attributes and
   CSS-hidden text — none of which reach a model through a human paste, the
   extension's own use case. The surfaces that *do* reach a model through an
   agent fetch are the ones a page-side tool cannot watch.
3. **Detection without a decision.** A warning that does not change the next
   action is a nag. Blocking was out of scope by design, and the harm case
   (unattended agent with tools) was never in scope at all.

None of this makes prompt injection less real — it is OWASP LLM01 and
EchoLeak-class bugs exist. It means a *mechanism* detector on the page is the
wrong instrument. The defence belongs in the agent: least privilege, egress
control, treating all ingested content as data, human approval for side effects.

## What is still worth reading here

Months of work went into parts that outlive the product decision:

- **`docs/limitations.md`** — a complete, honest catalogue of what the detector
  misses and why, including measured recovery rates. Most security tools never
  publish this. It is the most reusable document in the repository.
- **The detector and its taxonomy** — a 2,011-line pure-function detector over
  invisible Unicode, bidi controls, Tags-block smuggling, variation selectors,
  sneaky bits, encoded blobs and instruction shapes, covered by 309 unit tests
  across three suites, 6 e2e specs and 75 fixtures. Useful as a **corpus of
  attack patterns** (red-team training, CHAISH material), not as protection.
- **`bench/`** — an evaluation harness with a synthetic 84-case concealment
  matrix, a 111-case garak-derived corpus, a 24-payload paraphrase axis and an
  NVIDIA NeMo Guardrails cross-check. Reusable for evaluating *any* input filter.
- **A negative lesson, documented:** an evasion-cost metric that reported "how
  many mutations to evade" and was actually reporting each case's starting
  verdict tier, plus a hyperparameter that swung the headline number by 2×. It
  was caught in review and recorded rather than quietly deleted — the methodology
  note matters more than the number ever did.

## What I would do differently

1. **Measure the base rate first.** One week of corpus work would have saved
   three months of engineering. The protocol now exists; it should have existed
   before the first detector.
2. **Evaluate a detector as a classifier.** Precision, recall and the prevalence
   it operates at — not "did it fire on my payload collection".
3. **Never ship a product on an unvalidated threat model.** The README described
   the threat confidently while the prevalence was unknown; that ordering is the
   overclaim, more than any single sentence in it.
4. **A metric that runs is not a metric that measures.** Any new number needs a
   sensitivity check and a confound check against the number it claims to add to.

## Where the work continues

- The base-rate study: `prompt-injection-base-rate` (protocol, scripts, results).
- Spanish-language AI-safety material built on it: CHAISH.
- The extension listings are deprecated: the AMO alpha listing is being delisted;
  the Chrome build was never published.

## Don't install this as protection

If you want protection: constrain the agent, not the page. If you want to see
what is hidden on a page you are reading, the code still does that — clone it,
load it temporarily, and read `docs/limitations.md` first.

## Credits

Attack taxonomy from OWASP LLM01: Prompt Injection. Prior art: Stegano and
ZeroWidth-Detection-Firefox by mikkel1156. License: GPL-3.0.
