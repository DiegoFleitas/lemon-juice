# How severity and the page verdict are computed

This is the model behind the [Severity and the page verdict](../README.md#severity-and-the-page-verdict)
section of the README. The implementation lives in `detectors.js`
(`promoteSeverity`, `applyContextualPromotion`, `pageVerdict`,
`corroborationCount`) and is called from `scan.js` after deduplication. The
decision records in [`decisions/`](decisions/) explain how the model got here.

## Severity is earned rather than fixed

Severity starts from _how likely a pattern is to be an attack vs. a legitimate
feature_. Bidi overrides and the Tags block are essentially never innocent in
web copy; zero-width joiners are legitimate in Arabic/Indic scripts and emoji, so
they score low. The instruction-phrase detector and all deobfuscation passes are
informational on their own: they false-positive on any page _about_ prompt
injection (including the OWASP page and the README).

Severity is then **earned rather than fixed**, because a mechanism alone says
little. Two things can raise it:

- **Payload corroboration.** Every decoded payload (base64, percent-encoding, hex escapes, variation selectors, the reassembled Unicode-Tags string) is re-scanned for injected content. A blob whose payload carries an LLM control token or a reverse shell convicts on its own and goes to HIGH; one carrying instruction-like prose moves a single step. Each corroborator is weighted by its own severity, so a bare `eval(` inside a decoded code sample stays informational.
- **Proven concealment.** A phrase that only became readable after stripping invisible characters or undoing leetspeak/homoglyphs, or one sitting in an HTML comment, an attribute, or genuinely hidden (non-accessibility) text, moves a step. Mere proximity does not count: an invisible character elsewhere in the same paragraph is not evidence.

A page carrying an injection hides its instructions. A page about one leaves
them in plain sight, which is why documentation and security writeups do not
climb. The verdict the popup shows is derived from the resulting severity mix;
the four tiers and their thresholds are in the [README](../README.md#severity-and-the-page-verdict).

## Why there is no 0–100 score

A 0–100 score suits a scanner reading a closed, enumerable input such as a
manifest permission list, where the denominator is real. A web page's finding
space is unbounded and there is no external reputation signal to moderate a
composite with, so a number would imply precision the input cannot support. A
verdict tier is the honest level of detail.

## Known accepted false positive

A page that _demonstrates_ prompt injection by showing an encoded payload scores
the same as one carrying it. The bytes an LLM ingests are identical, and
"showcase vs. carry" is not mechanically decidable, so this is left in rather
than papered over with intent-guessing heuristics. This is a detection aid. A
human makes the call.

## See also

- [`bench/README.md`](../bench/README.md) — measured mechanism detection, payload recovery and verdict rates.
- [`docs/decisions/`](decisions/) — the scoring decisions, including the accepted paraphrase ceiling.
- [`AGENTS.md`](../AGENTS.md#architecture) — where the scoring functions sit in the codebase and the rules for adding to them.
