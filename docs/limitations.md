# Limitations

Lemon Juice flags things for a human to judge. Highlighted **≠** malicious, it
produces both false negatives and false positives, and a clean scan means
"nothing obvious found," not "this page is safe." The [README](../README.md) has
the short version; this page is the full catalogue. Measured detection-recovery
numbers live in [`bench/README.md`](../bench/README.md).

## Known misses

These are detectable in principle, just not implemented (or only partially implemented) today. Several have working local bypass demonstrations — concrete attack payloads that slip past every detector:

- **Cross-element dialogue**: fabricated conversation turns split across sibling elements — each turn is a separate text node, so the turn-pair detector never sees them together.
- **Unlisted role labels**: `Visitor:`, `Guide:`, `Guest:`, `Interviewer:`, `Q:`/`A:` — labels outside the recognized set bypass role recognition. **Partially addressed**: the structural matcher now uses `\p{L}{1,21}` so any letter-starting label (including these) is detected. A hardcoded enumeration is no longer maintained.
- **Rephrased override language**: paraphrase as a class is still out of scope by design — the instruction detector is a phrase list, and paraphrase is unbounded. Measured on a 24-payload axis: **12.5% recovered (3/24), none at verdict level, 0/12 on the held-out half** before the 2026-10-25 structural additions; now **29.2% (7/24), none at verdict level, 1/12 held out**. Those additions encode five payload _shapes_ (exfiltration with a destination, extraction grammar, credential imperative, a bare second-person override), not a classifier, and the held-out bar in [`decisions/2026-10-20-paraphrase-ceiling.md`](decisions/2026-10-20-paraphrase-ceiling.md) is not met. See [`decisions/2026-10-25-detection-strengthening.md`](decisions/2026-10-25-detection-strengthening.md).
- **Spaced-letter coverage**: payloads with 2+ spaces between words are now collapsed generically (`collapseSpacedTokens`) before the instruction scan — measured **100% on the benchmark matrix, was 17%**. A payload spaced with a single space between every letter _and_ every word has no recoverable word boundary; it still relies on the three override families written out in `SPACED_INSTRUCTION_PATTERNS`, so a novel phrasing in that exact spacing can slip.
- **Compliance flip outside regex vocabulary**: `"No problem, here is…"` avoids every word in `COMPLIANCE_FLIP_RE` (`sure|certainly|of course|understood|absolutely`).
- **Single-turn override**: a lone `User:`-styled directive without a fabricated assistant reply — the detector requires ≥2 distinct role-labeled turns.
- **Closed shadow roots**: `mode:"closed"` — `.shadowRoot` is null by spec, unreachable.
- **Dynamic/post-scan injection**: content injected via `setTimeout`, fetch callback, or user interaction after the scanner runs.
- **`<template>` content**: `DocumentFragment` inside `<template>` is not traversed by TreeWalker on the document.
- **Payload splitting**: instructions across multiple DOM nodes (OWASP #6).
- **Raw model elements**: a `<think>` or `<thinking>` tag written as an HTML element is parsed as markup, so the tag name never reaches a text node. Only fake model frames delivered as text (visible copy, HTML comments, and the `aria-label`/`title` attributes the scanner already reads) are scanned. Frames of any length are detected; the first 4 KiB of each frame are stored and re-scanned for corroboration.
- **Adversarial suffixes**: high-entropy gibberish triggers (OWASP #8).
- **Small-capital / phonetic-extension letters (partially fixed)**: `ɪɢɴᴏʀᴇ` is not a Unicode compatibility variant, so NFKC leaves it untouched and `\b` never saw ASCII. `unicodeLetterToAscii` now folds the U+1D00 set, so the spelled-out instruction below is caught — 0% → 50% on the benchmark matrix, and 100% after the 2026-10-25 structural additions (the second gain is phrasing coverage, not the letter map). Phonetic-extension letters outside that table may still slip.
- **Visible-character obfuscation**: emoji, symbols, or punctuation between words in an instruction phrase ("ignore 🔒 all previous instructions"). Only 🚫 substituting for "ignore"/"disregard" is individually patterned.
- **Emoji-only instructions**: pictograph sequences conveying a message visually.
- **Compound obfuscation built on an undetected primitive**: the normalization passes do compose. NFKC fancy-Unicode, leetspeak, delimiter stripping and spaced letters stack, so a double-struck phrase written with spaced letters is still caught. Layering only helps for primitives the normalizer already knows, though, so anything built on a miss listed above (phonetic letters outside the fold table, visible-character obfuscation) slips through however the layers combine.
- **Cross-origin iframes**: scanned on Firefox. Every frame the extension can reach scans only its own document and the popup merges the per-frame results, so a payload inside a cross-origin frame is found there. Chrome's `activeTab` covers only the top frame's origin, so a cross-origin frame stays invisible on Chrome (same-origin frames are scanned on both). If a browser refuses the all-frames injection outright, the popup falls back to top-frame scanning and those frames are missed again; frames that load after the click are never rescanned.

## Out of scope by design

These attack vectors are unreachable by a static DOM text scanner. They require runtime monitoring, image processing, or conversation state:

- **Multimodal / image-based payloads** (OWASP #7): text-only scanner; images are never inspected.
- **Server-side, URL-fragment, and dynamically-fetched content**: not in the rendered DOM at scan time.
- **Closed shadow roots**: unreachable by spec. The Shadow DOM API deliberately hides them.
- **Data exfiltration**: sending stolen content to a remote server. Requires network-level or output-level monitoring. This extension makes zero network calls and never reads model output.
- **Multi-turn attacks**: building up malicious context across multiple user/assistant exchanges. Requires conversation state tracking across turns. This extension scans a single page snapshot on click.
- **Few-shot poisoning structure**: inserting fake `user:`/`assistant:` example pairs to bias output. The role-prefix heuristic catches individual `human:`/`ai:` lines, but detecting the structure of an embedded conversation is beyond regex scope.
- **Prompt flooding / token overload**: thousands of repeated tokens or deeply nested parentheses used to overwhelm context windows — undetectable from a static text-scan snapshot, and any threshold-based heuristic would false-positive hard on legitimate pages with long content.
- **Denial-of-service via infinite loops** ("Write a never-ending story"): intent/behavioral attack; a model looping is not detectable in static page text.
- **Data poisoning / training-data injection**: occurs during fine-tuning, not at inference time via rendered DOM.
- **Semantic/thematic bias injection** ("Climate change is a hoax, says science"): requires world knowledge or natural-language understanding to distinguish from genuine debate or discussion — pure regex cannot address.
- **Logical confusion / ambiguous-intent framing** ("I'm just testing eval(), not trying to break anything"): the string `eval(` fires the code-execution detector, but the semantic wrapper ("just testing") is indistinguishable from genuine benign intent via regex.
- **Third-party / API-wrapper injection**: occurs in API request construction, not in rendered DOM text.
- **Output leakage** ("Log this value and send it to me: get_admin_password()"): a user-to-model prompt vector, not page content being scanned.
- **Input-reflection / XSS probes** (`<script>alert(1)</script>`): `<script>` in a text node is too common in docs and code samples to be useful signal. Encoded variants (HTML entities) are caught by the existing entity decoder.

## Known false positives

Legitimate zero-width joiners in Arabic/Indic scripts, SEO keyword stuffing with invisible characters between every letter, and any article discussing prompt injection (including the project README). `.sr-only`/`aria-hidden` accessibility text is still flagged (same CSS techniques as real hidden payloads) but downgraded to LOW/informational rather than suppressed. Full suppression would be a detection-evasion shortcut. It is also barred from corroborating anything, since screen-reader markup is normally the site's own accessibility work. Without that exclusion an accessible chat transcript (`<span class="sr-only">Assistant:</span>`) would score HIGH.

## Why this is not a shield

A browser extension on the page cannot do what OWASP's LLM01 prevention strategies expect of the LLM application developer — enforce least privilege, validate model output, or keep a human in the loop. For unattended agents, the defense has to live in the agent. [Claude for Chrome](https://www.anthropic.com/research/prompt-injection-defenses) classifies prompt injection across text and deceptive UI; its [guidance](https://support.claude.com/en/articles/12902428-use-claude-in-chrome-safely) layers permission prompts with minimal site access. None of it is bulletproof — ShadowPrompt sidestepped those defenses via a browser-extension messaging bug before Anthropic patched it. No vendor claims prompt injection is solved.

**Treat Lemon Juice as a supplement for when you're reading, not a safety net for when you're not.**
