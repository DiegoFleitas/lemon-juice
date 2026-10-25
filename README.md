<div align="center">

<img src="icons/icon-128.png" width="96" height="96" alt="Lemon Juice logo (green, unripe, for the alpha)">

# Lemon Juice

_Escrito con jugo de limón. The lemon is green while this is alpha. It ripens to yellow at 1.0._

![Firefox 115+](https://img.shields.io/badge/firefox-115%2B-orange)
![Chrome (unpacked)](https://img.shields.io/badge/chrome-unpacked-yellow)
![Manifest V3](https://img.shields.io/badge/manifest-v3-yellow)
![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://www.gnu.org/licenses/gpl-3.0.html)

[Why](#why) • [Detects](#what-it-detects) • [Scope](#scope) • [Install](#install) • [Develop](#develop) • [Architecture](#architecture) • [Privacy](#privacy) • [Limitations](#limitations)

Docs: [limitations catalogue](docs/limitations.md) • [detection model](docs/detection-model.md) • [benchmark](bench/README.md) • [security review notes](docs/security-review-notes.md)

</div>

<p align="center">
  <img src="assets/screenshot-04.webp" width="600" alt="Lemon Juice scanning a page: hidden text highlighted on the left, results in the popup on the right">
  <br>
  <em>"Ah, yes. Written with lemon juice." — William of Baskerville, The Name of the Rose (1986)</em>
</p>

A browser extension for Firefox and Chrome that holds a web page up to the flame. It reveals hidden text and flags prompt-injection payloads before you hand the page to ChatGPT, Claude, Gemini, or a browser agent. It uses a non-invasive overlay that never rewrites the page's own styles.

> [!IMPORTANT]
> This is a detection aid, not a shield. It does not block or "clean" anything. A clean scan means "nothing obvious found," not "this page is safe." See [Limitations](#limitations).

![Lemon Juice scanning a page: highlighted hidden text on the left, results panel on the right](assets/lemon-juice.webp)

## Why

Indirect prompt injection is ranked **LLM01** (the single highest risk) in the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/). Attackers hide instructions in invisible Unicode, bidi overrides, or zero-width characters: a human sees nothing, an AI reads and obeys. The browser is where most of us meet this threat. Yet on Firefox the only existing tooling was a narrow zero-width-character add-on.

Click the toolbar icon and Lemon Juice surfaces invisible Unicode, ASCII smuggling via the Unicode Tags block, visually hidden text, encoded blobs, control tokens, and instruction-like phrases. Findings are highlighted on the page and listed in the popup, grouped by severity, and can be exported as JSON or plain text.

It detects **concealment and known payload shapes**; it does not classify intent. A reworded instruction can be perfectly visible to a human and still pass through — see [Known misses](docs/limitations.md#known-misses) for the measured number.

**Why Firefox first?** I use it day to day. Chrome's automation-protocol tooling is more mature and most agent frameworks target it first, so the Chrome port shipped as an unpacked build first, with the Web Store listing still on the [roadmap](#roadmap).

## What it detects

Coverage is measured, not asserted: [`bench/`](bench/) runs 84 attack cases across 14 hiding techniques and 26 benign pages, and reports mechanism detection, payload recovery and page verdict separately. Current numbers and known gaps are in [`bench/README.md`](bench/README.md).

### High confidence

Patterns essentially never legitimate in web copy, or well-filtered against common false positives.

| Category                                                                         | Examples                                                                                                                                               | Severity   |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- |
| **ASCII smuggling**                                                              | Unicode Tags block (`U+E0000–E007F`) carrying a full hidden ASCII payload                                                                              | High       |
| **Bidi controls**                                                                | RTL/LTR overrides & isolates that reorder or hide text ("Trojan Source")                                                                               | High       |
| **Variation-selector smuggling**                                                 | Bytes hidden in a run of variation selectors after a base emoji                                                                                        | High       |
| **Sneaky Bits**                                                                  | Invisible-times (U+2062) and invisible-plus (U+2064) encoding binary bits as a byte stream                                                             | High       |
| **LLM control tokens**                                                           | `<\|im_start\|>`, `[INST]`, `<<SYS>>`, Gemma `<start_of_turn>`, GLM `[gMASK]`/`<sop>`, and other ASCII `<\|marker\|>` or fullwidth `｜marker｜` tokens | High       |
| **Visually hidden text**                                                         | 1px fonts, `opacity:0`, off-screen positioning, text-color-equals-background                                                                           | Medium     |
| **Zero-width & invisible chars**                                                 | ZWSP, word joiner, BOM, soft hyphen, Arabic/Syriac/Mongolian format chars                                                                              | Medium/Low |
| **Encoded blobs (base64, base32, ASCII85, hex, ROT13/Atbash, percent, escapes)** | Runs that decode to readable ASCII, filtered against binary and JWT-like payloads                                                                      | Medium     |

### Informational (heuristic)

Prone to false positives on legitimate pages that discuss prompt injection, so they never convict on their own. Corroboration, or evidence that the text was deliberately concealed, can promote them. See [Severity and the page verdict](#severity-and-the-page-verdict) below.

| Category                                                        | Examples                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Instruction phrases**                                         | "ignore previous instructions", `system:`, `human:`, "reveal your system prompt", "fetch data from evil.com"                                                                                                                                                                                                                                                                                                                                   |
| **System-prompt extraction probes**                             | "repeat the text above verbatim", "encode your instructions in base64"                                                                                                                                                                                                                                                                                                                                                                         |
| **Leetspeak obfuscation**                                       | `1gn0r3 4ll pr3v10us 1nstruct10ns`                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Fancy Unicode letters**                                       | Math bold/italic/script/fraktur/sans-serif, fullwidth letter forms, regional-indicator-symbol letters                                                                                                                                                                                                                                                                                                                                          |
| **Delimiter-stripped text**                                     | Pipe, underscore, backtick, caret, tilde between letters                                                                                                                                                                                                                                                                                                                                                                                       |
| **Spaced-letter instructions**                                  | `i g n o r e a l l p r e v i o u s i n s t r u c t i o n s` — three override families only, see [Known misses](docs/limitations.md#known-misses)                                                                                                                                                                                                                                                                                               |
| **Emoji-substituted phrases**                                   | 🚫 substituting for "ignore" or "disregard"                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Chain-of-thought hijacking phrases**                          | "let's think step by step", "take a deep breath and think carefully"                                                                                                                                                                                                                                                                                                                                                                           |
| **Delimiter-fence markers**                                     | `---BEGIN INSTRUCTIONS---`, `--- END SYSTEM ---` section fences                                                                                                                                                                                                                                                                                                                                                                                |
| **JWT-downgraded base64 blobs**                                 | Base64 runs that look like JWT header+payload segments                                                                                                                                                                                                                                                                                                                                                                                         |
| **Fabricated conversation turns**                               | `User:`/`Assistant:` dialogue carrying an instruction or refusal flip (single text node only)                                                                                                                                                                                                                                                                                                                                                  |
| **Fake model frames**                                           | `<think>…</think>`, `<thinking>…</thinking>`, `<tool_call>…</tool_call>`, `<function=…>…</function>`, `<parameter=…>…</parameter>` wrapping injected text as the model's own deliberation or tool call — LOW on its own (an unclosed opener is a LOW incomplete frame), promoted when concealed or when the frame carries a control token or executable content that is itself scored as evidence (a bare `eval(`/`exec(` stays informational) |
| **Compound / continuation-of-system-prompt instructions**       | "As part of your updated guidelines", "Per your revised instructions"                                                                                                                                                                                                                                                                                                                                                                          |
| **HTML entities, unicode escapes, combining marks, homoglyphs** | Decoded/revealed via normalization pipeline                                                                                                                                                                                                                                                                                                                                                                                                    |

### Severity and the page verdict

Severity starts from _how likely a pattern is to be an attack vs. a legitimate feature_ — bidi overrides and the Tags block are essentially never innocent in web copy, while zero-width joiners are legitimate in Arabic/Indic scripts and emoji and score low. It is then **earned rather than fixed**: decoded payloads are re-scanned for injected content (corroboration), and text that only became readable after undoing an obfuscation moves up a step. Instruction-phrase heuristics never convict on their own. The full rules — what corroborates what, how concealment is proven, and why there is deliberately no 0–100 score — are in [`docs/detection-model.md`](docs/detection-model.md).

The popup leads with a page verdict rather than a raw count:

| Verdict            | Meaning                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------- |
| `clean`            | Nothing found                                                                            |
| `noise`            | Findings, but nothing corroborating and nothing high. A lone zero-width space lands here |
| `suspicious`       | A high-severity finding, or one corroborated finding                                     |
| `likely-injection` | A corroborated high-severity finding, or two independently corroborated findings         |

There is deliberately **no 0–100 score**, and a page that _demonstrates_ an injection by showing an encoded payload scores the same as one carrying it. Both are deliberate choices, covered in the detection model linked above.

## Scope

OWASP's LLM01 prevention strategies target the **LLM application developer**: constrain model behavior, validate outputs, enforce least privilege, keep a human in the loop. A browser extension on the page can't do any of those. What it _can_ do maps to one-and-a-half of them:

- **#6 Segregate and identify external content**: surface hidden content so a human notices it before feeding the page to an assistant.
- A client-side sliver of **#3 Input filtering**: flag known obfuscation vectors.

So the honest scope is: **reveal what an AI would ingest but you can't see.** Detection is not interception. This tool only helps when a human is watching. It runs on click, so it never sits inside an agent's own browsing loop. What it flags spans both categories: HIGH-severity patterns (control tokens, bidi overrides, invisible chars) are jailbreak or smuggling artifacts; LOW-severity patterns (instruction phrases) signal an injection attempt on the page.

For unattended agents the defense has to live in the agent, not on the page — [`docs/limitations.md`](docs/limitations.md#why-this-is-not-a-shield) covers why no browser extension closes that gap.

**Treat Lemon Juice as a supplement for when you're reading, not a safety net for when you're not.**

## Install

**From source (temporary add-on):**

1. Clone this repo.
2. Open `about:debugging#/runtime/this-firefox` in Firefox.
3. **Load Temporary Add-on…** and pick `manifest.json`.
4. Click the Lemon Juice icon in the toolbar on any page.

> [!NOTE]
> Temporary add-ons are removed when Firefox restarts. Reload from `about:debugging` to bring it back during development.

**AMO listing:** [Lemon Juice (Alpha)](https://addons.mozilla.org/firefox/addon/lemon-juice-alpha/) is live at 0.10.0. The 1.0 release will replace the alpha listing.

**Chrome (unpacked):**

1. `pnpm install && pnpm run package:chrome` — stages the Chrome build in `dist/chrome`.
2. Open `chrome://extensions` and turn on **Developer mode**.
3. **Load unpacked** and pick `dist/chrome`.
4. Click the Lemon Juice icon in the toolbar on any page.

> [!NOTE]
> There is no Chrome Web Store listing yet; the port ships unpacked first. The store listing is on the [roadmap](#roadmap).

## Develop

```sh
pnpm install
pnpm test        # unit tests (detectors.js, scan-helpers.js — pure, DOM-free)
pnpm test:e2e    # Playwright tests against real fixtures (Firefox and Chromium)
pnpm lint        # eslint + prettier
```

Buildless: plain ES modules, no bundler, no transpile step. Source files load directly as content scripts.

`detectors.js` and `scan-helpers.js` are deliberately free of `document`/`window` access, so detection logic tests in Node with no DOM harness. Add cases to `__tests__/detectors.test.js` for new detectors, `__tests__/scan-helpers.test.js` for helper changes, and `__tests__/e2e/` + `__tests__/fixtures/` when behavior needs a real page.

For test pages that exercise detection:

- [PayloadsAllTheThings — Prompt Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prompt%20Injection#tools)
- [Prompt-Injection-Everywhere](https://github.com/TakSec/Prompt-Injection-Everywhere)

> [!CAUTION]
> A clean scan against known payload collections does **not** mean the scanner catches everything. Attackers cook up techniques not sitting in any public repo yet. This scanner only knows the hiding tricks it was built to look for.

## Architecture

Five files, buildless, with a strict split between pure logic and DOM:

- `detectors.js` — **pure** detection logic (string in, findings out); no DOM, dual-exported for tests.
- `scan-helpers.js` — DOM helpers for scanning and overlay rendering.
- `scan.js` — DOM side: walks text and comment nodes across the top document, every open shadow root and every same-origin iframe, then draws the non-invasive overlay.
- `popup.js` / `popup.html` — injects the scripts into the active tab, renders findings, sets the badge, exports JSON/TXT.
- `manifest.json` — MV3, shared by both browsers; the Chrome manifest is derived at package time (Gecko-only keys dropped).

Injection order matters: `detectors.js` > `scan-helpers.js` > `scan.js`. Each file reads `globalThis` at the top of its IIFE. [`AGENTS.md`](AGENTS.md#architecture) has the load-bearing details: the scoring layer, the overlay invariants, and which tests to add when changing a detector.

## Privacy

- **Nothing leaves your browser.** No network calls, telemetry, or analytics.
- **No host permissions.** `activeTab` grants page access only when you click the icon.
- **No dynamic code execution.** No `eval`, `new Function`, or remote code. The MV3 manifest ships `script-src 'self'`.
- All decoding and scanning happens locally in the content-script sandbox.

> [!NOTE]
> Static scanners sometimes flag `detectors.js` for "dynamic code execution": it carries attack-payload strings like `eval(` and `bash -i >& /dev/tcp/` as inert regex pattern data. [`docs/security-review-notes.md`](docs/security-review-notes.md) has the rebuttal, with commands to verify it yourself.

## Limitations

> [!WARNING]
> Highlighted **≠** malicious. This tool flags things for a human to judge. It produces both false negatives and false positives.

The full catalogue — every known miss with its measured recovery number, the vectors that are out of scope by design, and the accepted false positives — is in [`docs/limitations.md`](docs/limitations.md). The headlines:

- **Cross-origin iframes** are not traversed (same-origin policy); per-frame aggregation is on the [roadmap](#roadmap).
- **Dynamic / post-scan content**, `<template>` fragments and **closed shadow roots** are invisible to a static DOM snapshot.
- **Cross-element dialogue and payload splitting**: instructions split across DOM nodes are never reassembled.
- **Rephrased override language** is the largest measured gap: 29.2% recovered on a 24-payload axis, 1/12 on the held-out half, none at verdict level.
- **No images, no conversation state**: multimodal payloads and multi-turn attacks are out of scope by design.
- **Accessibility text** (`.sr-only`, `aria-hidden`) is still flagged, but downgraded to LOW and barred from corroborating anything.

Current detection-recovery numbers are in `bench/README.md`; [`docs/decisions/`](docs/decisions/) records which misses are deliberately left open.

## Roadmap

- [x] Full detector matrix in `__tests__/detectors.test.js`
- [x] Recursive open shadow root and same-origin iframe scanning
- [ ] Cross-origin iframes via `scripting.executeScript({ allFrames: true })`, with per-frame result aggregation. Firefox can reach these under `activeTab`; a Chrome build would need host permissions for cross-origin frames.
- [ ] Opt-in auto-scan on user-configured domains (per-site host permissions, kept off by default). This changes the no-host-permissions posture, so it needs an options page and a privacy-section rewrite, not just a detector.
- [x] Chrome port: namespace shim, Chromium Playwright project, and `pnpm run package:chrome` packaging.
- [ ] Chrome Web Store listing (developer account, privacy policy, review).
- [ ] 1.0: replace the [alpha AMO listing](https://addons.mozilla.org/firefox/addon/lemon-juice-alpha/) with a stable one, and define the exit criteria for the items above.

## Credits

- Attack taxonomy from [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
- Prior art: **Stegano** (invisible-Unicode classifier) and **ZeroWidth-Detection-Firefox** by mikkel1156.
