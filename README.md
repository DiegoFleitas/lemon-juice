<div align="center">

<img src="icons/icon-128.png" width="96" height="96" alt="Lemon Juice logo (green, unripe, for the alpha)">

# Lemon Juice

_Escrito con jugo de limón. The lemon is green while this is alpha. It ripens to yellow at 1.0._

![Firefox 115+](https://img.shields.io/badge/firefox-115%2B-orange)
![Manifest V3](https://img.shields.io/badge/manifest-v3-yellow)
![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](https://www.gnu.org/licenses/gpl-3.0.html)

[Why](#why) • [Detects](#what-it-detects) • [Scope](#scope) • [Install](#install) • [Develop](#develop) • [Architecture](#architecture) • [Privacy](#privacy) • [Limitations](#limitations)

</div>

<p align="center">
  <img src="assets/screenshot-04.png" width="600" alt="Lemon Juice scanning a page: hidden text highlighted on the left, results in the popup on the right">
  <br>
  <em>"Ah, yes. Written with lemon juice." — William of Baskerville, The Name of the Rose (1986)</em>
</p>

A Firefox extension that holds a web page up to the flame. It reveals hidden text and flags prompt-injection payloads before you hand the page to ChatGPT, Claude, Gemini, or a browser agent. It uses a non-invasive overlay that never rewrites the page's own styles.

> [!IMPORTANT]
> This is a detection aid, not a shield. It does not block or "clean" anything. A clean scan means "nothing obvious found," not "this page is safe." See [Limitations](#limitations).

![Lemon Juice scanning a page: highlighted hidden text on the left, results panel on the right](assets/lemon-juice.jpg)

## Why

Indirect prompt injection is ranked **LLM01** (the single highest risk) in the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/). Attackers hide instructions in invisible Unicode, bidi overrides, or zero-width characters: a human sees nothing, an AI reads and obeys. The browser is where most of us meet this threat. Yet on Firefox the only existing tooling was a narrow zero-width-character add-on.

Click the toolbar icon and Lemon Juice surfaces invisible Unicode, ASCII smuggling via the Unicode Tags block, visually hidden text, encoded blobs, control tokens, and instruction-like phrases. Findings are highlighted on the page and listed in the popup, grouped by severity.

**Why Firefox first?** I use it day to day. Chrome's automation-protocol tooling is more mature and most agent frameworks target it first, so a port is on the roadmap.

## What it detects

### High confidence

Patterns essentially never legitimate in web copy, or well-filtered against common false positives.

| Category                                                     | Examples                                                                                            | Severity   |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- | ---------- |
| **ASCII smuggling**                                          | Unicode Tags block (`U+E0000–E007F`) carrying a full hidden ASCII payload                           | High       |
| **Bidi controls**                                            | RTL/LTR overrides & isolates that reorder or hide text ("Trojan Source")                            | High       |
| **Variation-selector smuggling**                             | Bytes hidden in a run of variation selectors after a base emoji                                     | High       |
| **Sneaky Bits**                                              | Invisible-times (U+2062) and invisible-plus (U+2064) encoding binary bits as a byte stream          | High       |
| **LLM control tokens**                                       | `<\|im_start\|>`, `[INST]`, `</system>`, `---END OF PROMPT---` and other chat-template turn markers | High       |
| **Visually hidden text**                                     | 1px fonts, `opacity:0`, off-screen positioning, text-color-equals-background                        | Medium     |
| **Zero-width & invisible chars**                             | ZWSP, word joiner, BOM, soft hyphen, Arabic/Syriac/Mongolian format chars                           | Medium/Low |
| **Encoded blobs (base64, percent, hex escapes, spaced hex)** | Runs that decode to readable ASCII, filtered against binary and JWT-like payloads                   | Medium     |

### Informational (heuristic)

Prone to false positives on legitimate pages that discuss prompt injection. Never raise overall severity on their own.

| Category                                                        | Examples                                                                                                     |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Instruction phrases**                                         | "ignore previous instructions", `system:`, `human:`, "reveal your system prompt", "fetch data from evil.com" |
| **System-prompt extraction probes**                             | "repeat the text above verbatim", "encode your instructions in base64"                                       |
| **Leetspeak obfuscation**                                       | `1gn0r3 4ll pr3v10us 1nstruct10ns`                                                                           |
| **Fancy Unicode letters**                                       | Math bold/italic/script/fraktur/sans-serif, fullwidth letter forms, regional-indicator-symbol letters        |
| **Delimiter-stripped text**                                     | Pipe, underscore, backtick, caret, tilde between letters                                                     |
| **Spaced-letter instructions**                                  | `i g n o r e a l l p r e v i o u s i n s t r u c t i o n s`                                                  |
| **Emoji-substituted phrases**                                   | 🚫 substituting for "ignore" or "disregard"                                                                  |
| **Chain-of-thought hijacking phrases**                          | "let's think step by step", "take a deep breath and think carefully"                                         |
| **Delimiter-fence markers**                                     | `---BEGIN INSTRUCTIONS---`, `--- END SYSTEM ---` section fences                                              |
| **JWT-downgraded base64 blobs**                                 | Base64 runs that look like JWT header+payload segments                                                       |
| **HTML entities, unicode escapes, combining marks, homoglyphs** | Decoded/revealed via normalization pipeline                                                                  |

Severity reflects _how likely a pattern is to be an attack vs. a legitimate feature_. Bidi overrides and the Tags block are essentially never innocent in web copy; zero-width joiners are legitimate in Arabic/Indic scripts and emoji, so they score low. The instruction-phrase detector and all deobfuscation passes are informational only: they false-positive on any page _about_ prompt injection (including the OWASP page and this README).

## Scope

OWASP's LLM01 prevention strategies target the **LLM application developer**: constrain model behavior, validate outputs, enforce least privilege, keep a human in the loop. A browser extension on the page can't do any of those. What it _can_ do maps to one-and-a-half of them:

- **#6 Segregate and identify external content**: surface hidden content so a human notices it before feeding the page to an assistant.
- A client-side sliver of **#3 Input filtering**: flag known obfuscation vectors.

So the honest scope is: **reveal what an AI would ingest but you can't see.** Detection is not interception. This tool only helps when a human is watching. It runs on click, so it never sits inside an agent's own browsing loop. What it flags spans both categories: HIGH-severity patterns (control tokens, bidi overrides, invisible chars) are jailbreak or smuggling artifacts; LOW-severity patterns (instruction phrases) signal an injection attempt on the page.

For unattended agents, the defense has to live in the agent. [Claude for Chrome](https://www.anthropic.com/research/prompt-injection-defenses) classifies prompt injection across text and deceptive UI; its [guidance](https://support.claude.com/en/articles/12902428-use-claude-in-chrome-safely) layers permission prompts with minimal site access. None of it is bulletproof — ShadowPrompt sidestepped those defenses via a browser-extension messaging bug before Anthropic patched it. No vendor claims prompt injection is solved.

**Treat Lemon Juice as a supplement for when you're reading, not a safety net for when you're not reading.**

## Install

**From source (temporary add-on):**

1. Clone this repo.
2. Open `about:debugging#/runtime/this-firefox` in Firefox.
3. **Load Temporary Add-on…** and pick `manifest.json`.
4. Click the Lemon Juice icon in the toolbar on any page.

> [!NOTE]
> Temporary add-ons are removed when Firefox restarts. Reload from `about:debugging` to bring it back during development.

**AMO listing:** coming once v0.1 is published.

## Develop

```sh
pnpm install
pnpm test        # unit tests (detectors.js, scan-helpers.js — pure, DOM-free)
pnpm test:e2e    # Playwright tests against real fixtures (browser)
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

| File                      | Role                                                                                                                                                                                                                                                       |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `detectors.js`            | **Pure** detection logic. String in, findings out. No DOM. Exposed as `globalThis.PIScanner` (injection) and `module.exports` (tests). The testable core.                                                                                                  |
| `scan-helpers.js`         | DOM helpers for scanning and overlay rendering. Dual-export pattern. `resolveBackgroundColor` returns `null` when nothing paints a real background (no guessing the system canvas color), preventing text-color false positives on self-themed dark pages. |
| `scan.js`                 | DOM side: walks text and comment nodes across the top document, every open shadow root, and every same-origin iframe document. Runs detectors, applies CSS-hidden-text heuristics, draws hit markers into a non-invasive overlay.                          |
| `popup.js` / `popup.html` | Injects the scripts into the active tab, reads back results, renders findings, sets the toolbar badge.                                                                                                                                                     |
| `manifest.json`           | MV3. `activeTab` + `scripting`, no host permissions needed.                                                                                                                                                                                                |

> [!IMPORTANT]
> Injection order matters: `detectors.js` > `scan-helpers.js` > `scan.js`. Each file reads `globalThis` at the top of its IIFE.

## Privacy

- **Nothing leaves your browser.** No network calls, telemetry, or analytics.
- **No host permissions.** `activeTab` grants page access only when you click the icon.
- All decoding and scanning happens locally in the content-script sandbox.

## Limitations

> [!WARNING]
> Highlighted **≠** malicious. This tool flags things for a human to judge. It produces both false negatives and false positives.

### Known misses

These are detectable in principle, just not implemented (or only partially implemented) today:

- **Payload splitting**: instructions across multiple DOM nodes (OWASP #6).
- **Adversarial suffixes**: high-entropy gibberish triggers (OWASP #8).
- **Visible-character obfuscation**: emoji, symbols, or punctuation between words in an instruction phrase ("ignore 🔒 all previous instructions"). Only 🚫 substituting for "ignore"/"disregard" is individually patterned.
- **Unicode homoglyph blocks not yet normalized**: double-struck, circled, parenthesized, superscript/subscript, and small-caps forms pass through undetected.
- **Emoji-only instructions**: pictograph sequences conveying a message visually.
- **Compound obfuscation**: multiple obfuscation layers applied together.
- **Cross-origin iframes**: blocked by same-origin policy. Reachable in principle via `scripting.executeScript({ allFrames: true })`, but per-frame result aggregation isn't implemented yet.

### Out of scope by design

These attack vectors are unreachable by a static DOM text scanner. They require runtime monitoring, image processing, or conversation state:

- **Multimodal / image-based payloads** (OWASP #7): text-only scanner; images are never inspected.
- **Server-side, URL-fragment, and dynamically-fetched content**: not in the rendered DOM at scan time.
- **Closed shadow roots**: unreachable by spec. The Shadow DOM API deliberately hides them.
- **Data exfiltration**: sending stolen content to a remote server. Requires network-level or output-level monitoring. This extension makes zero network calls and never reads model output.
- **Multi-turn attacks**: building up malicious context across multiple user/assistant exchanges. Requires conversation state tracking across turns. This extension scans a single page snapshot on click.
- **Few-shot poisoning structure**: inserting fake `user:`/`assistant:` example pairs to bias output. The role-prefix heuristic catches individual `human:`/`ai:` lines, but detecting the structure of an embedded conversation is beyond regex scope.

### Known false positives

Legitimate zero-width joiners in Arabic/Indic scripts, SEO keyword stuffing with invisible characters between every letter, and any article discussing prompt injection (including this README). `.sr-only`/`aria-hidden` accessibility text is still flagged (same CSS techniques as real hidden payloads) but downgraded to LOW/informational rather than suppressed. Full suppression would be a detection-evasion shortcut.

## Roadmap

- [x] Full detector matrix in `__tests__/detectors.test.js`
- [x] Recursive open shadow root and same-origin iframe scanning
- [ ] Cross-origin iframes via `scripting.executeScript({ allFrames: true })` with per-frame result aggregation
- [ ] Opt-in auto-scan on user-configured domains (per-site host permissions, kept off by default)
- [ ] Chrome port

## Credits

- Attack taxonomy from [OWASP LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).
- Prior art: **Stegano** (invisible-Unicode classifier) and **ZeroWidth-Detection-Firefox** by mikkel1156.
