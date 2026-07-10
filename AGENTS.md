# AGENTS.md

This file provides guidance to AI coding agents (Claude Code, etc.) when working with code in this repository.

## What this is

Lemon Juice is a Firefox MV3 extension that scans the active tab for hidden
text and prompt-injection payloads (invisible Unicode, ASCII smuggling via the
Unicode Tags block, bidi-control "Trojan Source" tricks, visually-hidden CSS
text, suspicious base64 blobs, and instruction-like phrases). It's a detection
aid only — it highlights findings for a human to judge, it does not block or
sanitize anything, and it makes no network calls.

Buildless: plain ES, no bundler, no transpile step, no framework. The source
files are loaded directly by the browser as content scripts.

## Commands

```sh
pnpm install
pnpm test       # node --test — runs __tests__/*.test.js (pure, DOM-free)
pnpm test:e2e   # playwright test — runs __tests__/e2e/*.spec.js (browser, fixtures)
pnpm lint       # eslint . && prettier --check .
pnpm format     # prettier --write .
```

Playwright tests require the Firefox browser binary. `pnpm install` downloads it
automatically via `postinstall`. Manual: `pnpm exec playwright install firefox`.

`detectors.js` and `scan-helpers.js` are under test via `node --test`; they're plain CommonJS
(`module.exports`) with no DOM dependency, so they run directly under Node's
built-in test runner (`node:test` + `node:assert/strict`), no test framework
dependency needed. Add cases to `__tests__/detectors.test.js` when adding a
detector. `eslint.config.js` is a flat config with hand-declared globals
(no `globals` package): browser/WebExtension globals for `detectors.js`
(shared with Node globals since it's dual-loaded), `scan-helpers.js`,
`scan.js`, and `popup.js`; plain Node globals for `__tests__/` and `scripts/`.

The toolbar icons (`icons/icon-48.png`, `icons/icon-128.png`) are generated,
not hand-drawn — `scripts/generate-icons.js` builds a flat-color lemon PNG
directly from pixel data via `zlib.deflateSync`/`zlib.crc32` (no image-editing
dependency). Re-run `node scripts/generate-icons.js` after touching the
colors/size logic in that file; the PNGs are committed since there's no build
step to regenerate them at install/load time.

## Loading and testing the extension manually

There's no build step. To try changes in Firefox:

1. Open `about:debugging#/runtime/this-firefox`.
2. **Load Temporary Add-on…** and select `manifest.json`.
3. Open any page and click the toolbar icon to run a scan; use **Re-scan
   page** in the popup after editing `detectors.js`/`scan-helpers.js`/`scan.js` (requires
   reloading the temporary add-on from `about:debugging` first, since content
   script files are cached at injection time).

Temporary add-ons are removed on Firefox restart.

## Architecture

Five files, strict separation between pure logic and DOM:

- **`detectors.js`** — Pure detection logic, deliberately free of any
  `document`/`window` access. Takes a string, returns findings. Exposes
  `globalThis.PIScanner` (for content-script injection) _and_
  `module.exports` (so it's Node-testable without a DOM harness). Contains
  nine scan functions aggregated by `scanText()`: `scanInvisible`
  (invisible/control code points + the Tags-block ASCII smuggling
  reassembly), `scanEncoded` (base64 runs that decode to readable text),
  `scanPercentEncoded` (`%XX` escape runs), `scanHexEscape` (`\xXX` escape
  runs), `scanSpacedHex` (bare hex byte pairs separated by whitespace, no
  `\x` prefix — same decode-then-verify-printability gate as the other
  encoded-blob detectors), `scanControlTokens` (LLM chat-template turn
  markers like `<|im_start|>`/`<|im_end|>`, `[INST]`/`[/INST]`, `</system>` —
  HIGH severity, essentially never legitimate in web copy, unlike the LOW
  informational `system:`/`assistant:` instruction phrases below),
  `scanInstructions` (informational-only instruction-phrase matches
  that never raise overall severity alone), `scanVariationSelectors`
  (bytes hidden in a run of Unicode variation selectors after a base
  character), and `scanSneakyBits` (bytes hidden as a run of invisible-times/
  invisible-plus math operators), plus `worstSeverity()` for aggregating.

  A separate normalization layer feeds re-scans back into `scanInstructions`
  (and, for `stripInvisibleChars`, the encoded-blob scans too) rather than
  being its own top-level detector: `stripInvisibleChars` removes
  invisible/tag characters and re-runs the encoded + instruction scans over
  the stripped text; `normalizeDeobfuscated` runs a single per-character pass
  converting fancy Unicode letters to ASCII (`unicodeLetterToAscii`), then
  leetspeak (the `LEET` map), then stripping obfuscation delimiters
  (`| _ \` ^ ~`), before re-running the instruction scan; and
`SPACED_INSTRUCTION_PATTERNS` is a separate regex pass over the raw text
for space-delimited letters (`i g n o r e ...`). If you're adding a new way
to *disguise* letters or words (not a new hiding *mechanism*), it likely
belongs in this normalization layer rather than as a new `scanX` function.
  See "Adding a new detector" below.

- **`scan-helpers.js`** — Pure-ish DOM helper functions shared between the
  scanner and tests. Dual-export (global + CJS) matching the `detectors.js`
  pattern. Contains `elementHidesText`, `elementIsA11yHidden`,
  `isTransparentBg`, `resolveBackgroundColor`, `luminance`, `colorFor`,
  `snippet`, `directText`, `highlightElement`, `clearMarks`, and two
  traversal helpers: `collectRoots(root)` recursively gathers every
  `Document`/`ShadowRoot` reachable from `root` — open shadow roots
  (`element.shadowRoot`) and same-origin iframe documents
  (`iframe.contentDocument`), nested arbitrarily deep — and
  `deepQuerySelector(root, selector)` (built on `collectRoots`) finds an
  element by selector across all of them. `resolveBackgroundColor` walks
  the ancestor chain (through shadow-host boundaries) for a non-transparent
  background; if everything is transparent it probes the system `Canvas`
  color via an off-screen element (respects OS dark mode). All style
  resolution uses `el.ownerDocument.defaultView.getComputedStyle(el)` rather
  than the module-level `document`, since `el` may belong to an iframe's
  document. Closed shadow roots and cross-origin iframes are
  unreachable by design (spec / same-origin policy respectively) —
  `collectRoots` silently skips them rather than throwing.
- **`scan.js`** — The DOM side. Calls `collectRoots(document)` once per scan
  and runs both passes over every collected root (top document, each open
  shadow root, each same-origin iframe document): Pass 1 walks text **and
  comment** nodes (`NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT` — a
  `Comment` node's `.nodeValue`/`.parentElement` shape matches `Text`
  exactly, so no branching needed; findings get an `inComment: true` flag
  the popup surfaces, since a `<!-- ... -->` never renders but an LLM
  ingesting the page's raw HTML/DOM still sees it) with a `TreeWalker`, runs
  `PIScanner.scanText` on each; Pass 2 uses
  `elementHidesText` (from helpers) for CSS-hidden-text detection (tiny font
  size, `opacity:0`, off-screen absolute positioning, negative text-indent,
  text color equal to background — _not_ plain `display:none`, which is too
  common to be signal). Highlights hits with an outline + `data-piscan-mark`
  attribute, and stashes a serializable summary on `window.__PIScanResult`.
  `data-piscan-id` values are unique across the whole page (one counter
  shared across all roots), which lets `popup.js`'s `scrollTo` re-locate an
  element by id later via `deepQuerySelector`.
- **`popup.js` / `popup.html`** — On popup open, injects `detectors.js` then
  `scan-helpers.js` then `scan.js` into the active tab via
  `browser.scripting.executeScript`, reads back `window.__PIScanResult` with
  a follow-up call, renders findings grouped/colored by severity, and sets
  the toolbar badge count/color.

**Injection order is load-bearing:** `detectors.js` must be injected before
`scan-helpers.js` before `scan.js` (see the `files: [...]` array in `popup.js`)
because `scan.js` reads `globalThis.PIScanner` and `globalThis.__PIScannerHelpers`
at the top of its IIFE.

**Permissions model:** only `activeTab` + `scripting` — no host permissions.
Scanning only ever happens on the tab active when the user clicks the
toolbar icon, and only for that one interaction. This same-origin-only
posture is also why iframe traversal stops at `contentDocument` access
(reachable without new permissions) rather than injecting into every frame
via `scripting.executeScript({ allFrames: true })`, which would reach
cross-origin iframes too but needs per-frame result aggregation in
`popup.js` — not implemented; see the shadow-DOM/iframe limitations in
README.md.

## Adding a new detector

New detection logic belongs in `detectors.js` as a pure function operating on
a string, added to the aggregate list in `scanText()`, and returning findings
shaped like the existing ones (`type`, `severity`, `index`, plus whatever
type-specific fields the popup's `render()` in `popup.js` needs to label
them). Any new `item.type` also needs a case added to the label switch in
`popup.js`'s `render()` function, or it'll fall through to the raw `type`
string.

That's the right shape for a new hiding _mechanism_ (a new kind of invisible
character, encoding scheme, etc.). If instead you're adding a new way to
_disguise_ letters or words in already-visible text, extend the
normalization layer in the `detectors.js` bullet above (`unicodeLetterToAscii`'s
range table, the `LEET` map, or the delimiter-strip charset in
`normalizeDeobfuscated`) so it feeds the existing `scanInstructions` re-scan,
rather than writing a parallel `scanX` function that reimplements its own
normalization.

Severity should reflect "how likely is this to be an attack vs. a legitimate
page feature" (see the comments at the top of `detectors.js` for the
reasoning already applied to bidi controls vs. ZWJ/ZWNJ, for example) —
don't default new patterns to `HIGH` without that justification, and keep
instruction-phrase-style heuristics informational (`LOW`, non-convicting) if
they're prone to false-positiving on legitimate pages that merely discuss the
topic.

## Before cutting a release

- Run `pnpm lint && pnpm test && pnpm test:e2e` on a clean tree, then
  `pnpm run package` and load the resulting zip as a temporary add-on.
- If you touched `scripts/release.js` or `.github/workflows/release.yml`,
  dry-run them instead of trusting them on the first real tag push.
- Before adding a new piece of automation, check what's already configured.
