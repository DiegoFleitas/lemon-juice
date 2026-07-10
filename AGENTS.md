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
  `globalThis.PIScanner` via `detectors.js:797`. Contains nine scan
  functions aggregated by `scanText()` (see `detectors.js:677`): invisible
  characters/control codes + Unicode-Tags ASCII smuggling reassembly,
  base64 runs, percent-encoded runs, hex-escape runs, space-delimited hex
  byte pairs, LLM control tokens (`<|im_start|>`, `[INST]`, `</system>` —
  HIGH severity), instruction phrases (`system:`, `assistant:` — LOW
  informational), variation-selector smuggling, and invisible-times/
  invisible-plus math-operator smuggling, plus `worstSeverity()` for
  aggregating (`detectors.js:770`).

  A separate normalization layer at `detectors.js:571`/
  `detectors.js:634`/`detectors.js:364` strips invisible tag characters
  and normalizes obfuscated text (fancy Unicode → ASCII, leetspeak,
  delimiter stripping, space-delimited-letter patterns) before
  re-running the instruction and encoded-blob scans. If you're adding
  a new way to _disguise_ letters or words (not a new hiding
  _mechanism_), it likely belongs in this normalization layer rather
  than as a new `scanX` function. See "Adding a new detector" below.

- **`scan-helpers.js`** — Pure-ish DOM helper functions shared between the
  scanner and tests. Dual-export (global + CJS) matching the `detectors.js`
  pattern. Contains `elementHidesText`, `elementIsA11yHidden`,
  `isTransparentBg`, `resolveBackgroundColor`, `luminance`,
  `collectRoots`, `deepQuerySelector`, and others (see the full export list
  at `scan-helpers.js:192`). `resolveBackgroundColor` walks the ancestor
  chain (through shadow-host boundaries) for a non-transparent background,
  falling back to `<body>`/`<html>`, and returns `null` when nothing paints a
  real background. It deliberately does **not** guess the system `Canvas`
  color in that case: `Canvas` reflects the _browser_ theme, not what the page
  actually paints, so a page that self-themes dark (Notion, etc.) viewed in a
  light-mode browser would report a white canvas behind its own white text and
  trip a false `"text color = background"` match. `elementHidesText` therefore
  runs the color-equality reason **only against a real resolved background**
  (`null` ⇒ skip it); the other reasons (tiny font, `opacity:0`, off-screen,
  negative text-indent) are unaffected. All style resolution uses
  `el.ownerDocument.defaultView.getComputedStyle(el)` rather than the
  module-level `document`, since `el` may belong to an iframe's document.
  Closed shadow roots and cross-origin iframes are unreachable by design
  (spec / same-origin policy respectively) — `collectRoots` silently skips
  them rather than throwing.
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
  text color equal to a **real** background — _not_ plain `display:none`, which
  is too common to be signal). Markers are **non-invasive**: nothing is
  injected into page elements and no page style is overwritten. Each finding
  element only gets invisible `data-piscan-mark`/`data-piscan-id` attributes;
  the visible candle glyph + numbered badges + a severity-colored outline box
  are drawn into a single per-Document overlay layer (`.piscan-overlay`,
  `position:absolute`, `pointer-events:none`), positioned over the element via
  `getBoundingClientRect()` + scroll offset (`scan-helpers.js` `drawMarker`).
  One box per element, one badge per finding, colored by the element's worst
  severity. Shadow-DOM elements share their host document's coordinate space,
  so their markers live in the host document's overlay; same-origin iframe
  elements get an overlay inside the iframe document. `clearMarks` tears the
  overlay(s) down (and restores any reveal overrides) at the start of every
  scan, so markers never accumulate and the overlay is never itself re-scanned.
  `makeHighlightVisible` still reveals genuinely-hidden text (bumping tiny
  fonts, `opacity:0→0.5`, off-screen→static, resetting text-indent — recorded
  in `data-piscan-saved`, undone by `clearMarks`) so the marker has a visible
  box to anchor to, but it **never** rewrites text color. A serializable
  summary is stashed on `window.__PIScanResult`. `data-piscan-id` values are
  unique across the whole page (one counter shared across all roots), which
  lets `popup.js`'s `scrollTo` re-locate an element by id later via
  `deepQuerySelector`, and links each overlay marker to its element via
  `data-piscan-for`.
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
range table at `detectors.js:386`, the `LEET` map at `detectors.js:48`, or the
delimiter-strip regex at `detectors.js:661`) so it feeds the existing
`scanInstructions` re-scan, rather than writing a parallel `scanX` function
that reimplements its own normalization.

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
