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

Four files, strict separation between pure logic and DOM:

- **`detectors.js`** — Pure detection logic, deliberately free of any
  `document`/`window` access. Takes a string, returns findings. Exposes
  `globalThis.PIScanner` (for content-script injection) _and_
  `module.exports` (so it's Node-testable without a DOM harness, once tests
  exist). Contains four detector families aggregated by `scanText()`:
  `scanInvisible` (invisible/control code points + the Tags-block ASCII
  smuggling reassembly), `scanEncoded` (base64 runs that decode to readable
  text), `scanInstructions` (informational-only instruction-phrase matches
  that never raise overall severity alone), plus `worstSeverity()` for
  aggregating.
- **`scan-helpers.js`** — Pure DOM helper functions shared between the
  scanner and tests. Dual-export (global + CJS) matching the `detectors.js`
  pattern. Contains `elementHidesText`, `sameColor`, `rgb`, `colorFor`,
  `snippet`, `directText`, `highlightElement`, and `clearMarks`.
- **`scan.js`** — The DOM side. Walks text nodes with a `TreeWalker`, runs
  `PIScanner.scanText` on each, uses `elementHidesText` (from helpers) for
  CSS-hidden-text detection (tiny font size, `opacity:0`, off-screen absolute
  positioning, negative text-indent, text color equal to background — _not_
  plain `display:none`, which is too common to be signal), highlights hits
  with an outline + `data-piscan-mark` attribute, and stashes a serializable
  summary on `window.__PIScanResult`.
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
toolbar icon, and only for that one interaction.

## Adding a new detector

New detection logic belongs in `detectors.js` as a pure function operating on
a string, added to the aggregate list in `scanText()`, and returning findings
shaped like the existing ones (`type`, `severity`, `index`, plus whatever
type-specific fields the popup's `render()` in `popup.js` needs to label
them). Any new `item.type` also needs a case added to the label switch in
`popup.js`'s `render()` function, or it'll fall through to the raw `type`
string.

Severity should reflect "how likely is this to be an attack vs. a legitimate
page feature" (see the comments at the top of `detectors.js` for the
reasoning already applied to bidi controls vs. ZWJ/ZWNJ, for example) —
don't default new patterns to `HIGH` without that justification, and keep
instruction-phrase-style heuristics informational (`LOW`, non-convicting) if
they're prone to false-positiving on legitimate pages that merely discuss the
topic.
