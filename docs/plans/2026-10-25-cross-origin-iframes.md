# Cross-Origin Iframe Scanning Plan

**Status:** Implemented (2026-10-26). Per-frame scanning, popup aggregation,
frame-qualified target ids, the Chrome/refusal fallback, a verdict-parity pin and
a two-origin e2e are all in place and green on Firefox and Chromium. The one
open item is the first task below: confirming on a real temporary add-on that a
Firefox `activeTab` injection actually reaches a cross-origin frame, which no
CI browser can prove. Tracked as issue #17.

**Goal:** scan cross-origin iframe documents on Firefox using only `activeTab` +
`scripting`, so a payload inside an embedded third-party frame is no longer
invisible. Chrome keeps today's behaviour: `activeTab` grants only the top
frame's origin there, and this project will not add host permissions.

## Constraints

- Permissions stay `activeTab` + `scripting`. No host permissions, no network.
- Firefox: with `activeTab`, `scripting.executeScript({ allFrames: true })` is
  meant to reach frames that were part of the original page (bug 1653408
  semantics). This must be verified on the current ESR before implementation.
- Chrome: `activeTab` covers the main frame's origin, so cross-origin frames are
  refused; same-origin frames are still reachable. The feature must degrade
  without surfacing an error.
- Scanning is still a snapshot taken on click; iframes that load later are not
  rescanned (existing limitation, unchanged).

## Design

1. **Per-frame flag.** Before injecting the scanner, the popup runs a small
   `executeScript` with `allFrames: true` that sets
   `window.__PISCAN_PER_FRAME__ = true` in every reachable frame.
2. **Per-frame scan.** The popup injects `detectors.js` > `scan-helpers.js` >
   `scan.js` with `allFrames: true`, as today but across frames. In per-frame
   mode `scan.js` calls `collectRoots(document, { skipIframes: true })`: each
   frame scans only its own document, so same-origin frames are no longer
   traversed twice (once from the top document, once on their own).
   `scan-helpers.collectRoots` gains the option; the default stays recursive.
3. **Per-frame output.** Each frame keeps its own `window.__PIScanResult` and
   draws its own overlay. Markers are already per-Document, so geometry does not
   change.
4. **Aggregation.** The popup reads every frame back with a single
   `executeScript({ allFrames: true, func })`; the result array carries
   `frameId` per entry. A new pure `mergeFrameResults(results)` in `popup.js`
   concatenates items (each tagged with its `frameId`), re-sorts by severity,
   re-indexes, caps at `MAX_ITEMS` (200), and recomputes `bySeverity`,
   `corroborationCount` and the page verdict from the merged totals.
5. **Verdict parity.** `pageVerdict`/`corroborationCount` live in `detectors.js`
   and cannot be imported into the popup page script. The merge reimplements the
   thresholds; a unit test pins parity against `PIScanner.pageVerdict` on the
   same inputs, so drift fails CI.
6. **Scrolling.** Findings gain `frameId` alongside `targetId`. `scrollTo` uses
   `executeScript({ target: { tabId, frameIds: [frameId] }, func })` to locate
   and scroll within the owning frame; frame 0 is the top document.
7. **Chrome degradation.** On Chrome, `allFrames` injection reaches the frames it
   is allowed to (top + same-origin) and silently skips the rest; if the browser
   rejects the whole call instead, the popup catches it and falls back to the
   current single-frame path. Either way the user sees no error.

## Tasks

- [ ] Manual Firefox verification: temporary add-on + page embedding a
      cross-origin iframe with a hidden payload; record the allFrames result.
      **Still outstanding** — CI has no extension host, so the `activeTab` frame
      reach below is not yet proven on a real install.
- [x] `collectRoots(root, { skipIframes })` + unit tests for both modes.
- [x] `scan.js` per-frame mode (flag, skipIframes, no iframe overlays from top).
- [x] Popup: flag injection, allFrames file injection, per-frame read-back.
- [x] `mergeFrameResults` + unit tests (indices, cap, severity order, verdict
      parity, frameId tagging).
- [x] Frame-aware `scrollTo` and cycle handling for folded rows across frames.
- [x] Chrome behaviour check + fallback path. (Fallback implemented and exercised
      through Chromium; the real-Chrome check folds into the manual run above.)
- [x] e2e: two-origin fixture (two local HTTP origins) asserting the
      cross-origin payload is found once, and same-origin frames are not
      double-scanned.
- [x] Docs: `docs/limitations.md` (Firefox scans, Chrome still top-origin only),
      README limitation bullet, roadmap tick.

## Acceptance

As in issue #17: cross-origin finding surfaced and highlighted on Firefox, no
duplicate same-origin findings, no new permissions, Chrome degrades quietly, full
suite green, docs updated.

## Risks

- Firefox `activeTab` frame reach is load-bearing; if it does not hold on
  current ESR the feature needs host permissions, which is out of scope.
- Merging per-frame item lists reorders indices; the popup's cycling/`groupKey`
  logic assumes a single list, so folded rows need a frame-aware identity.
- More frames mean more DOM work per click; the 200-item cap and per-frame
  snapshot keep this bounded, but ad-heavy pages should be measured.
