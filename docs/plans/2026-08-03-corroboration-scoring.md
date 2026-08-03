# Corroboration-Based Scoring

**Status:** Implemented (2026-08-03). Merged to `main` at `b6eb2de`; `pnpm lint`,
`pnpm test` (225), `pnpm test:e2e` (87) and the out-of-scope suite (21) all
green. Manual `about:debugging` load still unverified.

## Goal

Make severity reflect accumulated evidence rather than the single worst
mechanism, and lead the popup with a named page verdict instead of a raw count.

## Why not a 0–100 score

The prompt was an access-score model of the ExtensionChecker kind — a 0–100
number in four tiers. Rejected, and the reasoning is worth keeping because it
will be proposed again:

A numeric score works for a scanner reading a **closed, enumerable** input such
as a manifest permission list, where the denominator is real and you can
partition 100 points across known surfaces. A web page's finding space is
unbounded — there is no "out of what" — so the number would be invented
precision. That model also carries a second axis (store rating, install count)
to moderate the composite with; nothing equivalent exists here. And the tool is
positioned as a detection aid for a human to judge, which a composite number
actively undermines.

What _did_ transfer is the idea that each finding is **additive evidence on top
of the signal for the same capability**. That is the whole of this change.

## The defect

`worstSeverity()` was a pure max, so nothing but the single worst mechanism
influenced the result. Two consequences:

- **Corroboration was computed and thrown away.** `scanEncoded` stored the
  decoded blob and `scanInvisible` reassembled the smuggled Tags-block payload
  into `decoded`, but nothing ever scanned that text — its only consumer was a
  popup label string. A Unicode-Tags run decoding to _"ignore all previous
  instructions"_ scored identically to a stray bidi control in Arabic text.
- **Placement was display-only.** `inComment` and `attrName` were rendered as
  label suffixes, never scored, despite "invisible to a human, visible to an
  LLM" being the tool's entire thesis.

## What shipped

Four pure layers in `detectors.js`, called from `scan.js`, rendered by
`popup.js`.

**1. Payload re-scan** — `scanDecodedPayloads` runs the five content scanners
over every finding's `decoded` payload and attaches hits as `corroboration`
(`{type, severity, match}`). Depth-1: content scanners run, encoded-blob
scanners do not, so a payload nested in a payload is never decoded again. The
guarantee is structural — inner findings never enter the findings array and the
projection keeps only three fields. Results attach to the parent rather than
being emitted top-level, or they would double-count in `bySeverity` and inflate
the badge.

This required storing `decoded` at full length (`MAX_DECODED = 4096`) instead of
truncating to 120 chars at capture; truncation moved to display time via
`preview()` in `popup.js`. At the `MAX_ITEMS = 200` cap that puts the worst-case
scan result near 800 KB, structured-cloned onto `window.__PIScanResult` and read
back by the popup — bounded, but not free.

Including `scanContextSwitch` in the inner scanners creates a **self-corroboration
path**: a decoded payload containing a fabricated multi-turn transcript (two role
turns plus a compliance flip) corroborates its own parent. Deliberate — an
encoded transcript is exactly what this tool exists to catch — but it is a second
promotion route beyond the instruction-phrase one, and easy to forget.

**2. Severity promotion** — `promoteSeverity` weights each corroborator by **its
own severity**, not merely its type (`corroborationRank`): HIGH convicts
(→ HIGH), MEDIUM supports (one step via `NEXT_SEVERITY`), LOW is informational.
`likelyJwt`/`likelyA11y` get no exemption — those dampeners exist to suppress
_uncorroborated_ noise, and a JWT-shaped decoy carrying real instructions is
exactly the case `scanEncoded`'s comment anticipates.

**3. Contextual promotion** — `applyContextualPromotion`, pure but operating on
`scan.js`'s deduped array. Three signals, each one step:

- **A, self-concealment:** a content finding with `normalized: true` — it only
  became readable after stripping invisibles or undoing leetspeak/homoglyphs.
  Fires independently; a fancy-Unicode or double-struck disguise lives in
  _visible_ characters and emits no concealment finding at all.
- **B, hidden placement:** content sharing an element with a
  **non-`likelyA11y`** `css-hidden` finding. Both promote.
- **C, concealed placement:** `inComment` / `attrName`.

**4. Page verdict** — `pageVerdict` returns `clean` / `noise` / `suspicious` /
`likely-injection`. An uncorroborated MEDIUM stays `noise` on purpose: a lone
zero-width space is the largest false-positive source in the wild and used to
light the badge amber for no reason.

Also expanded `A11Y_HIDDEN_CLASSES` in `scan-helpers.js` (`visuallyhidden`,
`element-invisible`, `a11y-hidden`, `assistive-text`, `hidden-visually`) — the
list was missing the common framework names, so the dampener never fired on real
sites.

Commits: `7bfdc70` `46de7dd` `a50b21e` `0e23f9f` `2534b90` `4e1ee6f` `6c418d6`
`613f1a0` `1892fff`.

## What review caught — read this before adding a promotion rule

Every task shipped a defect that a review gate caught, and four of five were
errors in the **plan**, not the implementation. Two were false-positive designs
that looked obviously correct:

- **Any `code-execution` hit treated as convicting.** `scanCodeExecution` emits
  at three severities and its LOW tier (bare `eval(`/`exec(`/`subprocess.run(`)
  is explicitly informational — those are everywhere in legitimate code
  documentation. Matching on type alone made a base64'd code sample or sourcemap
  chunk score HIGH while the identical text un-encoded scored LOW. Fixed by
  `corroborationRank`.
- **Same-element co-location.** `targetId` is `node.parentElement`, so two
  findings 1800 characters apart in one `<pre>` "corroborated". Two verified
  false positives reached HIGH: an accessible chat transcript
  (`<span class="element-invisible">Assistant:</span>`, the standard accessible
  message list) and a docs page showing a prompt format beside one stray CMS
  soft-wrap character. Fixed by requiring proven concealment _of the content_.

Also caught: `preview()` threw a `TypeError` on page-controlled input outside the
popup's only try/catch; and `scanInvisible` stores `decoded` **uncapped**, so
feeding it to a backtracking regex took `scanText` from 73 ms to 2133 ms on an
attacker-controlled page — quadratic, so ~500 KB of tag chars would freeze for
30s+. Clamped at the consumer so no future producer can reintroduce it.

**Lesson:** prove a new promotion rule against a false positive, not just a true
one. `__tests__/e2e/corpus.spec.js`'s `MUST_STAY_QUIET` exists for this.

## Decisions that should not be silently re-litigated

**Signal A promotes the content, not the mechanism.** When a `normalized` phrase
sits on an element that also has an invisible-char finding, only the phrase is
promoted. The counter-argument is real — a zero-width space that split "ignore
previous instructions" is the weapon, not typography. Rejected because promoting
every invisible on the element re-opens the co-residency risk this rule closed.
Revisiting it needs its own FP fixture first.

**The encoded-showcase false positive is accepted, not suppressed.** A page
teaching prompt injection by showing an encoded payload reaches
`likely-injection` (its decoded payload carries a control token → convicting →
HIGH → corroborated HIGH). An LLM ingesting the page sees the same bytes whether
the author meant to demonstrate or attack; "showcase vs. carry" is not
mechanically decidable. Pinned by a test whose comment says a dropped verdict
means someone added intent-guessing.

## Fixtures

Six added under `__tests__/fixtures/`: `corroborated-payload.html` (true
positive), `encoded-showcase.html` (accepted-FP pin), `lone-zero-width.html`
(noise positive control), and three regression gates — `accessible-chat.html`,
`docs-prompt-format.html`, `discussion-with-stray-invisible.html`.

Three pre-existing e2e expectations moved, all attack fixtures that conceal
their payload: `refusal-flip-comment.html` (Signal C),
`fancy-unicode-role-labels.html` and `compound-obfuscation.html` (Signal A). The
vector loop's flat `severity === "low"` assertion was replaced with a
**stricter** one — any climb above LOW must carry a recorded reason and a
`promotedFrom`, so an unexplained promotion still fails.

## Verification

```sh
pnpm lint && pnpm test && pnpm test:e2e
pnpm exec playwright test --config __tests__/fixtures-out-of-scope/playwright.config.js
```

The out-of-scope suite has its own config and is **not** run by `pnpm test:e2e`
(the root `testMatch` excludes it). See
`__tests__/fixtures-out-of-scope/README.md`; that directory is gitignored.

Manual: load `manifest.json` via `about:debugging#/runtime/this-firefox`, then
check `corroborated-payload.html` (red, `└` sub-lines), `lone-zero-width.html`
(blue, "Findings present, nothing corroborating" — the noise-reduction win, and
the change most likely to be wrong), and `accessible-chat.html` (quiet). Not
`invisible-chars.html`, which carries a bidi override and correctly reads
`suspicious`.
