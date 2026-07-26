# NFKC Normalization — Root-Cause Fix for Styled-Letter Dodges

**Status:** Implemented.

## Context — stop running in circles

The out-of-scope fixture corpus keeps producing "quick wins" of one shape: a new
Unicode styled-letter block dodges detection, so we add another range branch to
`unicodeLetterToAscii`. Fullwidth letters → fullwidth colon → double-struck →
circled → superscript → … is an **unbounded** list — Unicode has dozens of
compatibility-variant blocks. Each hand-rolled branch is code maintained forever,
and the next fixture always finds the block we haven't added.

**Root cause:** we reimplement Unicode compatibility decomposition by hand. The
platform already does it. `String.prototype.normalize("NFKC")` folds every
styled-letter block — and future ones — in one call. Verified:

| Vector                                       | NFKC output   |
| -------------------------------------------- | ------------- |
| `Ｕｓｅｒ：` (fullwidth letters **+ colon**) | `User:`       |
| double-struck `𝕚𝕘𝕟𝕠𝕣𝕖`                       | `ignore`      |
| math-bold `𝐢𝐠𝐧𝐨𝐫𝐞` / fraktur `𝔦𝔤𝔫𝔬𝔯𝔢`        | `ignore`      |
| circled `ⓘⓖⓝ` / superscript `ᴵᴳᴺ`            | `ign` / `IGN` |

NFKC correctly does **not** fold cross-script homoglyphs (Cyrillic `а`),
regional-indicator flags (`🇮`), or leetspeak (`1gn0r3`) — those keep their custom
maps. So NFKC replaces exactly the ~15 math/fullwidth branches and nothing else.

One change closes both current styled-letter fixtures
(`unicode-homoglyph-blocks`, `fancy-unicode-role-labels`) **and** the ones nobody
has filed yet, while deleting code instead of adding it.

## Blast radius

`unicodeLetterToAscii` is called in exactly one place — the `normalizeDeobfuscated`
loop (`detectors.js:851`) — plus its own direct unit tests (`detectors.test.js:585–629`)
and the `PIScanner` export. The loop already handles variable-length index
mapping via `indexMap.push(rawIdx + k)`, so length changes from NFKC
(astral 2-UTF16 → 1 ASCII; `⒤` → `(i)`) are already accommodated.

## Change

**File:** `detectors.js`, `normalizeDeobfuscated` loop (`~detectors.js:845`).

Replace the `unicodeLetterToAscii(cp)` letter step with a per-char NFKC step:

```js
// Compatibility-fold styled letters/punctuation via the platform (covers
// math-bold/italic/fraktur/script/sans/mono/fullwidth/double-struck/circled/
// superscript/… at once). Only accept an all-printable-ASCII folding so we
// never rewrite arbitrary scripts.
const nfkc = ch.normalize("NFKC");
if (nfkc !== ch && /^[\x20-\x7e]+$/.test(nfkc)) {
  out += nfkc;
  for (let k = 0; k < nfkc.length; k++) indexMap.push(rawIdx);
  rawIdx += ch.length;
  continue;
}
```

Keep unchanged: LEET map, HOMOGLYPH map, delimiter strip, typoglycemia, and the
**regional-indicator** branch (NFKC can't fold those). Reduce
`unicodeLetterToAscii` to the RIS branch only (rename → `regionalIndicatorToAscii`,
or leave the function with just that branch) and call it after the NFKC step.

Net: ~15 range branches deleted, ~5 lines added.

**Ordering note:** run NFKC before LEET so a fullwidth digit folds to its ASCII
digit rather than being leet-substituted — a negligible edge (both feed only the
LOW instruction/context-switch scans).

## Tests

- Convert the direct `unicodeLetterToAscii(0x1d41a)…` assertions
  (`detectors.test.js:585–620`) — they test an implementation detail being
  deleted — into **behavior** tests on `scanText`/`normalizeDeobfuscated`
  (math-bold, fraktur, fullwidth, double-struck, circled all reveal the phrase).
  Keep the RIS test (`:623`) against the retained branch.
- Add: fullwidth-colon dialogue fires `context-switch` (via the already-wired
  deobfuscation pass); double-struck instruction fires `instruction-phrase`.
- FP probe: benign fullwidth/circled decorative text (`①②③`, `ＦＲＥＥ`) does not
  manufacture instruction matches.

## Fixture reclassification

`unicode-homoglyph-blocks.html` and `fancy-unicode-role-labels.html` become
detected → move to tracked positives (a unit assertion and
`contextSwitch/positive/` respectively); remove the gitignored out-of-scope
copies.

## Verification

```sh
pnpm lint && pnpm test && pnpm test:e2e
```

Existing fancy-unicode tests must stay green (NFKC folds the same math-bold/
fullwidth blocks they already cover). No existing test should assert a styled
letter is left un-folded.

## Still out of scope after this (not styled-letter dodges)

- `compound-obfuscation` — _spaced_ double-struck; NFKC folds the letters but the
  spacing still defeats contiguous-word patterns (the spaced pass runs on raw
  text).
- `adversarial-suffixes` (disemvoweled + random, OWASP #8), `emoji-only`,
  `visible-char-obfuscation` (emoji separators — a separate, riskier call),
  `payload-splitting` / `cross-element-dialogue` (structural),
  `rephrased-*` / `single-node-dodge` / `undetected-compliance-flip` (unbounded
  paraphrase), `closed-shadow-root` / `cross-origin-iframe` / `dynamic-injection`
  (unreachable / timing).
