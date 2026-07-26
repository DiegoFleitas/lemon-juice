# Treadmill Audit — Enumeration Lists Fixable at the Source

**Status:** Implemented. Prompted by the NFKC win
(styled-letter range table → `String.normalize("NFKC")`). Same question applied
across `detectors.js`: which hand-maintained enumerations are unbounded
treadmills with a principled/stdlib replacement?

Every claim below was verified by running the stdlib mechanism, not asserted from
memory.

## Fixable at source (ranked)

### 1. Invisible-char list → Unicode property net (strongest, lowest risk)

**Treadmill:** the `INVISIBLE` map hand-lists ~20 code points; any invisible not
on the list (or added in a future Unicode version) slips through — exactly the
NFKC shape.

**Verified:** `\p{Default_Ignorable_Code_Point}` matches every entry in the map
**and** the Unicode Tags block; `\p{Bidi_Control}` matches the bidi subset.

**Fix:** use the property regex as the detection _net_ in `scanInvisible`, and
keep the curated map as a **severity/name override table only** — ZWJ/ZWNJ stay
LOW (legit in emoji/Arabic), bidi controls stay HIGH — defaulting any
unlisted-but-ignorable char to MEDIUM + a generic name. Ordinary
letters/spaces/emoji are not `Default_Ignorable`, so the net is clean.

**Files:** `detectors.js` — `scanInvisible`, `INVISIBLE`.

### 2. Role-label list → structural role-turn detection (the one we keep feeding)

**Treadmill:** `ROLE_TURN_RE` was expanded twice (`agent|operator|customer|…`);
the README _still_ lists `Visitor:`/`Guide:`/`Interviewer:`/`Q:`/`A:` as misses.
Role labels are open-ended English — unbounded by construction.

**Fix:** stop enumerating labels; detect the _structure_. Match line-leading
`\p{Lu}\p{L}{1,20}:`, collect the distinct speaker tokens, require ≥2 distinct
plus the existing corroboration (refusal→acceptance flip or an instruction
phrase). A small denylist (`Note|Warning|Tip|Example|Step|Figure|Table|Chapter`)
bounds the obvious non-speaker prefixes.

**Risk:** more FP surface than a fixed list, but contextSwitch is already
corroboration-gated, so a bare `Foo:` line never convicts. Needs its own FP probe
against docs/tutorials.

**Files:** `detectors.js` — `ROLE_TURN_RE`, `scanContextSwitch`.

### 3. Homoglyph map → mixed-script detection (partial / complementary)

**Treadmill:** `HOMOGLYPH` maps 13 confusables out of thousands.

**Verified:** `pаypal` (Cyrillic `а`) trips `\p{Script=Latin}` +
`\p{Script=Cyrillic}` together; benign `paypal` is clean.

**Fix:** flag a token that mixes Latin with another script as a homoglyph
_signal_. **Caveat:** the map is used for _normalization_ (recover the Latin word,
then re-scan instructions), and recovering arbitrary confusables would need the
full Unicode confusables table — not hand-mappable. So mixed-script detection
**complements** the map (catches the general case as a signal) rather than
replacing it.

**Files:** `detectors.js` — normalization layer / a new signal.

## NOT source-fixable — name it, don't chase it

`INSTRUCTION_PATTERNS` (the jailbreak-phrase list) is the largest enumeration, but
its treadmill is **paraphrase**, which requires semantic / embedding / LLM
matching — forbidden by the buildless, no-deps, no-network constraints. It is
correctly scoped LOW/informational and accepted-incomplete. Trying to "fix it at
source" is a category error.

## Not worth it (finite / bounded / deliberate)

`LEET` (finite alphabet), `CONTROL_TOKENS` (few model families),
`TYPOGLYCEMIA_WORDS`, the CSS-hiding checks in `scan-helpers.js` (bounded by CSS
features), the delimiter-strip set (generalizing it over-strips real punctuation
— the restraint is deliberate), and the encoded-blob scanners (each needs custom
decode logic; common encodings are finite).

## Recommendation

Implement **#1 first** — cleanest, lowest risk, highest coverage gain — then
**#2** to kill the role-label treadmill we keep feeding. **#3** is optional and
complementary. Each is an independent change, stays LOW/advisory, and needs its
own FP probe plus green `pnpm lint && pnpm test && pnpm test:e2e`.
