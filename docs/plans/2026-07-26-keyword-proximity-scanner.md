# Rephrased-Override Instruction Pattern

**Status:** Implemented (redesigned). The original keyword-proximity scanner was
rejected on review; a single tight `INSTRUCTION_PATTERNS` regex ships instead.

## Goal

Catch rephrased overrides the exact-phrase `INSTRUCTION_PATTERNS` miss —
`skip all prior directions`, `forget your earlier training`,
`override your default safety rules` — without regressing the project's anti-FP
posture.

## Why the keyword-proximity approach was rejected

The first draft proposed a `scanInstructionKeywords` detector: four keyword
groups, fire when any two words from different groups fall within 80 characters.
Empirically it was a false-positive generator, because two of the groups are
everyday English (`your`, `all`, `show`, `tell`, `send`):

- **13/15 FP** on ordinary web copy — `"Your safety is our top priority"`,
  `"Show all results"`, `"Send your resume"`, `"Your training starts Monday"`.
- The draft's own "silent on benign prose" test listed
  `"Please disregard my previous email."` and asserted `[]`, but
  `disregard` + `previous` are 13 chars apart ⇒ it would have **failed**.
- A narrowed verb+noun proximity variant still FP'd **7/10** on manuals / safety
  pages / forms (`"Skip the safety briefing"`,
  `"Replace … per the instructions"`).

This is the paraphrase problem the treadmill audit
(`docs/plans/2026-07-25-treadmill-audit.md`) named **not source-fixable** —
distinguishing an attack on the assistant's instructions from a legit imperative
needs meaning, not word co-occurrence, which requires embeddings/LLM (forbidden
by the buildless / no-deps / no-network constraints).

## What shipped

One pattern appended to `INSTRUCTION_PATTERNS` (`detectors.js`), LOW
`instruction-phrase`, riding the existing raw + deobfuscated passes, dedup, and
popup label — no new type, no `scanText`/`popup.js`/export changes:

```js
/\b(?:skip|bypass|discard|forget|ignore|disregard|override)\s+(?:all\s+)?(?:the\s+)?(?:your\s+)?(?:previous|prior|earlier|above|current|default|initial|original)\s+(?:\w+\s+){0,2}?(?:instructions?|directions?|context|guidelines?|rules?|training|restrictions?|constraints?|safety)\b/i;
```

The discriminator is the `previous|prior|earlier|current|default|…` modifier
before the instruction-noun: it targets the assistant's own _prior state_.
Benign imperatives lack it (`"skip the safety briefing"` has no prior-state
modifier before the noun), so they stay clean.

**Verified: 6/6 intended positives, 0 FP** on the hard benign set (manuals,
safety pages, forms, `"Please disregard my previous email."`,
`"Your safety is our top priority."`).

Tests: `__tests__/detectors.test.js` — a positive case and a benign-guard case
next to the other `scanInstructions` corpus tests.

## Verification

```sh
pnpm lint && pnpm test
```
