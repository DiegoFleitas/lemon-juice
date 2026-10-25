# Benchmark summary — 2026-10-25

Seed `42`, 84 attack cases, 26 benign pages.

## Detection by technique

`medium+` = a HIGH or MEDIUM finding (the mechanism was spotted).
`recovered` = the instruction itself was recognised (instruction-phrase,
control-token or context-switch). `verdict` = the page verdict reached
suspicious or likely-injection.

| Technique | n | any finding | medium+ | recovered | verdict |
|---|---|---|---|---|---|
| base64 | 6 | 100% | 100% | 100% | 100% |
| bidi-controls | 6 | 100% | 100% | 100% | 100% |
| fullwidth-nfkc | 6 | 100% | 100% | 100% | 100% |
| hex-escapes | 6 | 100% | 100% | 100% | 100% |
| homoglyphs | 6 | 100% | 100% | 100% | 100% |
| leetspeak | 6 | 100% | 100% | 100% | 100% |
| percent-encoded | 6 | 100% | 100% | 100% | 100% |
| plain-control | 6 | 100% | 0% | 100% | 0% |
| small-caps | 6 | 100% | 100% | 100% | 100% |
| sneaky-bits | 6 | 100% | 100% | 100% | 100% |
| spaced-letters | 6 | 100% | 100% | 100% | 100% |
| unicode-tags | 6 | 100% | 100% | 100% | 100% |
| variation-selectors | 6 | 100% | 100% | 100% | 100% |
| zero-width | 6 | 100% | 100% | 100% | 100% |
| **overall** | **84** | **100%** | **92.9%** | **100%** | **92.9%** |

## Payload phrasing

| Class | n | medium+ | recovered | verdict |
|---|---|---|---|---|
| canonical | 42 | 92.9% | 100% | 92.9% |
| paraphrase | 42 | 92.9% | 100% | 92.9% |

## Benign pages (false positives)

Any finding: 3.8% · medium+: 0% · flagged verdict: 0%

| Page | Findings | Verdict | Worst |
|---|---|---|---|
| B-contract-nda | 0 | clean | - |
| B-docs-onboarding | 0 | clean | - |
| B-faq-shipping | 0 | clean | - |
| B-gut-11-a | 0 | clean | - |
| B-gut-11-b | 0 | clean | - |
| B-gut-1342-a | 0 | clean | - |
| B-gut-1342-b | 0 | clean | - |
| B-gut-1400-a | 0 | clean | - |
| B-gut-1400-b | 0 | clean | - |
| B-gut-1661-a | 0 | clean | - |
| B-gut-1661-b | 0 | clean | - |
| B-gut-2600-a | 0 | clean | - |
| B-gut-2600-b | 0 | clean | - |
| B-gut-2701-a | 0 | clean | - |
| B-gut-2701-b | 0 | clean | - |
| B-gut-345-a | 0 | clean | - |
| B-gut-345-b | 0 | clean | - |
| B-gut-74-a | 0 | clean | - |
| B-gut-74-b | 0 | clean | - |
| B-gut-84-a | 0 | clean | - |
| B-gut-84-b | 0 | clean | - |
| B-gut-98-a | 0 | clean | - |
| B-gut-98-b | 0 | clean | - |
| B-news-local | 0 | clean | - |
| B-recipe-stew | 0 | clean | - |
| B-security-blog-injection | 2 | noise | low |

## Latency (attack scans)

p50 0.28 ms · p95 1.02 ms · max 10.28 ms

> Detection is a *finding*, not a verdict. A LOW informational hit on a page
> that merely discusses injection is expected and is not a false positive in
> the product sense — see the verdict column.
