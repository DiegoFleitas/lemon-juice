# Changelog

## v0.9.2 - 2026-10-25

- fix(popup): keep the page domain out of export filenames (3451387)

## v0.9.1 - 2026-10-25

- fix(scan): recognize screen-reader wrappers on ancestors (f0d5a0d)

## v0.9.0 - 2026-10-25

- feat(popup): export findings as JSON or TXT (91f6eee)

## v0.8.1 - 2026-10-25

- fix(detectors): ignore generic tokens in ROT13/Atbash decode (76376b3)

## v0.8.0 - 2026-10-25

- fix(garak): strip page HTML with HTMLParser (de7bc28)
- feat(detectors): cover more garak probe families (f7081a1)
- fix(garak): tolerate whitespace in script/style end tags (a14228b)

## v0.7.0 - 2026-10-25

- feat(detectors): decode garak encoding families (372ecff)

## v0.6.1 - 2026-10-25

- fix(detectors): report unclosed model frames as incomplete (eeed611)
- docs: show complete fake-model-frame examples (d45f344)

## v0.6.0 - 2026-10-25

- chore(deps-dev): bump @eslint/js, @playwright/test, eslint, prettier (26963e9)
- chore(deps): bump actions/checkout from 6.0.3 to 7.0.0 (fd56633)
- Measure and document the paraphrase ceiling (#6) (e079129)
- feat(detectors): detect fake chat-template syntax and model frames (#7) (71f360f)
- Add detection benchmark and small-caps fix (#5) (1b1dd11)
- docs: swap hero screenshot to png (c6948d4)
- style(docs): drop em dashes and AI-writing tells from README (96952d6)
- docs: correct claims the scoring change invalidated (1846aa8)
- docs(agents): replace rotted line references with symbol names (784b8b4)

## v0.5.0 - 2026-08-03

- docs: collapse the corroboration-scoring plan to a record (a53dfd5)
- style(popup): drop em dashes from the verdict line (b6eb2de)
- docs: reconcile scoring plan with shipped implementation (c7461c3)
- docs: describe corroboration scoring and verdict tiers (91ddbdb)
- test(e2e): gate corroboration scoring against false positives (945a4b5)
- feat(popup): lead with the page verdict and explain promotions (1892fff)
- feat(scan): apply contextual promotion and compute page verdict (613f1a0)
- feat(detectors): add page-level verdict tiers (6c418d6)
- fix(detectors): require proven concealment for co-location (4e1ee6f)
- feat(detectors): promote severity from co-location and placement (2534b90)
- docs: rank corroboration by severity in plan (100811b)
- fix(detectors): weight corroboration by its own severity (0e23f9f)
- feat(detectors): promote severity from payload corroboration (a50b21e)
- fix(detectors): clamp decoded payload before re-scanning (46de7dd)
- feat(detectors): re-scan decoded payloads for corroborating content (7bfdc70)
- docs: correct plan fixture, test, and FP-gate errors (8bda895)
- fix(popup): guard preview against non-string input (ceff723)
- style: format corroboration-scoring plan (414a42b)
- refactor(detectors): store decoded payloads at full length (3f0f21c)
- docs: add corroboration-based scoring plan (9b0cc06)
- docs: add security review notes for scanner false positives (9c637fd)

## v0.4.0 - 2026-07-26

- fix(detectors): dedup overlapping instruction-phrase matches (063e9dc)
- feat(detectors): add rephrased-override instruction pattern (c9b8a4d)
- feat(detectors): add code-execution, reverse-shell, and extraction patterns (b8b49ab)
- fix(detectors): cover "disregard prior/earlier" like ignore (30a2a74)
- fix(detectors): run spaced-letter patterns on deobfuscated text too (18fa24d)
- fix(detectors): lowercase per-emit to keep indexMap in sync (2717219)
- docs: update README Known misses for structural matcher changes (ebecca4)
- refactor(detectors): normalize deobfuscation text to lowercase (5f46e80)
- fix(detectors): match lowercase role labels in structural ROLE_TURN_RE (7c2a4f8)
- docs(plans): mark treadmill audit implemented (a398edf)
- feat(fixtures): add e2e fixtures for structural role-turn detection (19ea3b9)
- feat(detectors): implement treadmill audit — property net, structural roles, mixed-script (7a9010b)
- docs: update README Known misses for NFKC coverage (3b8f79c)
- feat(fixtures): promote fancy-unicode-role-labels to tracked positives (773f23a)
- feat(detectors): replace hand-rolled styled-letter normalization with NFKC (60af73f)
- docs(plans): mark task 7 complete, correct task 4 status (bf337be)
- chore: ignore out-of-scope fixture corpus (5b1b625)
- docs: expand known-misses with bypass demonstrations (6443d59)
- feat(detectors): add OWASP/PIDB extended instruction patterns (c2f6418)
- docs(plans): mark role-label expansion implemented (797c7ae)
- feat(detectors): recognize support-desk role synonyms in context-switch (0b9ec7b)
- docs(plans): record fancy-unicode follow-up and role-label expansion plan (afe0896)
- feat(detectors): normalize role labels for context-switch detection (803a878)
- docs(plans): add course-derived plan and mark typoglycemia complete (3ccbc73)
- docs: document contextSwitch and compound-instruction detectors (354eeeb)
- test(e2e): add course-derived detector corpus and data-driven spec (45dc610)
- feat(popup): label fabricated conversation-turn findings (f52a135)
- feat(detectors): add contextSwitch detector and compound instruction phrases (c4f6557)

## v0.3.1 - 2026-07-10

- docs: document new instruction patterns and scope boundaries (2557d93)
- feat(detectors): add cot, delimiter-fence, and human/ai role patterns (a19ade2)
- docs: restore scope section and fix spaced-letter example (b7a8f10)
- docs: rewrite README with cleaner structure and banner image (87d4434)

## v0.3.0 - 2026-07-10

- fix(detectors): safe-guard decodeHtmlEntities against RangeError (f4160bc)
- fix(detectors): fix ReDoS in HTML_ENTITY_RUN regex (fe33358)
- fix(scan-helpers): replace dead clip-path rect() check with legacy clip detection (f66294e)
- docs: add broader-detection-coverage plan (1c0edeb)
- test(e2e): add fixtures and e2e tests for all new detectors (e09c681)
- feat(popup): refactor typeLabel to object lookup, add fixture tests (18b21d4)
- feat(detectors): add unicode-escape, html-entity, combining-marks, homoglyph, and typoglycemia detectors (a327337)
- feat(scan): scan aria-label and title attributes for hidden text (3ba495c)
- feat(scan): detect transform/clip-path css hiding techniques (f633453)
- fix(manifest): declare injected scripts web-accessible for strict-CSP pages (6bc7e83)
- docs: condense verbose code comments (2615a29)

## v0.2.0 - 2026-07-10

- chore: remove product name from comments (afaa2a7)
- docs: mention SEO keyword stuffing as a known false-positive source (a634f4b)
- fix(scan): non-invasive overlay markers + dark-page color=bg false positive (1f9f576)
- docs: tighten README prose, fix em dashes, add severity mapping to What section (445fec6)
- docs: reference source line numbers instead of replicating function lists (2280657)
- docs: trim release section, add isTransparentBg/elementIsA11yHidden to helpers list (2993888)
- test(scan): add dark-mode plaintext e2e fixture and test (b4fda01)
- fix(scan): resolve system Canvas color instead of hardcoding white fallback (fd0a3bb)
- test(scan): add isTransparentBg unit tests and plaintext-GPL e2e fixture (a8334e8)
- fix(scan): normalize transparent background detection across string formats (4b4d4e3)

## v0.1.5 - 2026-07-07

- docs(plans): add false-positive-fatigue mitigation plan (2cddc4c)
- test(scan): cover decoration nodes not being re-marked (af9306b)
- fix(scan): don't re-scan injected highlight decorations (07f28e2)
- feat(scan,popup): fold 5+ near-duplicate findings into one row (a42ed30)
- feat(popup): show which occurrence a repeated finding scrolled to (d7c02eb)
- fix(popup): keep scrollTo's DOM traversal self-contained (1a821fa)
- fix(scan): dedup repeated findings and downgrade a11y-marked CSS-hidden severity (2fcb5f9)
- fix(popup): suppress zero counts in status line, badge shows actionable count only (d8a2d30)
- docs: document control-token, spaced-hex, and comment-node scanning (1354d5e)
- test(detectors): cover control-token, spaced-hex, and comment scanning (26b7f47)
- feat(detectors): add control-token, spaced-hex, and comment-node detection (53aa6c6)
- docs: update architecture docs for shadow/iframe scanning (1766627)
- test(scan): add e2e fixtures and tests for shadow/iframe traversal (dbf98c8)
- feat(scan): traverse open shadow roots and same-origin iframes (65466fc)

## v0.1.4 - 2026-07-07

- docs: add missing GPL-3.0 LICENSE file (fa5c4a2)

## v0.1.3 - 2026-07-07

- fix(popup): avoid unsafe innerHTML assignment in render() (b70ab42)
- fix(manifest): declare no data collection for AMO validation (a23904a)

## v0.1.2 - 2026-07-07

- docs: align descriptions across manifest.json, package.json, and GitHub (9cab034)

## v0.1.1 - 2026-07-07

- docs(agents): add a pre-release checklist (38f88cc)
- fix(popup): handle injection failures instead of an unhandled rejection (0bcf0c3)
- refactor(scan): dedupe bg-resolution helper, drop dead sameColor/rgb (a1d6818)
- fix(release): auto-format bumped files with prettier (9b647f6)
- style: reformat manifest.json and CHANGELOG.md with prettier (c06f3c1)
- style(release): format release.js and release.yml with prettier (30ff9f2)
- docs(test-resources): humanize unknown-unknowns caution (3d1555e)
- docs(test-resources): add unknown-unknowns caveat to test resources section (109f5a0)

## v0.1.0 - 2026-07-07

- docs: add test resources section with payload collection links (eb3bf50)
- docs(agents): document the 7 detectors and normalization pipeline (d024bb1)
- docs(readme): sync architecture and dev docs with 5-file layout (7057c49)
- docs(readme): add alpha status badge (15af50f)
- security(ci): pin actions to commit SHAs, scope ci.yml permissions (8e35e13)
- perf(ci): cache pnpm store and read Node version from .nvmrc (19bda5e)
- feat(release): add release script and GitHub Actions workflow (74cffc6)
- fix(gitignore): stop ignoring release automation source files (3f2c486)
- fix(manifest): drop invalid version_name key (1e983a4)
- docs(readme): note the green lemon marks the alpha release (5e06391)
- feat(icons): tint the lemon green for the alpha release (ed0cbcf)
- chore(manifest): mark extension as alpha pre-release (f0fabb4)
- docs(readme): scope automation caveat and Firefox-first rationale (46402aa)
- docs(readme): qualify the intro's hidden-text claim (f4c0934)
- docs(readme): trim the IMPORTANT callout to scope + pointer (587c345)
- docs(readme): update roadmap (3fd5625)
- docs(readme): note the project's early stage in the maturity disclaimer (27219d4)
- docs(readme): disclaim false sense of security from clean scans (f8a5da2)
- feat(detectors): detect emoji-substitution and regional-indicator obfuscation (92c58a4)
- feat(detectors): detect 'give me the system prompt' injection variant (342dffc)
- fix(readme): replace paraphrased epigraph with actual film quote (1e9550d)
- chore: initial commit (abc9f4e)
