# Changelog

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
