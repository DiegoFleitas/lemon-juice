# Changelog

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
