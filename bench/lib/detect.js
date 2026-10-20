"use strict";

const path = require("path");
const PIScanner = require(path.join(__dirname, "..", "..", "detectors.js"));

const VERDICT_FLAGGED = new Set([
  PIScanner.VERDICT.SUSPICIOUS,
  PIScanner.VERDICT.LIKELY_INJECTION,
]);
const CONTENT_TYPES = new Set(["instruction-phrase", "control-token", "context-switch"]);

/**
 * Adapter: this is the only place that knows how the detector is called.
 * If the PIScanner API changes, fix it here and nowhere else.
 */
function scan(text) {
  const start = process.hrtime.bigint();
  let findings = PIScanner.scanText(text);
  // scan.js applies contextual promotion after deduping across elements. For a
  // text-only corpus the only reachable signal is `normalized` (the phrase was
  // revealed by stripping concealment), so calling it here mirrors the product
  // path minus comments, attributes and CSS-hidden text, which need a DOM.
  findings = PIScanner.applyContextualPromotion(findings);
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;

  let high = 0;
  let medium = 0;
  let low = 0;
  for (const f of findings) {
    if (f.severity === PIScanner.SEVERITY.HIGH) high++;
    else if (f.severity === PIScanner.SEVERITY.MEDIUM) medium++;
    else low++;
  }

  const verdict = PIScanner.pageVerdict(findings);

  // Payload understood, not just mechanism spotted: the instruction type must
  // appear either as its own finding or as a corroborator of a decoded payload.
  const allTypes = new Set();
  for (const f of findings) {
    allTypes.add(f.type);
    for (const c of f.corroboration || []) allTypes.add(c.type);
  }

  return {
    findings: findings.length,
    high,
    medium,
    low,
    worst: PIScanner.worstSeverity(findings),
    verdict,
    flaggedAny: findings.length > 0,
    flaggedMedium: high + medium > 0,
    flaggedVerdict: VERDICT_FLAGGED.has(verdict),
    // Mechanism detected is not payload understood: a Tags-block hit proves the
    // smuggling channel was found, not that the instruction was recognised.
    recovered: [...CONTENT_TYPES].some((t) => allTypes.has(t)),
    elapsedMs,
    types: [...allTypes].sort(),
  };
}

module.exports = { scan, PIScanner };
