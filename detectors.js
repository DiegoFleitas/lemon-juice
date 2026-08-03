(function () {
  "use strict";

  const SEVERITY = { HIGH: "high", MEDIUM: "medium", LOW: "low" };

  // Decoded payloads are re-scanned for corroborating content (see
  // scanDecodedPayloads), so they must be stored at full length — truncating
  // here would blind the re-scan. popup.js truncates at display time instead.
  // The cap only bounds what gets structured-cloned onto window.__PIScanResult.
  const MAX_DECODED = 4096;

  // --- 1. Invisible / control code points -----------------------------------
  // Curated set. Value = [human-readable name, severity].
  // Severity reflects "how likely is this to be an attack vs. a legit script
  // feature": bidi overrides and the Tags block are almost never innocent in
  // web copy; ZWJ/ZWNJ are legitimate in Arabic/Indic scripts and emoji.
  const INVISIBLE = new Map([
    [0x200b, ["ZERO WIDTH SPACE", SEVERITY.MEDIUM]],
    [0x200c, ["ZERO WIDTH NON-JOINER", SEVERITY.LOW]], // legit in Persian/Indic
    [0x200d, ["ZERO WIDTH JOINER", SEVERITY.LOW]], // legit in emoji ZWJ seqs
    [0x2060, ["WORD JOINER", SEVERITY.MEDIUM]],
    [0xfeff, ["ZERO WIDTH NO-BREAK SPACE (BOM)", SEVERITY.MEDIUM]],
    [0x00ad, ["SOFT HYPHEN", SEVERITY.LOW]],
    [0x061c, ["ARABIC LETTER MARK", SEVERITY.LOW]],
    [0x180e, ["MONGOLIAN VOWEL SEPARATOR", SEVERITY.MEDIUM]],
    [0x2028, ["LINE SEPARATOR", SEVERITY.LOW]],
    [0x2029, ["PARAGRAPH SEPARATOR", SEVERITY.LOW]],
    // Bidirectional controls — the "Trojan Source" family. Can visually
    // reorder or hide text so what a human reads differs from the code points.
    [0x202a, ["LEFT-TO-RIGHT EMBEDDING", SEVERITY.HIGH]],
    [0x202b, ["RIGHT-TO-LEFT EMBEDDING", SEVERITY.HIGH]],
    [0x202c, ["POP DIRECTIONAL FORMATTING", SEVERITY.HIGH]],
    [0x202d, ["LEFT-TO-RIGHT OVERRIDE", SEVERITY.HIGH]],
    [0x202e, ["RIGHT-TO-LEFT OVERRIDE", SEVERITY.HIGH]],
    [0x2066, ["LEFT-TO-RIGHT ISOLATE", SEVERITY.HIGH]],
    [0x2067, ["RIGHT-TO-LEFT ISOLATE", SEVERITY.HIGH]],
    [0x2068, ["FIRST STRONG ISOLATE", SEVERITY.HIGH]],
    [0x2069, ["POP DIRECTIONAL ISOLATE", SEVERITY.HIGH]],
  ]);

  // Leetspeak substitution map — common digit/symbol → letter replacements
  // used to bypass word-boundary regex patterns in prompt injection.
  const LEET = new Map([
    ["0", "o"],
    ["1", "i"],
    ["2", "z"],
    ["3", "e"],
    ["4", "a"],
    ["5", "s"],
    ["6", "g"],
    ["7", "t"],
    ["8", "b"],
    ["9", "g"],
    ["@", "a"],
    ["$", "s"],
  ]);

  // Cross-alphabet homoglyphs — Cyrillic/Greek letters visually identical to Latin.
  // Only high-confidence, genuinely identical-looking mappings. Output feeds only
  // scanInstructions, so FP risk is bounded by the patterns' English-phrase specificity.
  const HOMOGLYPH = new Map([
    ["\u0430", "a"], // Cyrillic а
    ["\u0435", "e"], // Cyrillic е
    ["\u043e", "o"], // Cyrillic о
    ["\u0440", "p"], // Cyrillic р
    ["\u0441", "c"], // Cyrillic с
    ["\u0443", "y"], // Cyrillic у
    ["\u0445", "x"], // Cyrillic х
    ["\u0456", "i"], // Cyrillic і
    ["\u03bf", "o"], // Greek ο (omicron)
    ["\u03b1", "a"], // Greek α (alpha)
    ["\u03c1", "p"], // Greek ρ (rho)
    ["\u03c7", "x"], // Greek χ (chi)
    ["\u03ba", "k"], // Greek κ (kappa)
  ]);

  // Typoglycemia word list — instruction-related words that attackers scramble
  // (same first/last letter, middle letters shuffled) to bypass word-boundary
  // regexes while remaining readable by LLMs.
  const TYPOGLYCEMIA_WORDS = [
    "ignore",
    "bypass",
    "override",
    "reveal",
    "delete",
    "system",
    "previous",
    "instructions",
    "disable",
    "remove",
    "enable",
    "activate",
    "disregard",
    "follow",
    "obey",
    "comply",
    "pretend",
    "assume",
    "imagine",
    "prompt",
    "filter",
    "safety",
    "access",
    "admin",
    "developer",
    "repeat",
    "explain",
    "forget",
    "display",
    "output",
    "print",
    "never",
    "jailbreak",
  ];

  function isTypoglycemia(word, target) {
    if (word.length !== target.length || word.length < 3) return false;
    return (
      word[0] === target[0] &&
      word[word.length - 1] === target[word.length - 1] &&
      [...word.slice(1, -1)].sort().join("") === [...target.slice(1, -1)].sort().join("")
    );
  }

  // Unicode Tags block: U+E0000–U+E007F. This is the "ASCII smuggling" vector —
  // a full invisible ASCII alphabet. Essentially never legitimate in web text,
  // so it's the single highest-value thing this whole extension detects.
  function isTagChar(cp) {
    return cp >= 0xe0000 && cp <= 0xe007f;
  }

  // Unicode property regexes for the invisible-char detection net.
  // Covers every format character and default ignorable that Unicode itself
  // defines — not just the curated hand-list below.
  const INVISIBLE_NET_RE = /\p{Default_Ignorable_Code_Point}/u;
  const BIDI_CTRL_RE = /\p{Bidi_Control}/u;

  function isPropInvisible(cp) {
    // Variation selectors are default-ignorable but have their own detector.
    if (isVariationSelector(cp)) return false;
    const ch = String.fromCodePoint(cp);
    return INVISIBLE_NET_RE.test(ch) || BIDI_CTRL_RE.test(ch);
  }

  // Iterates by code point (for...of) — Tags block is in the astral plane (> U+FFFF).
  function scanInvisible(text) {
    const findings = [];
    let index = 0;
    let smuggled = ""; // reassembled Tags-block payload, if any
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (isTagChar(cp)) {
        // Map U+E00xx back to its ASCII twin (U+E0041 -> 'A', etc.)
        if (cp >= 0xe0020 && cp <= 0xe007e) smuggled += String.fromCharCode(cp - 0xe0000);
        findings.push({
          type: "unicode-tag",
          codePoint: cp,
          hex: `U+${cp.toString(16).toUpperCase()}`,
          name: "UNICODE TAG (ASCII smuggling)",
          severity: SEVERITY.HIGH,
          index,
        });
      } else if (isPropInvisible(cp)) {
        const override = INVISIBLE.get(cp);
        findings.push({
          type: "invisible",
          codePoint: cp,
          hex: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
          name: override ? override[0] : "DEFAULT IGNORABLE",
          severity: override ? override[1] : SEVERITY.MEDIUM,
          index,
        });
      }
      index += ch.length; // advance by UTF-16 units so index maps to the DOM string
    }
    if (smuggled) {
      // Attach the decoded hidden message to the first tag finding so the popup
      // can show "…this invisible run decodes to: <payload>".
      const first = findings.find((f) => f.type === "unicode-tag");
      if (first) first.decoded = smuggled;
    }
    return findings;
  }

  // --- 2. Encoded-payload heuristic (OWASP scenario #9) ----------------------
  // Only flag if decoded output looks like readable ASCII (avoids hashes, data-URIs, etc.).
  const BASE64_RUN = /[A-Za-z0-9+/]{24,}={0,2}/g;

  // JWTs (header.payload.signature, each segment base64) decode cleanly and are
  // common in legitimate dev-tool pages/API docs/code samples. Corroborate
  // with the full dot-separated three-segment shape (not just "does this one
  // segment's decoded text look like JSON") so both the header AND payload
  // segments of the same real JWT get recognized, not just whichever one
  // happens to start with {"alg".
  const JWT_HEADER_RE = /^\{"(alg|typ)"\s*:/;
  const JWT_TRIPLE_RE = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

  function isJwtLike(text, index, blobLength) {
    const start = Math.max(0, index - 500);
    const end = Math.min(text.length, index + blobLength + 500);
    const window = text.slice(start, end);
    const triple = JWT_TRIPLE_RE.exec(window);
    if (!triple) return false;
    const tripleStart = start + triple.index;
    const tripleEnd = tripleStart + triple[0].length;
    if (index < tripleStart || index + blobLength > tripleEnd) return false; // our blob isn't inside the triple
    const headerSegment = triple[0].split(".")[0];
    const headerJson = tryDecodeBase64(headerSegment);
    return !!headerJson && JWT_HEADER_RE.test(headerJson);
  }

  function scanEncoded(text) {
    const findings = [];
    let m;
    while ((m = BASE64_RUN.exec(text)) !== null) {
      const blob = m[0];
      const decoded = tryDecodeBase64(blob);
      if (decoded && looksLikeText(decoded)) {
        const jwt = isJwtLike(text, m.index, blob.length);
        findings.push({
          type: "encoded-base64",
          // Downgrade rather than suppress: keep it visible at LOW so a
          // deliberately JWT-shaped decoy carrying real injected instructions
          // still surfaces something, matching the instruction-phrase
          // philosophy (informational, non-convicting, never fully hidden).
          severity: jwt ? SEVERITY.LOW : SEVERITY.MEDIUM,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "…" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
          ...(jwt ? { likelyJwt: true } : {}),
        });
      }
    }
    return findings;
  }

  function tryDecodeBase64(s) {
    try {
      // Attackers strip the '=' padding to dodge naive alignment checks; pad
      // back out to a multiple of 4 instead of rejecting outright. A run whose
      // final quantum is truly malformed (not just missing padding) will
      // either throw here or decode to garbage that looksLikeText() rejects.
      const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
      // atob in browsers, Buffer in Node — support both so tests pass.
      const raw =
        typeof atob === "function"
          ? atob(padded)
          : Buffer.from(padded, "base64").toString("binary");
      return raw;
    } catch {
      return null;
    }
  }

  function looksLikeText(s) {
    if (s.length < 6) return false;
    let printable = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
    }
    return printable / s.length > 0.85;
  }

  // --- 2b. Percent-encoding / hex-escape heuristics --------------------------
  const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2}){6,}/g;
  const HEX_ESCAPE_RUN = /(?:\\x[0-9A-Fa-f]{2}){6,}/g;

  function scanPercentEncoded(text) {
    const findings = [];
    let m;
    while ((m = PERCENT_RUN.exec(text)) !== null) {
      const blob = m[0];
      let decoded;
      try {
        decoded = decodeURIComponent(blob);
      } catch {
        continue; // malformed multi-byte sequence — not a real payload
      }
      if (looksLikeText(decoded)) {
        findings.push({
          type: "encoded-percent",
          severity: SEVERITY.MEDIUM,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "…" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
        });
      }
    }
    return findings;
  }

  function decodeHexEscapes(s) {
    // \xNN pairs -> raw bytes, interpreted as a binary/Latin-1 string (same
    // convention as tryDecodeBase64's "binary" mode) so looksLikeText can gate
    // it identically.
    let out = "";
    for (let i = 0; i < s.length; i += 4) {
      out += String.fromCharCode(parseInt(s.slice(i + 2, i + 4), 16));
    }
    return out;
  }

  function scanHexEscape(text) {
    const findings = [];
    let m;
    while ((m = HEX_ESCAPE_RUN.exec(text)) !== null) {
      const blob = m[0];
      const decoded = decodeHexEscapes(blob);
      if (looksLikeText(decoded)) {
        findings.push({
          type: "encoded-hex-escape",
          severity: SEVERITY.MEDIUM,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "…" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
        });
      }
    }
    return findings;
  }

  // --- 2c. Space-separated hex byte smuggling ---------------------------------
  // "49 67 6e 6f 72 65" → "Ignore". The looksLikeText gate keeps ordinary
  // space-separated numbers from false-positiving (they decode to garbage).
  const SPACED_HEX_RUN = /\b(?:[0-9A-Fa-f]{2}\s+){5,}[0-9A-Fa-f]{2}\b/g;

  function decodeSpacedHex(s) {
    return s
      .trim()
      .split(/\s+/)
      .map((h) => String.fromCharCode(parseInt(h, 16)))
      .join("");
  }

  function scanSpacedHex(text) {
    const findings = [];
    let m;
    while ((m = SPACED_HEX_RUN.exec(text)) !== null) {
      const blob = m[0];
      const decoded = decodeSpacedHex(blob);
      if (looksLikeText(decoded)) {
        findings.push({
          type: "encoded-spaced-hex",
          severity: SEVERITY.MEDIUM,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "…" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
        });
      }
    }
    return findings;
  }

  // --- 2d. \uXXXX Unicode escape and HTML entity decoding --------------------
  const UNICODE_ESCAPE_RUN = /(?:\\u[0-9A-Fa-f]{4}){6,}/g;

  function decodeUnicodeEscapes(s) {
    return s.replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) =>
      String.fromCharCode(parseInt(h, 16))
    );
  }

  function scanUnicodeEscape(text) {
    const findings = [];
    let m;
    while ((m = UNICODE_ESCAPE_RUN.exec(text)) !== null) {
      const blob = m[0];
      const decoded = decodeUnicodeEscapes(blob);
      if (decoded && looksLikeText(decoded)) {
        findings.push({
          type: "encoded-unicode-escape",
          severity: SEVERITY.LOW,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "\u2026" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
        });
      }
    }
    return findings;
  }

  const HTML_ENTITY_RUN = /(?:&#[0-9]{2,7};|&#x[0-9A-Fa-f]{1,6};){6,}/g;

  function decodeHtmlEntities(s) {
    return s
      .replace(/&#(\d+);/g, (_, n) => {
        try {
          return String.fromCodePoint(+n);
        } catch {
          return "";
        }
      })
      .replace(/&#x([0-9A-Fa-f]+);/g, (_, h) => {
        try {
          return String.fromCodePoint(parseInt(h, 16));
        } catch {
          return "";
        }
      });
  }

  function scanHtmlEntities(text) {
    const findings = [];
    let m;
    while ((m = HTML_ENTITY_RUN.exec(text)) !== null) {
      const blob = m[0];
      const decoded = decodeHtmlEntities(blob);
      if (decoded && looksLikeText(decoded)) {
        findings.push({
          type: "encoded-html-entity",
          severity: SEVERITY.LOW,
          index: m.index,
          sample: blob.slice(0, 32) + (blob.length > 32 ? "\u2026" : ""),
          decoded: decoded.slice(0, MAX_DECODED),
        });
      }
    }
    return findings;
  }

  // --- 3. Instruction-phrase heuristic (OWASP scenario #1) -------------------
  // Deliberately INFORMATIONAL only (never bumps overall severity to HIGH on
  // its own) because it false-positives on any page discussing prompt
  // injection — including the OWASP page and this very extension's README.

  // Bare role labels. Shared with scanContextSwitch(), which must EXCLUDE this
  // pattern from its corroboration check — otherwise any transcript corroborates
  // itself.
  const ROLE_LABEL_PATTERN = /^\s*(system|assistant|user|human|ai)\s*:/im;

  const INSTRUCTION_PATTERNS = [
    /\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)\b/i,
    /\bdisregard\s+(the\s+)?(previous|prior|above|earlier|system)\b/i,
    /\byou\s+are\s+now\b/i,
    /\bnew\s+instructions?\s*:/i,
    ROLE_LABEL_PATTERN,
    /\bdo\s+not\s+(tell|inform|mention\s+to)\s+the\s+user\b/i,
    // --- expanded corpus (jailbreak/override phrasing) ---
    /\bforget\s+(all\s+)?(previous|prior|earlier)\s+(instructions|context|prompts?)\b/i,
    /\boverride\s+(your|the)\s+(instructions|programming|guidelines|rules)\b/i,
    // Deliberately NOT bare "act as" — false-positives on ordinary copy like
    // "act as a proxy". Require the more specific roleplay phrasing instead.
    /\bpretend\s+(to\s+be|you\s*(?:'re|are))\b/i,
    /\broleplay\s+as\b/i,
    /\bdeveloper\s+mode\b/i,
    // "DAN" as a bare acronym collides with the name "Dan" — match its
    // defining phrase instead.
    /\bdo\s+anything\s+now\b/i,
    // Bare "jailbreak" false-positives on phone/device jailbreaking articles;
    // require it to be paired with an AI/assistant-referencing noun.
    /\bjailbreak(?:ing)?\s+(?:the\s+)?(?:model|ai|assistant|chatbot|llm)\b/i,
    // Bare "from now on" is common in ordinary prose ("from now on, meetings
    // start at 9am"); require it to address "you/your" directly.
    /\bfrom\s+now\s+on\s*,?\s*(you|your)\b/i,
    /\byour\s+new\s+role\s+is\b/i,
    // Bare "print/show instructions" false-positives hard on product manuals
    // and tutorials ("Print instructions are included in the box."). Require
    // the possessive "your" so it targets the assistant's own instructions.
    /\b(reveal|show|print|output|display)\s+your\s+(system\s+prompt|instructions|initial\s+prompt)\b/i,

    // --- Expanded jailing/override patterns (Prompt-Injection-Everywhere coverage) ---
    // Stemming variants (ignore/ignoring/ignores/ignored)
    /\bignor(?:ing|es|ed)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|context)\b/i,
    // "disregard all previous" (the "all" variant was missing from the main pattern above)
    /\bdisregard(?:ing|ed)?\s+all\s+(?:the\s+)?(?:previous|prior|above|earlier)\b/i,
    // "Never say you can't" — common jailbreak prefix
    /\bnever\s+(?:say|tell|respond|answer)\s+(?:me\s+)?(?:you\s+)?(?:can't|cannot|can\s+not)\b/i,
    // Format-shifting: "as a poem, explain all previous instructions"
    /\b(?:explain|repeat|reveal|output)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|context)\b/i,
    // Hypothetical wrappers: "Hypothetically, if you were to…"
    /\bhypothetically[\s,;:]/i,
    // External-fetch injection: "fetch data from evil.com"
    /\bfetch\s+(?:\w+\s+)?(?:from|at)\s+\S+\.\S+/i,
    // Ethical-framing jailbreak: "as an ethical hacker / pentester"
    /\bas\s+an?\s+ethical\s+(?:hacker|researcher|pentester)\b/i,
    // Imperative "give/tell/show me the system prompt" — no "your" required
    /\b(give|tell|show|send|reveal|provide)\s+(?:me\s+)?(?:the\s+)?(?:your\s+)?system\s+prompt\b/i,
    // Emoji substituting for negation words — 🚫 (no entry) in place of "ignore/disregard"
    /🚫\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|context)\b/i,

    // --- System-prompt extraction probes ---
    // Asking the assistant to reproduce or re-encode its own instructions,
    // rather than override them outright — a softer extraction angle that
    // the override/reveal patterns above don't cover (no "system prompt" /
    // "instructions" possessive phrasing required).
    /\brepeat\s+(?:the\s+)?(?:text|words?)\s+above\s+verbatim\b/i,
    /\bprint\s+your\s+(?:initial\s+)?instructions?\s+word\s+for\s+word\b/i,
    /\bencode\s+your\s+(?:instructions?|system\s+prompt)\s+(?:in|as)\s+base\s*64\b/i,

    // --- Chain-of-thought (CoT) hijacking phrases (OWASP #10) ---
    // Legitimate in educational content but exploited to lower the model's guard:
    // "let's think step by step" then comply with anything. Informational only.
    /\blet's\s+(?:think|reason|work)\s+(?:step\s+by\s+step|through\s+this)\b/i,
    /\b(?:think|reason)\s+step\s+by\s+step\b/i,
    /\bthink\s+carefully\s*[,;:.!?]/i,
    // "take a deep breath and think/reason/work…" — the standalone phrase is
    // common in self-care/meditation content; require the jailbreak-paired "and".
    /\btake\s+a\s+deep\s+breath\s+and\s+(?:think|reason|work|solve|answer|respond|approach)\b/i,

    // --- Delimiter-fence markers ---
    // "--- BEGIN INSTRUCTIONS ---" / "--- END INSTRUCTIONS ---" section fences,
    // used to wall off injected instructions from the surrounding context.
    // No leading \b — fence markers can appear at line start after whitespace.
    /---\s*(?:BEGIN|START)\s+(?:INSTRUCTIONS?|PROMPT|OVERRIDE|RULES|SYSTEM)\s*---/i,
    /---\s*(?:END|STOP)\s+(?:INSTRUCTIONS?|PROMPT|OVERRIDE|RULES|SYSTEM)\s*---/i,

    // --- Compound / continuation-of-system-prompt instructions (OWASP scenario #1) ---
    // Text posing as an amendment to the assistant's own instructions. Bare
    // "updated policy:" and "the following supersedes" false-positive hard on ToS
    // pages, changelogs and contract boilerplate — require "you"/"your".
    /\bas\s+part\s+of\s+your\s+(?:updated|new|revised|current)\s+(?:guidelines|instructions?|policy|rules)\b/i,
    /\bnew\s+instructions?\s+effective\s+immediately\b/i,
    /\bper\s+your\s+(?:revised|updated|new)\s+instructions?\b/i,
    /\bupdated\s+policy\s*:\s*(?:you|your|the\s+assistant|assistant)\b/i,
    /\bthe\s+following\s+supersedes\s+(?:all\s+)?(?:your\s+|any\s+)?(?:previous|prior|earlier)\s+(?:instructions?|guidelines|rules|prompts?)\b/i,

    // --- OWASP / PIDB extended patterns ---
    // Authority claim: "I am the developer/admin/creator of this system"
    /\bi\s+am\s+(?:the|a)\s+(?:developer|admin|creator|owner|operator)\b/i,
    // Role-based negation: "act as if you're not bound by restrictions"
    /\bact\s+as\s+if\s+(?:you(?:'re|r\s+e)\s+|you\s+are\s+)not\s+bound\b/i,
    // Extraction probe: "what were your exact instructions"
    /\bwhat\s+(?:were|are)\s+(?:your|the)\s+exact\s+instructions?\b/i,
    // Filter-bypass declaration: "no restrictions / rules / limits / boundaries"
    /\bno\s+(?:restrictions|rules|limits|boundaries)\b/i,
    // Safety-control negation: "content filter bypass", "safety disabled"
    /\b(?:content\s+filter|moderation|safety)\s+(?:bypass|disabled|removed)\b/i,
    // Gamification jailbreak: "tokens reward / penalty / point"
    /\btokens?\s+(?:reward|penalty|point)\b/i,
    // Confirmation trigger: "if you understand, say/reply/respond/type"
    /\bif\s+you\s+understand[\s,;:]+(?:say|reply|respond|type)\b/i,

    // --- Data extraction / recursive-prompting probes ---
    /\btell\s+me\s+(?:all\s+)?your\s+secrets?\b/i,
    /\breveal\s+(?:all\s+)?your\s+secrets?\b/i,
    /\byou\s+are\s+(?:now\s+)?the\s+system\s+prompt\b/i,
    /\bgenerate\s+a\s+prompt\s+that\s+will\b/i,

    // Rephrased override: destructive verb + a "prior-state" modifier +
    // instruction-noun (up to 2 filler words between). The modifier is the
    // discriminator — it targets the assistant's own prior instructions,
    // unlike benign imperatives ("skip the safety briefing", "replace the
    // batteries per the instructions"). Overlaps with the dedicated ignore/
    // disregard/forget/override patterns above are collapsed by scanInstructions'
    // overlap dedup, so one phrase reports once.
    /\b(?:skip|bypass|discard|forget|ignore|disregard|override)\s+(?:all\s+)?(?:the\s+)?(?:your\s+)?(?:previous|prior|earlier|above|current|default|initial|original)\s+(?:\w+\s+){0,2}?(?:instructions?|directions?|context|guidelines?|rules?|training|restrictions?|constraints?|safety)\b/i,
  ];

  // Spaced-letter patterns (e.g. "i g n o r e") run as a separate pass in
  // scanText() so they don't duplicate findings with scanInstructions().
  const SPACED_INSTRUCTION_PATTERNS = [
    // "i g n o r e a l l p r e v i o u s i n s t r u c t i o n s"
    /\bi\s+g\s+n\s+o\s+r\s+e\s+(?:a\s+l\s+l\s+)?(?:p\s+r\s+e\s+v\s+i\s+o\s+u\s+s|p\s+r\s+i\s+o\s+r|a\s+b\s+o\s+v\s+e)\s+(?:i\s+n\s+s\s+t\s+r\s+u\s+c\s+t\s+i\s+o\s+n\s+s?|p\s+r\s+o\s+m\s+p\s+t\s+s?)\b/i,
    // "d i s r e g a r d a l l (t h e) p r e v i o u s"
    /\bd\s+i\s+s\s+r\s+e\s+g\s+a\s+r\s+d\s+(?:a\s+l\s+l\s+)?(?:t\s+h\s+e\s+)?(?:p\s+r\s+e\s+v\s+i\s+o\s+u\s+s|p\s+r\s+i\s+o\s+r|a\s+b\s+o\s+v\s+e|e\s+a\s+r\s+l\s+i\s+e\s+r|s\s+y\s+s\s+t\s+e\s+m)\b/i,
    // "n e v e r s a y / t e l l / r e s p o n d / a n s w e r"
    /\bn\s+e\s+v\s+e\s+r\s+(?:s\s+a\s+y|t\s+e\s+l\s+l|r\s+e\s+s\s+p\s+o\s+n\s+d|a\s+n\s+s\s+w\s+e\s+r)\s+(?:m\s+e\s+)?(?:y\s+o\s+u\s+)?(?:c\s+a\s+n\s+(?:'|n\s+o\s+t)|c\s+a\s+n\s+n\s+o\s+t)\b/i,
  ];

  const SEVERITY_RANK = { [SEVERITY.HIGH]: 3, [SEVERITY.MEDIUM]: 2, [SEVERITY.LOW]: 1 };

  function scanInstructions(text) {
    const matches = [];
    for (const re of INSTRUCTION_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        matches.push({
          index: m.index,
          end: m.index + m[0].length,
          severity: SEVERITY.LOW, // informational — corroborates, never convicts alone
          match: m[0].slice(0, 80),
          source: re.source, // internal: cross-pass dedup key, not for display
        });
      }
    }
    // A single phrase can match several patterns (e.g. the dedicated
    // "ignore ... previous ... instructions" and the broader rephrased-override
    // pattern both hit "ignore all previous instructions"; the CoT forms overlap
    // each other). Report each overlapping region once, keeping the
    // highest-severity match (then longest, then earliest).
    matches.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        b.end - b.index - (a.end - a.index) ||
        a.index - b.index
    );
    const kept = [];
    for (const m of matches) {
      if (kept.some((k) => m.index < k.end && k.index < m.end)) continue;
      kept.push(m);
    }
    return kept
      .sort((a, b) => a.index - b.index)
      .map((m) => ({
        type: "instruction-phrase",
        severity: m.severity,
        index: m.index,
        match: m.match,
        pattern: m.source,
      }));
  }

  // --- 3b. Context-switch / fake-conversation heuristic (OWASP scenario #1) --
  // Injected content fabricates a multi-turn dialogue so the assistant reads a
  // compliance it never gave. FALSE-POSITIVE RISK IS REAL: legitimate support
  // transcripts, chat-log docs and LLM tutorials all contain "User:"/"AI:"
  // turns. Structure alone is therefore NOT enough — a finding needs two role
  // lines PLUS corroboration: a refusal→acceptance flip, or an instruction
  // phrase other than the bare role label itself (ROLE_LABEL_PATTERN, which
  // every transcript trips). The weaker instruction-phrase path additionally
  // requires two DISTINCT roles, so a FAQ repeating one label doesn't convict
  // on a stray phrase. The flip path deliberately does not: a fabricated
  // refusal-then-compliance is inherently same-role (the attacker writes the
  // assistant refusing, then complying), and the refusal + acceptance
  // co-occurrence is specific enough to carry it alone.
  // Severity stays LOW for the same reason scanInstructions is LOW: it
  // corroborates, it never convicts. It also inherits scanInstructions' FP
  // profile — a tutorial that both shows role labels and quotes "ignore all
  // previous instructions" will fire. That is the accepted cost of LOW.
  // LIMITATION: scan.js scans one DOM text node at a time, so this only sees
  // dialogues that live in a single node (<pre>, comment, textarea, attribute).
  // Structural role-turn matcher: any line-leading letter word followed by
  // a colon is a potential dialogue marker (User:, AI:, admin:, etc.).
  // Both uppercase (User:) and lowercase (user:) labels are matched so
  // case-only role-label obfuscation doesn't bypass detection. Denylisted
  // section headers (Note:, Warning:, Tip:, …) are filtered out below.
  // Safe to be wide — unlike ROLE_LABEL_PATTERN, this is corroboration-gated
  // (≥2 distinct labels PLUS a flip or instruction phrase), so bare "Hello:"
  // lines on support pages never convict on their own.
  const ROLE_TURN_RE = /^[ \t>*-]*(?:\*\*)?(\p{L}{1,21})(?:\*\*)?\s*:/gmu;
  const ROLE_DENYLIST_RE = /^(?:Note|Warning|Tip|Example|Step|Figure|Table|Chapter)$/i;
  const REFUSAL_RE =
    /\b(?:i\s+(?:can't|cannot|can\s+not|won't|will\s+not|am\s+unable\s+to)|i'm\s+(?:sorry|not\s+able))\b/i;
  const COMPLIANCE_FLIP_RE =
    /\b(?:sure|certainly|of\s+course|understood|absolutely)\b[,.!]?\s*(?:here(?:'s|\s+is|\s+are)|i(?:'ll|\s+will|\s+can)\b)/i;

  function scanContextSwitch(text) {
    const findings = [];
    const turns = [...text.matchAll(ROLE_TURN_RE)];
    if (turns.length < 2) return findings;
    const labels = new Set(
      turns
        .map((t) => t[1].normalize("NFKC").toLowerCase())
        .filter((l) => !ROLE_DENYLIST_RE.test(l))
    );
    const flip = REFUSAL_RE.test(text) && COMPLIANCE_FLIP_RE.test(text);
    const instr =
      labels.size >= 2 &&
      scanInstructions(text).some((f) => f.pattern !== ROLE_LABEL_PATTERN.source);
    if (!flip && !instr) return findings;
    const match = text.slice(turns[0].index, turns[0].index + 80).split("\n")[0];
    findings.push({
      type: "context-switch",
      severity: SEVERITY.LOW,
      index: turns[0].index,
      roles: [...labels],
      reason: flip ? "compliance-flip" : "instruction-phrase",
      match,
    });
    return findings;
  }

  // --- 4. Variation-selector smuggling ("emoji byte-smuggling") -------------
  // VS1-16 (U+FE00–U+FE0F) → bytes 0-15, VS17-256 (U+E0100–U+E01EF) → 16-255.
  // A legitimate single-emojification selector (e.g. ❤️'s U+FE0F) decodes to
  // too few bytes to pass looksLikeText's length gate — so it won't FP.
  function variationSelectorByte(cp) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00; // VS1-16 -> byte 0-15
    if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16; // VS17-256 -> byte 16-255
    return -1;
  }

  function isVariationSelector(cp) {
    return variationSelectorByte(cp) !== -1;
  }

  function decodeUtf8Bytes(bytes) {
    try {
      // TextDecoder is a global in both modern browsers and Node (11+); Buffer
      // is the Node fallback, mirroring tryDecodeBase64's atob/Buffer split.
      if (typeof TextDecoder === "function") {
        return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes));
      }
      return Buffer.from(bytes).toString("utf8");
    } catch {
      return null;
    }
  }

  function scanVariationSelectors(text) {
    const findings = [];
    let index = 0;
    let bytes = [];
    let runStart = null;
    const flush = () => {
      if (bytes.length) {
        const decoded = decodeUtf8Bytes(bytes);
        if (decoded && looksLikeText(decoded)) {
          findings.push({
            type: "variation-selector-smuggling",
            severity: SEVERITY.HIGH,
            index: runStart,
            length: bytes.length,
            decoded: decoded.slice(0, MAX_DECODED),
          });
        }
      }
      bytes = [];
      runStart = null;
    };
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      const b = variationSelectorByte(cp);
      if (b !== -1) {
        if (runStart === null) runStart = index;
        bytes.push(b);
      } else {
        flush();
      }
      index += ch.length;
    }
    flush();
    return findings;
  }

  // --- 5. Sneaky Bits smuggling (invisible-times/invisible-plus bit encoding) -
  // U+2062 (INVISIBLE TIMES) = bit 0, U+2064 (INVISIBLE PLUS) = bit 1,
  // MSB-first, 8 bits/byte, then UTF-8 decoded. Never legitimate in prose.
  // Ref: embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/
  function sneakyBitValue(cp) {
    if (cp === 0x2062) return 0;
    if (cp === 0x2064) return 1;
    return -1;
  }

  function isSneakyBitsChar(cp) {
    return sneakyBitValue(cp) !== -1;
  }

  function bitsToBytes(bits) {
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      let byte = 0;
      for (let k = 0; k < 8; k++) byte = (byte << 1) | bits[i + k];
      bytes.push(byte);
    }
    return bytes;
  }

  function scanSneakyBits(text) {
    const findings = [];
    let index = 0;
    let bits = [];
    let runStart = null;
    const flush = () => {
      if (bits.length >= 8) {
        const decoded = decodeUtf8Bytes(bitsToBytes(bits));
        if (decoded && looksLikeText(decoded)) {
          findings.push({
            type: "sneaky-bits-smuggling",
            severity: SEVERITY.HIGH,
            index: runStart,
            length: bits.length,
            decoded: decoded.slice(0, MAX_DECODED),
          });
        }
      }
      bits = [];
      runStart = null;
    };
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      const bit = sneakyBitValue(cp);
      if (bit !== -1) {
        if (runStart === null) runStart = index;
        bits.push(bit);
      } else {
        flush();
      }
      index += ch.length;
    }
    flush();
    return findings;
  }

  // --- 6. Combining diacritical marks (Zalgo) detection ----------------------
  // 8+ combining marks (U+0300–U+036F) stacked on one base character is almost
  // never legitimate and can obscure text or bypass word-boundary regexes.
  function scanCombiningMarks(text) {
    const findings = [];
    let index = 0;
    let stackCount = 0;
    let stackStart = null;
    const flush = () => {
      if (stackCount >= 8)
        findings.push({
          type: "excessive-combining-marks",
          severity: SEVERITY.LOW,
          index: Math.max(0, stackStart - 1),
          count: stackCount,
        });
      stackCount = 0;
      stackStart = null;
    };
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x0300 && cp <= 0x036f) {
        if (stackStart === null) stackStart = index;
        stackCount++;
      } else {
        flush();
      }
      index += ch.length;
    }
    flush();
    return findings;
  }

  // --- 6b. Mixed-script homoglyph detection -----------------------------------
  function scanMixedScript(text) {
    const findings = [];
    const tokenRe = /\p{L}+/gu;
    let m;
    while ((m = tokenRe.exec(text)) !== null) {
      const token = m[0];
      if (hasMixedScript(token)) {
        findings.push({
          type: "mixed-script",
          severity: SEVERITY.LOW,
          index: m.index,
          token: token.slice(0, 40),
        });
      }
    }
    return findings;
  }

  function hasMixedScript(token) {
    let hasLatin = false;
    let hasOther = false;
    for (const ch of token) {
      if (/\p{Script=Latin}/u.test(ch)) hasLatin = true;
      else if (/\p{Script=Common}/u.test(ch)) continue;
      else if (/\p{Script=Inherited}/u.test(ch)) continue;
      else hasOther = true;
    }
    return hasLatin && hasOther;
  }

  // --- 7. LLM chat-template control-token smuggling --------------------------
  // Verbatim <|im_start|>, [INST], </system> — parsed as turn boundaries if a
  // model ingests the page. HIGH (unlike bare "system:"/"assistant:" in prose).
  const CONTROL_TOKENS = [
    /<\|im_start\|>/i,
    /<\|im_end\|>/i,
    /<\/system>/i,
    /\[INST\]/i,
    /\[\/INST\]/i,
    /---\s*END OF PROMPT\s*---/i,
  ];

  function scanControlTokens(text) {
    const findings = [];
    for (const re of CONTROL_TOKENS) {
      const m = re.exec(text);
      if (m) {
        findings.push({
          type: "control-token",
          severity: SEVERITY.HIGH,
          index: m.index,
          match: m[0].slice(0, 80),
          pattern: re.source, // internal: cross-pass dedup key, not for display
        });
      }
    }
    return findings;
  }

  // --- 7b. Code-execution / sandbox-escape heuristic -------------------------
  // Python RCE and sandbox-escape patterns. Near-zero false-positive risk in
  // normal web copy — these are code-injection payloads, not prose.
  const CODE_EXECUTION_PATTERNS = [
    // Sandbox escape: Python attribute chain to reach __builtins__
    /__class__\s*\.\s*__mro__/i,
    /__subclasses__\s*\(/i,
    /__globals__\s*\[/i,
    /__builtins__\s*\[/i,
    // Direct RCE via stdlib
    /\bos\.popen\s*\(/i,
    /\bos\.system\s*\(/i,
    /\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(/i,
    // Execution of arbitrary code
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\b__import__\s*\(/i,
    /\bpickle\.loads?\s*\(/i,
    // Alternative Python RCE paths
    /\bpty\.spawn\s*\(/i,
    /\bwin32api\.(?:ShellExecute|CreateProcess)\s*\(/i,
    // Dynamic import / compilation (PEP 302 / importlib)
    /\bimportlib\.import_module\s*\(/i,
    /\bcompile\s*\(/i,
    // Obfuscated execution via decode-then-exec
    /\bexec\s*\(.*(?:b64decode|decode|decompress|rot13)\s*\(/i,
  ];

  function scanCodeExecution(text) {
    const findings = [];
    for (const re of CODE_EXECUTION_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        const isSandboxEscape =
          /__class__|__mro__|__subclasses__|__globals__|__builtins__/.test(re.source);
        // Corroborated decode-then-exec (two signals) stays MEDIUM; a bare
        // eval(/exec(/subprocess.run( etc. is LOW — those appear constantly in
        // legitimate code documentation this extension scans, so they're
        // informational, not convicting (AGENTS.md anti-FP posture).
        const isCorroborated = /b64decode|decode|decompress|rot13/.test(re.source);
        const severity = isSandboxEscape
          ? SEVERITY.HIGH
          : isCorroborated
            ? SEVERITY.MEDIUM
            : SEVERITY.LOW;
        findings.push({
          type: "code-execution",
          severity,
          index: m.index,
          match: m[0].slice(0, 80),
          pattern: re.source,
        });
      }
    }
    return findings;
  }

  // --- 7c. Reverse-shell / network-exfiltration commands ----------------------
  // Standalone shell commands (not wrapped in Python). HIGH severity.
  const REVERSE_SHELL_PATTERNS = [
    /\bbash\s+-i\s*[>&]+\s*\/dev\/tcp\//i,
    /\bnc\s+-e\s+\/bin\/(?:bash|sh|dash)\b/i,
    /\bbash\s+-c\s+(?:"|')\s*bash\s+-i\b/i,
    /\bncat\s+--exec\s+\/bin\/(?:bash|sh)\b/i,
    /\bpython\s+-c\s+(?:"|')\s*import\s+(?:os|subprocess|pty)\b/i,
    // Python socket-based reverse shell
    /\bsocket\.connect\s*\([^)]*\)[\s\S]{0,200}subprocess\.Popen\s*\([^)]*\/bin\/(?:bash|sh)\b/i,
  ];

  function scanReverseShell(text) {
    const findings = [];
    for (const re of REVERSE_SHELL_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        findings.push({
          type: "reverse-shell",
          severity: SEVERITY.HIGH,
          index: m.index,
          match: m[0].slice(0, 80),
          pattern: re.source,
        });
      }
    }
    return findings;
  }

  // --- Normalization for the encoded/instruction re-scan pass ---------------
  // Strips INVISIBLE + Tags-block chars (same set scanInvisible flags).
  // Variation-selector code points are NOT stripped — they ARE the payload.
  function stripInvisibleChars(text) {
    let out = "";
    const indexMap = []; // indexMap[i] = index in `text` of stripped `out[i]`
    let rawIndex = 0;
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (!(isTagChar(cp) || isPropInvisible(cp))) {
        out += ch;
        for (let k = 0; k < ch.length; k++) indexMap.push(rawIndex + k);
      }
      rawIndex += ch.length;
    }
    return { text: out, indexMap };
  }

  // De-dup key for findings that can surface in both the raw and normalized
  // pass. Keyed on stable identity, not the matched text: instruction/control
  // findings by which pattern fired, encoded findings by decoded payload — both
  // survive the strip/normalize offset shift that changes `sample`/`index`.
  function contentFindingKey(f) {
    if (f.type === "instruction-phrase" || f.type === "control-token")
      return `${f.type}:${f.pattern}`;
    if (f.type === "context-switch")
      return `${f.type}:${[...f.roles].sort().join(",")}:${f.reason}`;
    if (f.type === "code-execution" || f.type === "reverse-shell")
      return `${f.type}:${f.pattern}`;
    return `${f.type}:${f.decoded}`;
  }

  // --- Regional-indicator-symbol folding (NFKC can't fold these) ------------
  function unicodeLetterToAscii(cp) {
    // Regional Indicator Symbols (U+1F1E6–U+1F1FF) — used in flag emoji but also a
    // homoglyph vector: they visually spell out ASCII text like IGNORE ALL PREVIOUS.
    if (cp >= 0x1f1e6 && cp <= 0x1f1ff) return cp - 0x1f1e6 + 0x41; // RIS A–Z → A–Z
    return -1;
  }

  // --- Advanced deobfuscation: invisible-strip + NFKC + leet + unicode-text + delimiter-strip ----
  // ONLY safe for instruction-scanning — DO NOT use for encoded/percent/hex scans
  // (leetspeak substitution corrupts the encoding).
  function normalizeDeobfuscated(text) {
    let out = "";
    const indexMap = []; // indexMap[i] = index in `text` of stripped `out[i]`
    let rawIdx = 0;
    // Append the lowercased replacement for the current source char, keeping
    // indexMap.length === out.length. Lowercasing per-emit (not as a bulk
    // out.toLowerCase() post-pass) is load-bearing: a bulk lowercase can change
    // length (İ → i̇) after indexMap is frozen and desync the two.
    const emit = (s) => {
      const low = s.toLowerCase();
      out += low;
      for (let k = 0; k < low.length; k++) indexMap.push(rawIdx);
    };
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      // Skip invisible/tag chars (same as stripInvisibleChars)
      if (isTagChar(cp) || isPropInvisible(cp)) {
        rawIdx += ch.length;
        continue;
      }
      // NFKC normalization: folds styled-letter blocks (math bold, fullwidth,
      // double-struck, circled, superscript, etc.) and fullwidth punctuation
      // in one platform call. Only accept all-printable-ASCII output so we
      // never rewrite non-Latin scripts.
      const nfkc = ch.normalize("NFKC");
      if (nfkc !== ch && /^[\x20-\x7e]+$/.test(nfkc)) {
        emit(nfkc);
        rawIdx += ch.length;
        continue;
      }
      // Regional Indicator Symbols — NFKC can't fold these (they're emoji
      // modifier code points, not Unicode compatibility variants)
      const ascii = unicodeLetterToAscii(cp);
      if (ascii !== -1) {
        emit(String.fromCharCode(ascii));
        rawIdx += ch.length;
        continue;
      }
      // Leetspeak: digit/symbol → letter
      const leet = LEET.get(ch.toLowerCase());
      if (leet) {
        emit(leet);
        rawIdx += ch.length;
        continue;
      }
      // Homoglyph: Cyrillic/Greek → Latin (visually identical lookalikes)
      const homo = HOMOGLYPH.get(ch);
      if (homo) {
        emit(homo);
        rawIdx += ch.length;
        continue;
      }
      // Strip delimiter chars used to bypass word-boundary regexes
      // (e.g. the pipe in I|g|n|o|r|e, or underscores in i_g_n_o_r_e).
      // Purposefully restrained — only strip chars that are (a) commonly used
      // for obfuscation and (b) rarely appear in normal prose.
      if (ch === "|" || ch === "_" || ch === "`" || ch === "^" || ch === "~") {
        rawIdx += ch.length;
        continue;
      }
      emit(ch);
      rawIdx += ch.length;
    }
    // Typoglycemia pass: correct first/last-letter scrambled instruction words.
    // Same-length replacement — the indexMap built above stays valid.
    out = out.replace(/\b[a-zA-Z]+\b/g, (match) => {
      const lower = match.toLowerCase();
      for (const w of TYPOGLYCEMIA_WORDS) {
        if (lower !== w && isTypoglycemia(lower, w)) {
          return match[0] === match[0].toUpperCase()
            ? w[0].toUpperCase() + w.slice(1)
            : w;
        }
      }
      return match;
    });
    return { text: out, indexMap };
  }

  // --- corroboration --------------------------------------------------------

  // Depth-1 only, structurally: the five scanners below never themselves
  // produce a `.decoded` field, and the projection into `corroboration` keeps
  // only type/severity/match — so nothing carrying `.decoded` can ever flow
  // back in here. A payload nested inside a payload is therefore never
  // decoded again. Findings attach to their parent as `corroboration` rather
  // than being emitted top-level — emitting them would double-count in
  // scan.js's bySeverity totals and inflate the toolbar badge. (A future
  // scanner added to the inner list must preserve both properties to keep
  // depth-1 true.)
  function scanDecodedPayloads(findings) {
    for (const f of findings) {
      if (!f.decoded) continue;
      // scanInvisible stores its reassembled Tags payload uncapped
      // (detectors.js:180), and every regex below backtracks superlinearly on
      // adversarial input. Clamp here so the bound holds no matter which
      // producer set `decoded`.
      const payload = f.decoded.slice(0, MAX_DECODED);
      const inner = [
        ...scanControlTokens(payload),
        ...scanInstructions(payload),
        ...scanCodeExecution(payload),
        ...scanReverseShell(payload),
        ...scanContextSwitch(payload),
      ];
      if (!inner.length) continue;
      f.corroboration = inner.map((c) => ({
        type: c.type,
        severity: c.severity,
        match: c.match,
      }));
    }
    return findings;
  }

  // Corroboration promotes, never demotes. A concealment mechanism whose
  // payload carries chat-template or executable content is no longer
  // ambiguous, so it goes straight to HIGH. One that merely carries
  // instruction-like prose moves a single step, consistent with instruction
  // phrases being informational on their own.
  const CONVICTING_CORROBORATION = new Set([
    "control-token",
    "code-execution",
    "reverse-shell",
  ]);
  const SUPPORTING_CORROBORATION = new Set(["instruction-phrase", "context-switch"]);
  // Saturates at HIGH. Two consumers apply this table — promoteSeverity here,
  // and applyContextualPromotion (Task 4) — so a corroboration/context type
  // recognized by both paths would compound across them.
  const NEXT_SEVERITY = {
    [SEVERITY.LOW]: SEVERITY.MEDIUM,
    [SEVERITY.MEDIUM]: SEVERITY.HIGH,
    [SEVERITY.HIGH]: SEVERITY.HIGH,
  };

  // A corroborator's weight is its OWN severity, not merely its type.
  // scanCodeExecution deliberately emits LOW for a bare eval(/exec( — those are
  // everywhere in legitimate code documentation — so treating them as
  // convicting would resurrect the false-positive fatigue this scoring work
  // exists to reduce. Its MEDIUM tier (corroborated decode-then-exec) still
  // counts, but only as support.
  //   2 = convicts on its own, 1 = supports (one step), 0 = informational only
  function corroborationRank(x) {
    if (CONVICTING_CORROBORATION.has(x.type)) {
      if (x.severity === SEVERITY.HIGH) return 2;
      if (x.severity === SEVERITY.MEDIUM) return 1;
      return 0;
    }
    return SUPPORTING_CORROBORATION.has(x.type) ? 1 : 0;
  }

  function promoteSeverity(finding) {
    const c = finding.corroboration;
    if (!c || !c.length) return finding;
    // No likelyJwt/likelyA11y exemption here on purpose: those dampeners exist
    // to suppress *uncorroborated* noise. A JWT-shaped blob whose payload
    // carries injected instructions is the decoy case scanEncoded's comment
    // explicitly wants surfaced.
    const rank = Math.max(0, ...c.map(corroborationRank));
    const next =
      rank === 2
        ? SEVERITY.HIGH
        : rank === 1
          ? NEXT_SEVERITY[finding.severity]
          : finding.severity;
    if (next === finding.severity) return finding;
    return { ...finding, severity: next, promotedFrom: finding.severity };
  }

  const CONCEALMENT_TYPES = new Set([
    "invisible",
    "unicode-tag",
    "css-hidden",
    "variation-selector-smuggling",
    "sneaky-bits-smuggling",
  ]);
  const CONTENT_TYPES = new Set([
    "instruction-phrase",
    "control-token",
    "context-switch",
    "code-execution",
    "reverse-shell",
  ]);

  // Text a human never sees but an LLM ingesting the DOM does. Deliberately
  // does NOT include plain body text: a page *about* prompt injection carries
  // its instruction phrases visibly, a page *carrying* one hides them. That
  // asymmetry is the whole point — see README.md's note on the OWASP page and
  // this repo's own README false-positiving.
  function concealedPlacement(item) {
    if (item.inComment) return "inside an HTML comment";
    if (item.attrName) return `inside the ${item.attrName} attribute`;
    return null;
  }

  function itemTargets(item) {
    if (item.targetIds && item.targetIds.length) return item.targetIds;
    return item.targetId ? [item.targetId] : [];
  }

  // Cross-finding corroboration, the between-detector analogue of
  // scanDecodedPayloads' within-finding check. Takes scan.js's deduped item
  // array (pure — no DOM), returns a new array with promotions applied.
  function applyContextualPromotion(items) {
    const byTarget = new Map();
    for (const item of items) {
      for (const id of itemTargets(item)) {
        const arr = byTarget.get(id) || [];
        arr.push(item);
        byTarget.set(id, arr);
      }
    }

    const reasons = new Map(); // item -> Set<string>
    const note = (item, reason) => {
      const s = reasons.get(item) || new Set();
      s.add(reason);
      reasons.set(item, s);
    };

    // A hiding mechanism and injected content on the same element corroborate
    // each other. Two mechanisms, or two content findings, do not.
    for (const group of byTarget.values()) {
      const concealment = group.filter((i) => CONCEALMENT_TYPES.has(i.type));
      const content = group.filter((i) => CONTENT_TYPES.has(i.type));
      if (!concealment.length || !content.length) continue;
      for (const i of concealment) note(i, "co-located with injected content");
      for (const i of content) note(i, "co-located with a concealment mechanism");
    }

    for (const item of items) {
      if (!CONTENT_TYPES.has(item.type)) continue;
      const where = concealedPlacement(item);
      if (where) note(item, where);
    }

    return items.map((item) => {
      const why = reasons.get(item);
      if (!why) return item;
      const contextual = [...why];
      const next = NEXT_SEVERITY[item.severity];
      if (next === item.severity) return { ...item, contextual };
      return {
        ...item,
        severity: next,
        promotedFrom: item.promotedFrom ?? item.severity,
        contextual,
      };
    });
  }

  // --- aggregate ------------------------------------------------------------
  function scanText(text) {
    const invisible = scanInvisible(text);
    const variationSelectors = scanVariationSelectors(text);
    const sneakyBits = scanSneakyBits(text);
    const combiningMarks = scanCombiningMarks(text);
    const mixedScript = scanMixedScript(text);

    const rawContent = [
      ...scanEncoded(text),
      ...scanPercentEncoded(text),
      ...scanHexEscape(text),
      ...scanSpacedHex(text),
      ...scanUnicodeEscape(text),
      ...scanHtmlEntities(text),
      ...scanControlTokens(text),
      ...scanInstructions(text),
      ...scanContextSwitch(text),
      ...scanCodeExecution(text),
      ...scanReverseShell(text),
    ];

    let normalizedOnly = [];
    const { text: normalizedText, indexMap } = stripInvisibleChars(text);
    if (normalizedText !== text) {
      const seen = new Set(rawContent.map(contentFindingKey));
      const rescanned = [
        ...scanEncoded(normalizedText),
        ...scanPercentEncoded(normalizedText),
        ...scanHexEscape(normalizedText),
        ...scanSpacedHex(normalizedText),
        ...scanUnicodeEscape(normalizedText),
        ...scanHtmlEntities(normalizedText),
        ...scanControlTokens(normalizedText),
        ...scanInstructions(normalizedText),
      ];
      normalizedOnly = rescanned
        .filter((f) => !seen.has(contentFindingKey(f)))
        .map((f) => ({
          ...f,
          index: indexMap[f.index] !== undefined ? indexMap[f.index] : text.length,
          normalized: true, // only found after stripping invisible/tag chars
        }));
    }

    // Deobfuscation pass: leetspeak + delimiter stripping, then re-scan
    // instructions and context-switch (encoded scans skipped — leet/delimiter
    // norm would corrupt them). Running scanContextSwitch here catches fabricated
    // dialogues whose role labels are disguised with fancy Unicode, leetspeak,
    // homoglyphs, etc. — normalizeDeobfuscated preserves newlines, so the
    // per-line role-turn matching still works on the normalized text.
    let deobfuscatedOnly = [];
    const { text: deobfText, indexMap: deobfIndexMap } = normalizeDeobfuscated(text);
    if (deobfText !== text) {
      const seen = new Set([
        ...rawContent.map(contentFindingKey),
        ...normalizedOnly.map(contentFindingKey),
      ]);
      const rescanned = [
        ...scanInstructions(deobfText),
        ...scanContextSwitch(deobfText),
        ...scanCodeExecution(deobfText),
        ...scanReverseShell(deobfText),
      ];
      deobfuscatedOnly = rescanned
        .filter((f) => !seen.has(contentFindingKey(f)))
        .map((f) => ({
          ...f,
          index:
            deobfIndexMap[f.index] !== undefined ? deobfIndexMap[f.index] : text.length,
          normalized: true,
        }));
    }

    // Spaced-letter pass: run SPACED_INSTRUCTION_PATTERNS against raw text AND
    // deobfuscated text. NFKC-foldable styled letters (double-struck, math-bold,
    // fullwidth, etc.) in the raw text don't match the pattern's [a-z], but the
    // deobfuscation pass folds them to ASCII then preserves the spacing — so
    // spaced + styled slips this pass but not the deobf version. The existing
    // spacedSeen set dedups both sources.
    let spacedOnly = [];
    const spacedSeen = new Set([
      ...rawContent.map(contentFindingKey),
      ...normalizedOnly.map(contentFindingKey),
      ...deobfuscatedOnly.map(contentFindingKey),
    ]);
    const spacedSources =
      deobfText !== text
        ? [
            [text, null],
            [deobfText, deobfIndexMap],
          ]
        : [[text, null]];
    for (const re of SPACED_INSTRUCTION_PATTERNS) {
      for (const [src, map] of spacedSources) {
        const m = re.exec(src);
        if (!m) continue;
        const index = map ? (map[m.index] ?? text.length) : m.index;
        const f = {
          type: "instruction-phrase",
          severity: SEVERITY.LOW,
          index,
          match: m[0].slice(0, 80),
          pattern: re.source,
          normalized: true,
        };
        if (!spacedSeen.has(contentFindingKey(f))) {
          spacedSeen.add(contentFindingKey(f));
          spacedOnly.push(f);
        }
      }
    }

    return scanDecodedPayloads([
      ...invisible,
      ...variationSelectors,
      ...sneakyBits,
      ...combiningMarks,
      ...mixedScript,
      ...rawContent,
      ...normalizedOnly,
      ...deobfuscatedOnly,
      ...spacedOnly,
    ]).map(promoteSeverity);
  }

  function worstSeverity(findings) {
    if (findings.some((f) => f.severity === SEVERITY.HIGH)) return SEVERITY.HIGH;
    if (findings.some((f) => f.severity === SEVERITY.MEDIUM)) return SEVERITY.MEDIUM;
    return findings.length ? SEVERITY.LOW : null;
  }

  const PIScanner = {
    SEVERITY,
    scanText,
    scanInvisible,
    scanEncoded,
    scanPercentEncoded,
    scanHexEscape,
    scanSpacedHex,
    scanUnicodeEscape,
    scanHtmlEntities,
    scanControlTokens,
    scanInstructions,
    scanContextSwitch,
    scanVariationSelectors,
    scanSneakyBits,
    scanCombiningMarks,
    scanMixedScript,
    scanCodeExecution,
    scanReverseShell,
    scanDecodedPayloads,
    promoteSeverity,
    applyContextualPromotion,
    hasMixedScript,
    normalizeDeobfuscated,
    unicodeLetterToAscii,
    worstSeverity,
    isTagChar,
    isVariationSelector,
    isSneakyBitsChar,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = PIScanner;
  if (typeof globalThis !== "undefined") globalThis.PIScanner = PIScanner;
})();
