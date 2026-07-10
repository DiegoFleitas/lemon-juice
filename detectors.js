(function () {
  "use strict";

  const SEVERITY = { HIGH: "high", MEDIUM: "medium", LOW: "low" };

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
      } else if (INVISIBLE.has(cp)) {
        const [name, severity] = INVISIBLE.get(cp);
        findings.push({
          type: "invisible",
          codePoint: cp,
          hex: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
          name,
          severity,
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
          decoded: decoded.slice(0, 120),
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
          decoded: decoded.slice(0, 120),
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
          decoded: decoded.slice(0, 120),
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
          decoded: decoded.slice(0, 120),
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
          decoded: decoded.slice(0, 120),
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
          decoded: decoded.slice(0, 120),
        });
      }
    }
    return findings;
  }

  // --- 3. Instruction-phrase heuristic (OWASP scenario #1) -------------------
  // Deliberately INFORMATIONAL only (never bumps overall severity to HIGH on
  // its own) because it false-positives on any page discussing prompt
  // injection — including the OWASP page and this very extension's README.
  const INSTRUCTION_PATTERNS = [
    /\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts?)\b/i,
    /\bdisregard\s+(the\s+)?(previous|above|system)\b/i,
    /\byou\s+are\s+now\b/i,
    /\bnew\s+instructions?\s*:/i,
    /^\s*(system|assistant|user|human|ai)\s*:/im,
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

  function scanInstructions(text) {
    const findings = [];
    for (const re of INSTRUCTION_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        findings.push({
          type: "instruction-phrase",
          severity: SEVERITY.LOW, // informational — corroborates, never convicts alone
          index: m.index,
          match: m[0].slice(0, 80),
          pattern: re.source, // internal: cross-pass dedup key, not for display
        });
      }
    }
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
            decoded: decoded.slice(0, 120),
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
            decoded: decoded.slice(0, 120),
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

  // --- Normalization for the encoded/instruction re-scan pass ---------------
  // Strips INVISIBLE + Tags-block chars (same set scanInvisible flags).
  // Variation-selector code points are NOT stripped — they ARE the payload.
  function stripInvisibleChars(text) {
    let out = "";
    const indexMap = []; // indexMap[i] = index in `text` of stripped `out[i]`
    let rawIndex = 0;
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (!(isTagChar(cp) || INVISIBLE.has(cp))) {
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
    return `${f.type}:${f.decoded}`;
  }

  // --- Unicode alphanumeric normalisation ("fancy text" → ASCII) ------------
  function unicodeLetterToAscii(cp) {
    // Each range is a contiguous block of 26 code points mapping to A-Z or a-z.
    if (cp >= 0x1d400 && cp <= 0x1d419) return cp - 0x1d400 + 0x41; // Math Bold Caps
    if (cp >= 0x1d41a && cp <= 0x1d433) return cp - 0x1d41a + 0x61; // Math Bold Lower
    if (cp >= 0x1d434 && cp <= 0x1d44d) return cp - 0x1d434 + 0x41; // Math Italic Caps
    if (cp >= 0x1d44e && cp <= 0x1d467) return cp - 0x1d44e + 0x61; // Math Italic Lower
    if (cp >= 0x1d468 && cp <= 0x1d481) return cp - 0x1d468 + 0x41; // Math Bold Italic Caps
    if (cp >= 0x1d482 && cp <= 0x1d49b) return cp - 0x1d482 + 0x61; // Math Bold Italic Lower
    if (cp >= 0x1d504 && cp <= 0x1d51d) return cp - 0x1d504 + 0x41; // Fraktur Caps
    if (cp >= 0x1d51e && cp <= 0x1d537) return cp - 0x1d51e + 0x61; // Fraktur Lower
    if (cp >= 0x1d4b6 && cp <= 0x1d4cf) return cp - 0x1d4b6 + 0x61; // Math Script Lower
    if (cp >= 0x1d5a0 && cp <= 0x1d5b9) return cp - 0x1d5a0 + 0x41; // Sans-Serif Bold Caps
    if (cp >= 0x1d5ba && cp <= 0x1d5d3) return cp - 0x1d5ba + 0x61; // Sans-Serif Bold Lower
    if (cp >= 0x1d608 && cp <= 0x1d621) return cp - 0x1d608 + 0x41; // Sans-Serif Italic Caps
    if (cp >= 0x1d622 && cp <= 0x1d63b) return cp - 0x1d622 + 0x61; // Sans-Serif Italic Lower
    if (cp >= 0x1d670 && cp <= 0x1d689) return cp - 0x1d670 + 0x41; // Monospace Caps
    if (cp >= 0x1d68a && cp <= 0x1d6a3) return cp - 0x1d68a + 0x61; // Monospace Lower
    if (cp >= 0xff21 && cp <= 0xff3a) return cp - 0xff21 + 0x41; // Fullwidth Caps
    if (cp >= 0xff41 && cp <= 0xff5a) return cp - 0xff41 + 0x61; // Fullwidth Lower
    // Regional Indicator Symbols (U+1F1E6–U+1F1FF) — used in flag emoji but also a
    // homoglyph vector: they visually spell out ASCII text like IGNORE ALL PREVIOUS.
    if (cp >= 0x1f1e6 && cp <= 0x1f1ff) return cp - 0x1f1e6 + 0x41; // RIS A–Z → A–Z
    return -1;
  }

  // --- Advanced deobfuscation: invisible-strip + leet + unicode-text + delimiter-strip ----
  // ONLY safe for instruction-scanning — DO NOT use for encoded/percent/hex scans
  // (leetspeak substitution corrupts the encoding).
  function normalizeDeobfuscated(text) {
    let out = "";
    const indexMap = []; // indexMap[i] = index in `text` of stripped `out[i]`
    let rawIdx = 0;
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      // Skip invisible/tag chars (same as stripInvisibleChars)
      if (isTagChar(cp) || INVISIBLE.has(cp)) {
        rawIdx += ch.length;
        continue;
      }
      // Unicode fancy-text → ASCII (math bold/italic/script/fullwidth etc.)
      const ascii = unicodeLetterToAscii(cp);
      if (ascii !== -1) {
        out += String.fromCharCode(ascii);
        for (let k = 0; k < ch.length; k++) indexMap.push(rawIdx + k);
        rawIdx += ch.length;
        continue;
      }
      // Leetspeak: digit/symbol → letter
      const leet = LEET.get(ch.toLowerCase());
      if (leet) {
        out += leet;
        for (let k = 0; k < ch.length; k++) indexMap.push(rawIdx + k);
        rawIdx += ch.length;
        continue;
      }
      // Homoglyph: Cyrillic/Greek → Latin (visually identical lookalikes)
      const homo = HOMOGLYPH.get(ch);
      if (homo) {
        out += homo;
        for (let k = 0; k < ch.length; k++) indexMap.push(rawIdx + k);
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
      out += ch;
      for (let k = 0; k < ch.length; k++) indexMap.push(rawIdx + k);
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

  // --- aggregate ------------------------------------------------------------
  function scanText(text) {
    const invisible = scanInvisible(text);
    const variationSelectors = scanVariationSelectors(text);
    const sneakyBits = scanSneakyBits(text);
    const combiningMarks = scanCombiningMarks(text);

    const rawContent = [
      ...scanEncoded(text),
      ...scanPercentEncoded(text),
      ...scanHexEscape(text),
      ...scanSpacedHex(text),
      ...scanUnicodeEscape(text),
      ...scanHtmlEntities(text),
      ...scanControlTokens(text),
      ...scanInstructions(text),
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
    // instructions (encoded scans skipped — leet/delimiter norm would corrupt them).
    let deobfuscatedOnly = [];
    const { text: deobfText, indexMap: deobfIndexMap } = normalizeDeobfuscated(text);
    if (deobfText !== text) {
      const seen = new Set([
        ...rawContent.map(contentFindingKey),
        ...normalizedOnly.map(contentFindingKey),
      ]);
      const rescanned = scanInstructions(deobfText);
      deobfuscatedOnly = rescanned
        .filter((f) => !seen.has(contentFindingKey(f)))
        .map((f) => ({
          ...f,
          index:
            deobfIndexMap[f.index] !== undefined ? deobfIndexMap[f.index] : text.length,
          normalized: true,
        }));
    }

    // Spaced-letter pass: run SPACED_INSTRUCTION_PATTERNS on raw text (these
    // patterns require \s+ between every letter, so they only match genuinely
    // space-delimited obfuscation, never normal prose).
    let spacedOnly = [];
    const spacedSeen = new Set([
      ...rawContent.map(contentFindingKey),
      ...normalizedOnly.map(contentFindingKey),
      ...deobfuscatedOnly.map(contentFindingKey),
    ]);
    for (const re of SPACED_INSTRUCTION_PATTERNS) {
      const m = re.exec(text);
      if (m) {
        const f = {
          type: "instruction-phrase",
          severity: SEVERITY.LOW,
          index: m.index,
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

    return [
      ...invisible,
      ...variationSelectors,
      ...sneakyBits,
      ...combiningMarks,
      ...rawContent,
      ...normalizedOnly,
      ...deobfuscatedOnly,
      ...spacedOnly,
    ];
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
    scanVariationSelectors,
    scanSneakyBits,
    scanCombiningMarks,
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
