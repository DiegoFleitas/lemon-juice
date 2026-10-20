"use strict";

const enc = require("./encoding");
const inv = require("./invisible");
const obf = require("./obfuscation");

/**
 * Each technique: { id, category, note, make(payload) -> { text, decoded } }
 * `decoded` must equal the original payload (asserted by the runner), so any
 * miss is the detector's, not the generator's.
 */
const TECHNIQUES = [
  {
    id: "plain",
    category: "plain-control",
    note: "Instruction text in the open, no hiding. Informational by design.",
    make: (p) => ({ text: p, decoded: p }),
  },
  {
    id: "tags",
    category: "unicode-tags",
    note: "ASCII smuggled in the Unicode Tags block.",
    make: (p) => ({
      text: enc.encodeTags(p),
      decoded: enc.decodeTags(enc.encodeTags(p)),
    }),
  },
  {
    id: "zero-width",
    category: "zero-width",
    note: "ZWSP inserted between every character.",
    make: (p) => ({
      text: inv.encodeZeroWidth(p),
      decoded: inv.decodeZeroWidth(inv.encodeZeroWidth(p)),
    }),
  },
  {
    id: "bidi",
    category: "bidi-controls",
    note: "Payload wrapped in RLO/PDF (Trojan Source family).",
    make: (p) => ({
      text: inv.encodeBidi(p),
      decoded: inv.decodeBidi(inv.encodeBidi(p)),
    }),
  },
  {
    id: "leet",
    category: "leetspeak",
    note: "e→3, a→4, s→5, t→7, o→0, i→1.",
    make: (p) => ({
      text: obf.encodeLeet(p),
      decoded: obf.decodeLeet(obf.encodeLeet(p)),
    }),
  },
  {
    id: "spaced",
    category: "spaced-letters",
    note: "Letters separated by spaces, words by three spaces.",
    make: (p) => ({
      text: obf.encodeSpaced(p),
      decoded: obf.decodeSpaced(obf.encodeSpaced(p)),
    }),
  },
  {
    id: "homoglyph",
    category: "homoglyphs",
    note: "Latin letters swapped for Cyrillic lookalikes.",
    make: (p) => ({
      text: obf.encodeHomoglyph(p),
      decoded: obf.decodeHomoglyph(obf.encodeHomoglyph(p)),
    }),
  },
  {
    id: "fullwidth",
    category: "fullwidth-nfkc",
    note: "Fullwidth forms; NFKC should fold these.",
    make: (p) => ({
      text: obf.encodeFullwidth(p),
      decoded: obf.decodeFullwidth(obf.encodeFullwidth(p)),
    }),
  },
  {
    id: "small-caps",
    category: "small-caps",
    note: "Phonetic small capitals; not NFKC-compatible. README lists this as a known miss.",
    make: (p) => ({
      text: obf.encodeSmallCaps(p),
      decoded: obf.decodeSmallCaps(obf.encodeSmallCaps(p)),
    }),
  },
  {
    id: "base64",
    category: "base64",
    note: "Whole payload base64-encoded inline.",
    make: (p) => ({
      text: enc.encodeBase64(p),
      decoded: enc.decodeBase64(enc.encodeBase64(p)),
    }),
  },
  {
    id: "percent",
    category: "percent-encoded",
    note: "Every byte percent-encoded.",
    make: (p) => ({
      text: enc.encodePercent(p),
      decoded: enc.decodePercent(enc.encodePercent(p)),
    }),
  },
  {
    id: "hex",
    category: "hex-escapes",
    note: "Every byte as \\xNN.",
    make: (p) => ({
      text: enc.encodeHexEscapes(p),
      decoded: enc.decodeHexEscapes(enc.encodeHexEscapes(p)),
    }),
  },
  {
    id: "variation",
    category: "variation-selectors",
    note: "UTF-8 bytes carried by variation selectors (VS1-16 / VS17-256).",
    make: (p) => ({
      text: enc.encodeVariation(p),
      decoded: enc.decodeVariation(enc.encodeVariation(p)),
    }),
  },
  {
    id: "sneaky-bits",
    category: "sneaky-bits",
    note: "Bits encoded as U+2062 (0) / U+2064 (1), MSB-first.",
    make: (p) => ({
      text: enc.encodeSneakyBits(p),
      decoded: enc.decodeSneakyBits(enc.encodeSneakyBits(p)),
    }),
  },
];

module.exports = { TECHNIQUES };
