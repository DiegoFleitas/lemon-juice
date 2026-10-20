"use strict";

/**
 * Encoding-based smuggling vectors. Every encoder ships with a decoder and the
 * runner asserts decode(encode(x)) === x before scoring, so a false negative is
 * attributable to the detector and not to a broken generator.
 */

const TAG_BASE = 0xe0000;

function encodeTags(payload) {
  let out = "";
  for (const ch of payload) {
    const cp = ch.codePointAt(0);
    if (cp < 0x20 || cp > 0x7e) throw new Error("tags: ASCII only");
    out += String.fromCodePoint(TAG_BASE + cp);
  }
  return out;
}

function decodeTags(text) {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCodePoint(cp - TAG_BASE);
  }
  return out;
}

// Variation selectors carry one byte each: VS1-16 -> 0-15, VS17-256 -> 16-255.
function encodeVariation(payload) {
  const bytes = [...Buffer.from(payload, "utf8")];
  return bytes
    .map((b) =>
      b < 16 ? String.fromCodePoint(0xfe00 + b) : String.fromCodePoint(0xe0100 + (b - 16))
    )
    .join("");
}

function decodeVariation(text) {
  const bytes = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00);
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16);
  }
  try {
    return Buffer.from(bytes).toString("utf8");
  } catch {
    return "";
  }
}

// Sneaky Bits: U+2062 = bit 0, U+2064 = bit 1, MSB-first, 8 bits per byte.
function encodeSneakyBits(payload) {
  let out = "";
  for (const byte of Buffer.from(payload, "utf8")) {
    for (let k = 7; k >= 0; k--) {
      out += String.fromCodePoint((byte >> k) & 1 ? 0x2064 : 0x2062);
    }
  }
  return out;
}

function decodeSneakyBits(text) {
  const bits = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === 0x2062) bits.push(0);
    else if (cp === 0x2064) bits.push(1);
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let k = 0; k < 8; k++) b = (b << 1) | bits[i + k];
    bytes.push(b);
  }
  return Buffer.from(bytes).toString("utf8");
}

function encodeBase64(payload) {
  return Buffer.from(payload, "utf8").toString("base64");
}

function decodeBase64(text) {
  const m = text.match(/[A-Za-z0-9+/]{16,}={0,2}/);
  return m ? Buffer.from(m[0], "base64").toString("utf8") : "";
}

// Percent-encode every byte, not just unsafe characters: a payload of plain
// letters passed through encodeURIComponent is not hidden at all.
function encodePercent(payload) {
  return [...Buffer.from(payload, "utf8")]
    .map((b) => "%" + b.toString(16).padStart(2, "0").toUpperCase())
    .join("");
}

function decodePercent(text) {
  const bytes = [];
  for (const m of text.matchAll(/%([0-9A-Fa-f]{2})/g)) bytes.push(parseInt(m[1], 16));
  return Buffer.from(bytes).toString("utf8");
}

function encodeHexEscapes(payload) {
  return [...Buffer.from(payload, "utf8")]
    .map((b) => "\\x" + b.toString(16).padStart(2, "0"))
    .join("");
}

function decodeHexEscapes(text) {
  const bytes = [];
  for (const m of text.matchAll(/\\x([0-9A-Fa-f]{2})/g)) bytes.push(parseInt(m[1], 16));
  return Buffer.from(bytes).toString("utf8");
}

module.exports = {
  encodeTags,
  decodeTags,
  encodeVariation,
  decodeVariation,
  encodeSneakyBits,
  decodeSneakyBits,
  encodeBase64,
  decodeBase64,
  encodePercent,
  decodePercent,
  encodeHexEscapes,
  decodeHexEscapes,
};
