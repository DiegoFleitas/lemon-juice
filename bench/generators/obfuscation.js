"use strict";

/** Visible-character obfuscation: the text renders, but the words are disguised. */

// Injective on lowercase letters, so decode is exact.
const LEET_ENCODE = { e: "3", a: "4", s: "5", t: "7", o: "0", i: "1" };
const LEET_DECODE = Object.fromEntries(
  Object.entries(LEET_ENCODE).map(([k, v]) => [v, k])
);

function encodeLeet(payload) {
  return [...payload].map((ch) => LEET_ENCODE[ch] || ch).join("");
}

function decodeLeet(text) {
  return [...text].map((ch) => LEET_DECODE[ch] || ch).join("");
}

// Letters separated by single spaces, words by double spaces — the shape the
// README's example uses ("i g n o r e  a l l ..."). Using three spaces between
// words would exercise a different normalisation path and understate the
// detector, which is exactly the kind of generator bug this harness must avoid.
function encodeSpaced(payload) {
  return payload
    .split(" ")
    .map((word) => [...word].join(" "))
    .join("  ");
}

function decodeSpaced(text) {
  return text
    .split("  ")
    .map((word) => word.split(" ").join(""))
    .join(" ");
}

const HOMOGLYPH_ENCODE = {
  a: "\u0430",
  e: "\u0435",
  o: "\u043E",
  p: "\u0440",
  c: "\u0441",
  y: "\u0443",
  x: "\u0445",
  i: "\u0456",
};
const HOMOGLYPH_DECODE = Object.fromEntries(
  Object.entries(HOMOGLYPH_ENCODE).map(([k, v]) => [v, k])
);

function encodeHomoglyph(payload) {
  return [...payload].map((ch) => HOMOGLYPH_ENCODE[ch] || ch).join("");
}

function decodeHomoglyph(text) {
  return [...text].map((ch) => HOMOGLYPH_DECODE[ch] || ch).join("");
}

function encodeFullwidth(payload) {
  return [...payload]
    .map((ch) => {
      const cp = ch.codePointAt(0);
      if (cp === 0x20) return "\u3000";
      if (cp >= 0x21 && cp <= 0x7e) return String.fromCodePoint(cp + 0xfee0);
      return ch;
    })
    .join("");
}

function decodeFullwidth(text) {
  return [...text]
    .map((ch) => {
      const cp = ch.codePointAt(0);
      if (cp === 0x3000) return " ";
      if (cp >= 0xff01 && cp <= 0xff5e) return String.fromCodePoint(cp - 0xfee0);
      return ch;
    })
    .join("");
}

// Phonetic small capitals (U+1D00 block) are NOT NFKC compatibility variants,
// which is why the README lists them as a known miss. Included deliberately.
const SMALL_CAPS = {
  a: "\u1D00",
  b: "\u0299",
  c: "\u1D04",
  d: "\u1D05",
  e: "\u1D07",
  f: "\uA730",
  g: "\u0262",
  h: "\u029C",
  i: "\u026A",
  j: "\u1D0A",
  k: "\u1D0B",
  l: "\u029F",
  m: "\u1D0D",
  n: "\u0274",
  o: "\u1D0F",
  p: "\u1D18",
  q: "\u01EB",
  r: "\u0280",
  s: "\uA731",
  t: "\u1D1B",
  u: "\u1D1C",
  v: "\u1D20",
  w: "\u1D21",
  x: "x",
  y: "\u028F",
  z: "\u1D22",
};
const SMALL_CAPS_DECODE = Object.fromEntries(
  Object.entries(SMALL_CAPS)
    .filter(([k, v]) => k !== v)
    .map(([k, v]) => [v, k])
);

function encodeSmallCaps(payload) {
  return [...payload].map((ch) => SMALL_CAPS[ch] || ch).join("");
}

function decodeSmallCaps(text) {
  return [...text].map((ch) => SMALL_CAPS_DECODE[ch] || ch).join("");
}

module.exports = {
  encodeLeet,
  decodeLeet,
  encodeSpaced,
  decodeSpaced,
  encodeHomoglyph,
  decodeHomoglyph,
  encodeFullwidth,
  decodeFullwidth,
  encodeSmallCaps,
  decodeSmallCaps,
};
