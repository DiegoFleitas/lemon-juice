"use strict";

/** Invisible-character and bidi-control concealment. */

const ZWSP = "\u200B";
const RLO = "\u202E";
const PDF = "\u202C";
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;
const ALL_INVISIBLE = /[\u200B-\u200D\u2060\uFEFF\u00AD\u061C\u180E\u200E\u200F]/g;

function encodeZeroWidth(payload) {
  return [...payload].join(ZWSP);
}

function decodeZeroWidth(text) {
  return text.replace(ALL_INVISIBLE, "").split(ZWSP).join("");
}

function encodeBidi(payload) {
  return RLO + payload + PDF;
}

function decodeBidi(text) {
  return text.replace(BIDI_CONTROLS, "");
}

module.exports = { encodeZeroWidth, decodeZeroWidth, encodeBidi, decodeBidi };
