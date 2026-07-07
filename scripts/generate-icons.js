#!/usr/bin/env node
"use strict";

// Generates the toolbar icons referenced by manifest.json. Run with
// `node scripts/generate-icons.js` after changing colors/sizes below;
// there's no build step, so the PNGs are committed as static assets.

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const LEMON = [244, 220, 70];
const LEMON_SHADE = [205, 178, 45];
const LEAF = [93, 156, 68];

function smoothstep(edge0, edge1, x) {
  const t = Math.min(1, Math.max(0, (x - edge0) / (edge1 - edge0)));
  return t * t * (3 - 2 * t);
}

function renderLemon(size) {
  const pixels = new Uint8Array(size * size * 4);
  const cx = size / 2;
  const cy = size / 2 + size * 0.02;
  // A plain circle reads as an orange, so the body is an ellipse (taller
  // than wide) with the width tapered toward both ends to give it the
  // pointed nub silhouette that actually reads as a lemon.
  const rx = size * 0.32;
  const ry = size * 0.44;
  const tipScale = 0.42;
  const taperPower = 2.5;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const nx = (x + 0.5 - cx) / rx;
      const nyRaw = (y + 0.5 - cy) / ry;
      const ny = Math.max(-1, Math.min(1, nyRaw));
      const widthScale = 1 - (1 - tipScale) * Math.pow(Math.abs(ny), taperPower);
      const adjNx = nx / widthScale;
      const dist = Math.sqrt(adjNx * adjNx + nyRaw * nyRaw);
      const coverage = 1 - smoothstep(0.96, 1.04, dist);
      const i = (y * size + x) * 4;
      if (coverage <= 0) continue;

      // Subtle shading toward the bottom-right rim for a bit of depth.
      const rim = smoothstep(0.5, 1, dist);
      const color = [
        LEMON[0] + (LEMON_SHADE[0] - LEMON[0]) * rim,
        LEMON[1] + (LEMON_SHADE[1] - LEMON[1]) * rim,
        LEMON[2] + (LEMON_SHADE[2] - LEMON[2]) * rim,
      ];

      pixels[i] = color[0];
      pixels[i + 1] = color[1];
      pixels[i + 2] = color[2];
      pixels[i + 3] = Math.round(255 * coverage);
    }
  }

  // Small leaf accent at the stem tip so the silhouette reads as a lemon.
  const leafCx = cx + size * 0.05;
  const leafCy = cy - ry * 0.98;
  const leafRx = size * 0.1;
  const leafRy = size * 0.06;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const nx = (x + 0.5 - leafCx) / leafRx;
      const ny = (y + 0.5 - leafCy) / leafRy;
      const dist = Math.sqrt(nx * nx + ny * ny);
      const coverage = 1 - smoothstep(0.9, 1.1, dist);
      if (coverage <= 0) continue;
      const i = (y * size + x) * 4;
      pixels[i] = LEAF[0];
      pixels[i + 1] = LEAF[1];
      pixels[i + 2] = LEAF[2];
      pixels[i + 3] = Math.max(pixels[i + 3], Math.round(255 * coverage));
    }
  }

  return pixels;
}

function crc32(buf) {
  return zlib.crc32(buf);
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, "ascii");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crcInput = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(crcInput) >>> 0, 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePng(size, pixels) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(size, 0);
  ihdrData.writeUInt32BE(size, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 6; // color type: RGBA
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace

  const raw = Buffer.alloc(size * (1 + size * 4));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (1 + size * 4);
    raw[rowStart] = 0; // filter type: none
    Buffer.from(pixels.buffer, y * size * 4, size * 4).copy(raw, rowStart + 1);
  }
  const idatData = zlib.deflateSync(raw);

  return Buffer.concat([
    signature,
    chunk("IHDR", ihdrData),
    chunk("IDAT", idatData),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function main() {
  const outDir = path.join(__dirname, "..", "icons");
  fs.mkdirSync(outDir, { recursive: true });
  for (const size of [48, 128]) {
    const png = encodePng(size, renderLemon(size));
    const file = path.join(outDir, `icon-${size}.png`);
    fs.writeFileSync(file, png);
    console.log(`wrote ${path.relative(process.cwd(), file)} (${png.length} bytes)`);
  }
}

main();
