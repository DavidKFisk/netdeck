#!/usr/bin/env node
// Keeps every <img> in public/manual.html sized to its file: reads each manual-img/*.webp's real pixel size and
// rewrites the width/height attributes, so a re-captured screenshot never lays out at its old height.
//
//   node tools/figure-dims.js          rewrite; prints what changed
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const manual = path.join(root, 'public', 'manual.html');

function webpSize(file) {
  const b = fs.readFileSync(file);
  const tag = b.toString('ascii', 12, 16);
  if (tag === 'VP8 ') return [b.readUInt16LE(26) & 0x3fff, b.readUInt16LE(28) & 0x3fff];
  if (tag === 'VP8L') { const bits = b.readUInt32LE(21); return [(bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1]; }
  if (tag === 'VP8X') return [b.readUIntLE(24, 3) + 1, b.readUIntLE(27, 3) + 1];
  throw new Error(`${file}: not a WebP I understand (${tag})`);
}

let html = fs.readFileSync(manual, 'utf8');
let changed = 0, missing = 0;
html = html.replace(/<img src="(manual-img\/[^"]+\.webp)" width="(\d+)" height="(\d+)"/g, (whole, src, w, h) => {
  const file = path.join(root, 'public', src);
  if (!fs.existsSync(file)) { missing++; console.log(`  missing: ${src}`); return whole; }
  const [rw, rh] = webpSize(file);
  if (String(rw) === w && String(rh) === h) return whole;
  changed++;
  console.log(`  ${src}: ${w}x${h} -> ${rw}x${rh}`);
  return `<img src="${src}" width="${rw}" height="${rh}"`;
});
fs.writeFileSync(manual, html);
console.log(`${changed} figure${changed === 1 ? '' : 's'} resized, ${missing} missing`);
