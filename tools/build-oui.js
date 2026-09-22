#!/usr/bin/env node
// Builds public/oui-data.json from the IEEE MAC address registries (MA-L, MA-M, MA-S).
//
//   node tools/build-oui.js            downloads the three CSVs from standards-oui.ieee.org and rebuilds
//   node tools/build-oui.js <dir>      uses oui.csv / mam.csv / oui36.csv already in <dir>
//
// Output format keeps the file small: { "Manufacturer": ["prefix", ...], ... } where a prefix is 6 hex
// characters for a 24-bit block, 7 for a 28-bit block, 9 for a 36-bit block. oui.js expands it at load time.
const fs = require('fs');
const path = require('path');
const https = require('https');

const SOURCES = [
  ['oui.csv', 'https://standards-oui.ieee.org/oui/oui.csv', 6],
  ['mam.csv', 'https://standards-oui.ieee.org/oui28/mam.csv', 7],
  ['oui36.csv', 'https://standards-oui.ieee.org/oui36/oui36.csv', 9],
];
const OUT = path.join(__dirname, '..', 'public', 'oui-data.json');

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, { headers: { 'User-Agent': 'NetDeck-build' } }, (res) => {
      if (res.statusCode !== 200) { reject(new Error(`${url}: HTTP ${res.statusCode}`)); return; }
      res.pipe(file);
      file.on('finish', () => file.close(resolve));
    }).on('error', reject);
  });
}

// One CSV row; the organisation name may be quoted and contain commas.
function parseCsvLine(line) {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

// Trailing corporate designators add nothing on a screen ("Apple, Inc." -> "Apple") and cost ~15% of the file.
const DESIGNATOR = /[\s,]+(inc\.?|incorporated|ltd\.?|limited|llc\.?|l\.l\.c\.|corp\.?|corporation|co\.?,?\s*ltd\.?|co\.|company|gmbh|s\.?a\.?|a\.?g\.?|b\.?v\.?|n\.?v\.?|pty\.?\s*ltd\.?|s\.?r\.?l\.?|s\.?p\.?a\.?|oy|ab|a\/s|k\.?k\.?|plc|s\.?a\.?s\.?|sarl|s\.?l\.?|pte\.?\s*ltd\.?|technologies co\.?)\.?$/i;
function cleanName(raw) {
  let n = raw.replace(/\s+/g, ' ').trim();
  for (let i = 0; i < 3; i++) { const m = n.replace(DESIGNATOR, ''); if (m === n || m.length < 3) break; n = m; }
  n = n.replace(/[\s,]+$/, '');
  if (/^private$/i.test(n)) n = 'Private registration';
  return n;
}

async function main() {
  const dir = process.argv[2] ? path.resolve(process.argv[2]) : fs.mkdtempSync(path.join(require('os').tmpdir(), 'netdeck-oui-'));
  const byName = new Map();
  let total = 0;
  for (const [file, url, len] of SOURCES) {
    const p = path.join(dir, file);
    if (!process.argv[2]) { process.stdout.write(`downloading ${url} … `); await download(url, p); console.log('ok'); }
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
    let n = 0;
    for (const line of lines.slice(1)) {
      if (!line.trim()) continue;
      const [, assignment, org] = parseCsvLine(line);
      const prefix = (assignment || '').toUpperCase().replace(/[^0-9A-F]/g, '');
      if (prefix.length !== len) continue;
      const name = cleanName(org || '');
      if (!name) continue;
      if (!byName.has(name)) byName.set(name, []);
      byName.get(name).push(prefix);
      n++;
    }
    console.log(`${file}: ${n} assignments`);
    total += n;
  }
  const obj = {};
  for (const name of [...byName.keys()].sort()) obj[name] = byName.get(name).sort();
  const json = JSON.stringify(obj);
  fs.writeFileSync(OUT, json);
  console.log(`wrote ${OUT}: ${total} prefixes, ${byName.size} manufacturers, ${(json.length / 1024).toFixed(0)} KB`);
}
main().catch((e) => { console.error(e.message); process.exit(1); });
