#!/usr/bin/env node
// Builds both Windows installers for the current version:
//   NetDeck_<v>_x64-setup.exe          (~5 MB)   downloads WebView2 from Microsoft only if the PC lacks it
//   NetDeck_<v>_x64-offline-setup.exe  (~210 MB) carries Microsoft's full WebView2 installer, for PCs with no internet
// The offline one is the same app built with src-tauri/tauri.offline.conf.json merged in. Both land in
// src-tauri/target/release/bundle/nsis/.
//   node tools/build-installers.js                 both installers
//   node tools/build-installers.js --normal-only   just the everyday one
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { version } = require(path.join(ROOT, 'package.json'));
const DIR = path.join(ROOT, 'src-tauri', 'target', 'release', 'bundle', 'nsis');
const setup = path.join(DIR, `NetDeck_${version}_x64-setup.exe`);
const offline = path.join(DIR, `NetDeck_${version}_x64-offline-setup.exe`);
const held = `${setup}.normal`;
const mb = (f) => `${(fs.statSync(f).size / 1048576).toFixed(1)} MB`;
const tauri = (extra = '') => execSync(`npx @tauri-apps/cli@^2 build${extra}`, { cwd: ROOT, stdio: 'inherit' });

tauri();
if (!fs.existsSync(setup)) throw new Error(`build finished but ${setup} is missing`);
if (!process.argv.includes('--normal-only')) {
  // both builds write the same file name, so park the normal installer while the offline one builds
  fs.renameSync(setup, held);
  try {
    tauri(` --config "${path.join(ROOT, 'src-tauri', 'tauri.offline.conf.json')}"`);
    fs.renameSync(setup, offline);
  } finally {
    fs.renameSync(held, setup);
  }
}
console.log(`\nInstallers for ${version}:`);
console.log(`  ${path.relative(ROOT, setup)}  ${mb(setup)}`);
if (fs.existsSync(offline)) console.log(`  ${path.relative(ROOT, offline)}  ${mb(offline)}`);
