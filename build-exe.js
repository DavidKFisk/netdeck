// Package NetDeck as a single executable with Node's single-executable-application (SEA) support.
//   node build-exe.js
// Produces build/netdeck.exe (Windows) or build/netdeck (Linux/macOS) that runs with no Node install.
// Needs: Node 20+, and `postject` (fetched once via npx — the only build-time dependency).
const fs = require('fs');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const ROOT = __dirname;
const BUILD = path.join(ROOT, 'build');
const IS_WIN = process.platform === 'win32';
const exeName = IS_WIN ? 'netdeck.exe' : 'netdeck';
const exePath = path.join(BUILD, exeName);
const blobPath = path.join(BUILD, 'netdeck.blob');
const seaConfigPath = path.join(BUILD, 'sea-config.json');

fs.rmSync(BUILD, { recursive: true, force: true });
fs.mkdirSync(BUILD, { recursive: true });

// Every file the server reads at runtime goes in as an asset, keyed by its repo-relative path.
const assets = { 'commands.json': path.join(ROOT, 'commands.json') };
const addAssets = (dir, prefix) => {
  for (const file of fs.readdirSync(dir)) {
    const p = path.join(dir, file);
    if (fs.statSync(p).isDirectory()) addAssets(p, `${prefix}/${file}`);
    else assets[`${prefix}/${file}`] = p;
  }
};
addAssets(path.join(ROOT, 'public'), 'public');

fs.writeFileSync(seaConfigPath, JSON.stringify({
  main: path.join(ROOT, 'server.js'),
  output: blobPath,
  disableExperimentalSEAWarning: true,
  useCodeCache: false,
  assets,
}, null, 2));

// Direct execution for node itself; npx is a .cmd on Windows and needs a shell, so quote for it.
const run = (cmd, args) => {
  console.log(`> ${cmd} ${args.join(' ')}`);
  return execFileSync(cmd, args, { stdio: 'inherit' });
};
const runShell = (cmd, args) => {
  const quote = (s) => (/[\s"]/.test(s) ? `"${s.replace(/"/g, '\\"')}"` : s);
  const line = [cmd, ...args].map(quote).join(' ');
  console.log(`> ${line}`);
  return execSync(line, { stdio: 'inherit' });
};

run(process.execPath, ['--experimental-sea-config', seaConfigPath]);
fs.copyFileSync(process.execPath, exePath);

const postjectArgs = [exePath, 'NODE_SEA_BLOB', blobPath, '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'];
if (process.platform === 'darwin') postjectArgs.push('--macho-segment-name', 'NODE_SEA');
runShell(IS_WIN ? 'npx.cmd' : 'npx', ['--yes', 'postject@1.0.0-alpha.6', ...postjectArgs]);

if (process.platform === 'darwin') {
  try { run('codesign', ['--sign', '-', exePath]); } catch { console.log('(codesign skipped)'); }
}
fs.rmSync(blobPath, { force: true });
fs.rmSync(seaConfigPath, { force: true });

const size = (fs.statSync(exePath).size / 1048576).toFixed(1);
console.log(`\nBuilt ${exePath} (${size} MB). Run it with --open to launch the browser; custom-commands.json is kept next to the executable.`);
