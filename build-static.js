// Build the hosted (static) version of NetDeck into ./dist — plain files for any web host.
//   node build-static.js
// The result is the full reference (search, playbooks as steps, manual, cheat sheet, pins,
// links, custom commands) with execution off; a visitor can pair it with a NetDeck server
// running on their own machine (see README → Hosting).
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const OUT = path.join(ROOT, 'dist');
const STATIC_FLAG = '<script>window.NETDECK_STATIC = true;</script>';

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

for (const file of fs.readdirSync(path.join(ROOT, 'public'))) {
  const src = path.join(ROOT, 'public', file);
  if (fs.statSync(src).isDirectory()) {
    // asset folders (manual screenshots) are copied as they are
    fs.cpSync(src, path.join(OUT, file), { recursive: true });
    continue;
  }
  let content = fs.readFileSync(src);
  if (file.endsWith('.html')) {
    // Flag every page as static before any of its own scripts run.
    content = Buffer.from(content.toString('utf8').replace(/<title>/, `${STATIC_FLAG}\n  <title>`));
  }
  fs.writeFileSync(path.join(OUT, file), content);
}
fs.copyFileSync(path.join(ROOT, 'commands.json'), path.join(OUT, 'commands.json'));

// Common static-host conveniences: SPA-style 404 fallback and no-cache for the data file.
fs.copyFileSync(path.join(OUT, 'index.html'), path.join(OUT, '404.html'));
fs.writeFileSync(path.join(OUT, '_headers'), '/commands.json\n  Cache-Control: no-cache\n');

const files = fs.readdirSync(OUT);
console.log(`Static build written to ${OUT} (${files.length} files):`);
console.log('  ' + files.join('\n  '));
console.log('\nUpload the dist/ folder to any static host (Netlify, Cloudflare Pages, GitHub Pages, S3, nginx).');
