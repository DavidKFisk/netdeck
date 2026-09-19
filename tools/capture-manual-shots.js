// Drive a headless browser against the running NetDeck, run every playbook, and capture its result pane.
//   node tools/capture-manual-shots.js <debug-port> [playbook-id ...]     (no ids = everything, plus the overview)
// Output: public/manual-img/*.webp (shipped) and %TEMP%/netdeck-shots/*.png (for review).
// Identifying values are anonymised in the page before each capture.
const fs = require('fs');
const path = require('path');

const PORT = Number(process.argv[2] || 9333);
const APP = 'http://localhost:4573/';
const OUT = path.join(__dirname, '..', 'public', 'manual-img');
const REVIEW = path.join(require('os').tmpdir(), 'netdeck-shots'); // PNG copies for eyeballing
fs.mkdirSync(OUT, { recursive: true });
fs.mkdirSync(REVIEW, { recursive: true });

const RUNS = [
  { id: 'internet' }, { id: 'website', vals: { host: 'github.com' } }, { id: 'slow' },
  { id: 'path', vals: { host: '1.1.1.1' }, openTable: 1 }, { id: 'port', vals: { host: '127.0.0.1', port: '9' } },
  { id: 'services', vals: { host: 'github.com' } }, { id: 'mtu' }, { id: 'wifi' },
  { id: 'dns' }, { id: 'propagation', vals: { host: 'example.com' } }, { id: 'email', vals: { host: 'google.com' } },
  { id: 'exposure' }, { id: 'outbound' }, { id: 'proxy' },
  { id: 'pchealth' }, { id: 'timesync' }, { id: 'routing' }, { id: 'dhcp' }, { id: 'lan', openTable: 1 }, { id: 'ipv6' },
  { id: 'scan', openTable: 0 },
];
const ONLY = process.argv.slice(3);
const SELECTED = ONLY.length ? RUNS.filter((r) => ONLY.includes(r.id)) : RUNS;

const SCRUB = `(() => {
  const host = (document.querySelector('[data-ctx="hostname"]')?.textContent || '').trim();
  const allow = [/^1\\.1\\.1\\.1$/, /^1\\.0\\.0\\.1$/, /^8\\.8\\.8\\.8$/, /^8\\.8\\.4\\.4$/, /^9\\.9\\.9\\.9$/, /^140\\.82\\./, /^127\\./, /^0\\.0\\.0\\.0$/, /^255\\./, /^22[4-9]\\./, /^23\\d\\./, /^203\\.0\\.113\\./];
  const isPrivate = (ip) => { const [a, b] = ip.split('.').map(Number); return a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127); };
  window.__ipMap = window.__ipMap || new Map();
  const mapIp = (ip) => { if (isPrivate(ip) || allow.some((r) => r.test(ip))) return ip; if (!window.__ipMap.has(ip)) window.__ipMap.set(ip, '203.0.113.' + (10 + window.__ipMap.size)); return window.__ipMap.get(ip); };
  // Device names found by a scan can be personal ("Anna's iPhone"): replace every value in a table's Name column.
  window.__nameMap = window.__nameMap || new Map();
  document.querySelectorAll('table.data-table').forEach((tbl) => {
    const idx = [...tbl.querySelectorAll('th')].findIndex((th) => th.textContent.trim() === 'Name');
    if (idx === -1) return;
    tbl.querySelectorAll('tbody tr').forEach((tr) => {
      const cell = tr.children[idx];
      const v = cell && cell.textContent.trim();
      if (!v || v === host) return;
      if (!window.__nameMap.has(v)) window.__nameMap.set(v, 'device-' + (1 + window.__nameMap.size) + '.lan');
    });
  });
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const n of nodes) {
    let t = n.nodeValue;
    if (!t || !t.trim()) continue;
    const before = t;
    if (host) t = t.split(host).join('OFFICE-PC').split(host.toLowerCase()).join('office-pc');
    window.__nameMap.forEach((alias, name) => { t = t.split(name).join(alias); });
    t = t.replace(/\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b/g, (m) => mapIp(m));
    t = t.replace(/\\b([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}\\b/gi, '$1-xx-xx-xx');
    t = t.replace(/\\bfd[0-9a-f]{2}:[0-9a-f:]{8,}/gi, 'fd12:3456:789a::1f');
    if (t !== before) n.nodeValue = t;
  }
  return window.__ipMap.size;
})()`;

const CAPTURE_CSS = `
  .topbar, .context-strip, .filters, main { display: none !important; }
  body { padding: 0 !important; }
  .terminal { position: static !important; height: auto !important; border-top: none !important; }
  .terminal-body { display: block !important; }
  .history-panel { display: none !important; }
  .panes { display: block !important; overflow: visible !important; }
  .pane { overflow: visible !important; }
  .pane[hidden] { display: none !important; }
  .pane-playbook { overflow: visible !important; padding-bottom: 18px !important; }
  .pb-tablewrap { max-height: none !important; }
  .table-scroll { overflow: visible !important; }
`;

(async () => {
  let targets = [];
  for (let i = 0; i < 40 && !targets.some((t) => t.type === 'page'); i++) {
    try { targets = await fetch(`http://127.0.0.1:${PORT}/json`).then((r) => r.json()); } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  const page = targets.find((t) => t.type === 'page');
  if (!page) { console.log('NO_PAGE'); process.exit(1); }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const pending = new Map();
  ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  const evalJs = async (expression) => { const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 400)); return r.result?.result?.value; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const shoot = async (name, clip) => {
    for (const [fmt, dir, ext, quality] of [['webp', OUT, 'webp', 82], ['png', REVIEW, 'png', undefined]]) {
      const r = await send('Page.captureScreenshot', { format: fmt, quality, clip: clip ? { ...clip, scale: 1 } : undefined, captureBeyondViewport: true });
      fs.writeFileSync(path.join(dir, `${name}.${ext}`), Buffer.from(r.result.data, 'base64'));
    }
    const kb = Math.round(fs.statSync(path.join(OUT, `${name}.webp`)).size / 1024);
    console.log(`  saved ${name}.webp (${kb} KB)`);
  };

  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: 900, height: 1000, deviceScaleFactor: 1.5, mobile: false });
  await send('Page.navigate', { url: APP });
  await sleep(1500);
  await evalJs(`(async () => { for (let i = 0; i < 80 && !document.querySelector('#grid .card'); i++) await new Promise(r => setTimeout(r, 250)); await new Promise(r => setTimeout(r, 2500)); document.querySelector('.vtab[data-view="playbooks"]').click(); return true; })()`);

  // 1. Overview of the grouped Playbooks page (skipped when specific playbooks were asked for).
  await evalJs(SCRUB);
  if (!ONLY.length || ONLY.includes('overview')) await shoot('playbooks-overview', { x: 0, y: 0, width: 900, height: 1000 });

  // 2. One result pane per playbook.
  for (const run of SELECTED) {
    console.log(`running ${run.id}…`);
    const started = Date.now();
    const state = await evalJs(`(async () => {
      const c = document.querySelector('.card[data-pb="${run.id}"]');
      const vals = ${JSON.stringify(run.vals || {})};
      for (const [k, v] of Object.entries(vals)) c.querySelector('#pb-${run.id}-' + k).value = v;
      c.querySelector('.run-btn').click();
      for (let i = 0; i < 800; i++) { if (document.querySelector('.pane:not([hidden]) .pb-verdict:not([hidden])')) break; await new Promise(r => setTimeout(r, 250)); }
      const pane = document.querySelector('.pane:not([hidden])');
      const openTable = ${run.openTable ?? -1};
      if (openTable >= 0) { const b = pane.querySelectorAll('.pb-step')[openTable]?.querySelector('.pb-table-btn'); if (b && !b.hidden) { b.click(); await new Promise(r => setTimeout(r, 1200)); } }
      return pane.querySelector('.pb-verdict')?.dataset.tone || 'no-verdict';
    })()`);
    await send('Runtime.evaluate', { expression: `(() => { const s = document.createElement('style'); s.id = '__cap'; s.textContent = ${JSON.stringify(CAPTURE_CSS)}; document.head.appendChild(s); })()` });
    await evalJs(SCRUB);
    await sleep(300);
    const rect = await evalJs(`(() => { const r = document.getElementById('terminal').getBoundingClientRect(); return { x: 0, y: Math.max(0, r.top + scrollY), width: 900, height: Math.ceil(r.height) }; })()`);
    await shoot(`pb-${run.id}`, rect);
    console.log(`  ${run.id}: ${state} in ${((Date.now() - started) / 1000).toFixed(0)} s, ${rect.height}px tall`);
    await evalJs(`(() => { document.getElementById('__cap')?.remove(); document.getElementById('term-close-all').click(); return true; })()`);
  }
  console.log('ALL_DONE');
  ws.close();
})().catch((e) => { console.log('CAPTURE_ERROR', e.message); process.exit(1); });
