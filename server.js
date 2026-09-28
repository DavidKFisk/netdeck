// NetDeck — local command-reference server with live command execution.
// Zero runtime dependencies. Serves ./public and streams whitelisted command output.
//
//   node server.js [--port 4573] [--open]
//   NETDECK_ORIGIN=https://netdeck.example.com   allow a hosted copy of the page to connect (prints a token)
//   NETDECK_TOKEN=...                            fix the pairing token instead of generating one
//   NETDECK_DATA=<dir>                           where custom-commands.json lives (default: next to the app)
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

// ---------- single-executable support: assets come from the binary when packaged ----------
const sea = (() => {
  try {
    const s = require('node:sea');
    return s.isSea() ? s : null;
  } catch {
    return null;
  }
})();

function readAsset(rel) {
  if (sea) return Buffer.from(sea.getAsset(rel.replace(/\\/g, '/')));
  return fs.readFileSync(path.join(__dirname, rel));
}

function assetExists(rel) {
  if (sea) {
    try { sea.getAsset(rel.replace(/\\/g, '/')); return true; } catch { return false; }
  }
  return fs.existsSync(path.join(__dirname, rel));
}

const args = process.argv.slice(2);
const argValue = (flag) => { const i = args.indexOf(flag); return i !== -1 ? args[i + 1] : undefined; };
const PORT = Number(argValue('--port') || process.env.PORT || 4573);
// A double-clicked executable has no arguments and no terminal to read — open the browser for it.
const OPEN_BROWSER = args.includes('--open') || (sea && args.length === 0);

// Keep a double-clicked console window open long enough to read a fatal error.
function holdConsoleThenExit(code) {
  if (!sea || !process.stdin.isTTY) process.exit(code);
  console.log('\nPress Enter to close this window.');
  process.stdin.resume();
  process.stdin.once('data', () => process.exit(code));
}

process.on('uncaughtException', (err) => {
  console.error(`\nNetDeck stopped: ${err.stack || err.message}`);
  holdConsoleThenExit(1);
});
const DATA_DIR = process.env.NETDECK_DATA || (sea ? path.dirname(process.execPath) : __dirname);
const CUSTOM_FILE = path.join(DATA_DIR, 'custom-commands.json');
const ALLOWED_ORIGIN = (process.env.NETDECK_ORIGIN || '').replace(/\/$/, '');
const TOKEN = process.env.NETDECK_TOKEN || crypto.randomBytes(12).toString('hex');

const PLATFORM = process.platform; // 'win32' | 'linux' | 'darwin'
const IS_WIN = PLATFORM === 'win32';
const RUN_TIMEOUT_MS = 3 * 60 * 1000;

const BUILTIN = JSON.parse(readAsset('commands.json').toString('utf8'));
let CUSTOM = loadCustom();
let COMMANDS = [...BUILTIN, ...CUSTOM];
let BY_ID = new Map(COMMANDS.map((c) => [c.id, c]));

function loadCustom() {
  try {
    const list = JSON.parse(fs.readFileSync(CUSTOM_FILE, 'utf8'));
    return Array.isArray(list) ? list.filter((c) => c && typeof c.id === 'string' && c.id.startsWith('custom-')) : [];
  } catch {
    return [];
  }
}

function saveCustom() {
  fs.writeFileSync(CUSTOM_FILE, JSON.stringify(CUSTOM, null, 2));
  COMMANDS = [...BUILTIN, ...CUSTOM];
  BY_ID = new Map(COMMANDS.map((c) => [c.id, c]));
}

// Param validators: only these shapes ever reach a spawned process.
const VALIDATORS = {
  // Letters, digits, dot, hyphen and underscore (DNS service labels such as _dmarc). Nothing a shell could use — and no shell is involved anyway.
  host: (v) => typeof v === 'string' && /^[A-Za-z0-9_]([A-Za-z0-9._\-]{0,251}[A-Za-z0-9])?$/.test(v),
  port: (v) => /^\d{1,5}$/.test(String(v)) && +v >= 1 && +v <= 65535,
  url: (v) => {
    if (typeof v !== 'string' || v.length > 2048 || /["'\s`$;&|<>]/.test(v)) return false;
    try {
      const u = new URL(v);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  },
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const rel = path.posix.normalize('public/' + (urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '')));
  if (!rel.startsWith('public/') || rel.includes('..')) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  if (!assetExists(rel)) {
    res.writeHead(404).end('Not found');
    return;
  }
  // no-cache: always revalidate, so an upgraded NetDeck never runs last version's scripts.
  res.writeHead(200, { 'Content-Type': MIME[path.extname(rel)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  res.end(readAsset(rel));
}

// ---------- request authorization ----------
// Same-origin page: needs the X-NetDeck header (blocks CSRF — browsers can't add it cross-origin
// without a preflight, and we only answer preflights for ALLOWED_ORIGIN).
// Hosted page (ALLOWED_ORIGIN): additionally needs the pairing token.
const isLocalOrigin = (o) => /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o);

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-NetDeck, X-NetDeck-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Max-Age', '600');
    res.setHeader('Vary', 'Origin');
    return true;
  }
  return false;
}

function authorized(req) {
  const origin = req.headers.origin;
  if (!origin || isLocalOrigin(origin)) return req.headers['x-netdeck'] === '1';
  if (ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN) {
    const given = req.headers['x-netdeck-token'] || '';
    return req.headers['x-netdeck'] === '1' && given.length === TOKEN.length && crypto.timingSafeEqual(Buffer.from(given), Buffer.from(TOKEN));
  }
  return false;
}

// ---------- platform-specific run specs ----------
function runSpecFor(cmd) {
  if (!cmd.safe) return null;
  if (IS_WIN) return cmd.run || null;
  const spec = cmd.runUnix;
  if (!spec) return null;
  return PLATFORM === 'darwin' && spec.darwin ? { ...spec, ...spec.darwin, darwin: undefined } : spec;
}

function helpSpecFor(cmd) {
  const h = IS_WIN ? cmd.help : cmd.helpUnix;
  if (!h) return null;
  if (Array.isArray(h)) return { kind: 'exe', exe: h[0], args: h.slice(1) };
  if (h.ps && IS_WIN) return { kind: 'ps', command: `Get-Help ${h.ps} -Detailed` };
  return null;
}

// ---------- network context (gateway, DNS, local IP, admin) ----------
const CONTEXT_SCRIPT = `
$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric, InterfaceMetric)
$r = $null; $ip = $null; $dns = @()
# A default route can outrank the working one while its adapter only holds a tentative
# APIPA address (cable in, DHCP failed). Pick the first route whose adapter is really up.
foreach ($cand in $routes) {
  $a = @(Get-NetIPAddress -InterfaceIndex $cand.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.AddressState -eq 'Preferred' })
  if ($a.Count) { $r = $cand; $ip = $a[0].IPAddress; break }
}
if (-not $r -and $routes.Count) { $r = $routes[0] }
if ($r) {
  $dns = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
[pscustomobject]@{ gateway = $r.NextHop; adapter = $r.InterfaceAlias; ip = $ip; dns = $dns; admin = $admin } | ConvertTo-Json -Compress
`;

let contextCache = null;

function localIpv4(adapterName) {
  const ifaces = os.networkInterfaces();
  const names = adapterName ? [adapterName, ...Object.keys(ifaces)] : Object.keys(ifaces);
  for (const name of names) {
    const v4 = (ifaces[name] || []).find((a) => a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.'));
    if (v4) return { ip: v4.address, adapter: name };
  }
  return { ip: null, adapter: adapterName || null };
}

function fallbackContext() {
  return { gateway: null, dns: [], admin: false, partial: true, ...localIpv4(null) };
}

function ps(script, cb) {
  execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 20000 }, cb);
}

function getContextWindows() {
  return new Promise((resolve) => {
    ps(CONTEXT_SCRIPT, (err, stdout) => {
      try {
        if (err) throw err;
        const ctx = JSON.parse(stdout.trim());
        if (!Array.isArray(ctx.dns)) ctx.dns = ctx.dns ? [ctx.dns] : [];
        if (!ctx.ip) Object.assign(ctx, localIpv4(ctx.adapter));
        resolve(ctx);
      } catch {
        resolve(fallbackContext());
      }
    });
  });
}

function getContextUnix() {
  return new Promise((resolve) => {
    const finish = (gateway, adapter) => {
      let dns = [];
      try {
        dns = fs.readFileSync('/etc/resolv.conf', 'utf8').split('\n')
          .map((l) => l.match(/^\s*nameserver\s+(\S+)/)).filter(Boolean).map((m) => m[1]);
      } catch { /* no resolv.conf */ }
      const admin = typeof process.getuid === 'function' && process.getuid() === 0;
      resolve({ gateway, dns, admin, ...localIpv4(adapter) });
    };
    if (PLATFORM === 'darwin') {
      execFile('route', ['-n', 'get', 'default'], { timeout: 10000 }, (err, out) => {
        const gw = out?.match(/gateway:\s+(\S+)/)?.[1] || null;
        const iface = out?.match(/interface:\s+(\S+)/)?.[1] || null;
        finish(err ? null : gw, iface);
      });
    } else {
      execFile('ip', ['route', 'show', 'default'], { timeout: 10000 }, (err, out) => {
        const m = out?.match(/default via (\S+) dev (\S+)/);
        finish(err ? null : m?.[1] || null, m?.[2] || null);
      });
    }
  });
}

function getContext(refresh) {
  if (contextCache && !refresh) return Promise.resolve(contextCache);
  return (IS_WIN ? getContextWindows() : getContextUnix()).then((ctx) => {
    ctx.hostname = os.hostname();
    ctx.platform = PLATFORM;
    // So the page can give accurate "how to run as admin" steps for this particular install.
    ctx.packaged = Boolean(sea);
    ctx.appDir = sea ? path.dirname(process.execPath) : __dirname;
    ctx.fetchedAt = Date.now();
    contextCache = ctx;
    return ctx;
  });
}

// ---------- health: one ping each to the gateway and the internet ----------
function pingOnce(host) {
  return new Promise((resolve) => {
    if (!host) return resolve(null);
    const pingArgs = IS_WIN ? ['-n', '1', '-w', '1500', host]
      : PLATFORM === 'darwin' ? ['-c', '1', '-W', '1500', host] : ['-c', '1', '-W', '2', host];
    execFile('ping', pingArgs, { windowsHide: true, timeout: 5000 }, (err, stdout) => {
      const m = String(stdout || '').match(/time[=<]\s?([\d.]+)\s?ms/i);
      resolve(!err && m ? Math.max(0.5, parseFloat(m[1])) : null);
    });
  });
}

async function handleHealth(req, res) {
  const ctx = await getContext(false);
  const [gateway, internet] = await Promise.all([pingOnce(ctx.gateway), pingOnce('1.1.1.1')]);
  json(res, 200, { t: Date.now(), gateway, internet, gatewayHost: ctx.gateway });
}


// ---------- connection watcher: outage log + network sensors. Mirrors src-tauri/src/outage.rs (same rules, same
// shapes; no tray here). Pings the router and the internet every 5 s while the outage log is on, and every 2 s while
// a sensors view polls (/api/sensors keeps that going for 12 s). An outage is no internet reply for about 10 s or
// longer; shorter is a blip. NETDECK_OUTAGE_TEST=<file>: see outage.rs.
const OUTAGE_FILE = path.join(DATA_DIR, 'outage-log.json');
const OUTAGE = { interval: 5000, liveInterval: 2000, liveHold: 12000, gap: 20000, grace: 60000, downMs: 10000, keep: 90 * 864e5, ctxEvery: 600000, saveEvery: 60000, ring: 900 };
const OUTAGE_LAYERS = ['isp', 'lan', 'offline', 'unknown'];
/* alerts: internet ping above limit ms for secs, router ping likewise, internet loss above limit % over the last
   minute, no internet reply for secs — the same rules and defaults as outage.rs */
const ALERT_RULES = ['ping', 'router', 'loss', 'down'];
const ALERT_DEFAULTS = { ping: { on: false, limit: 150, secs: 30 }, router: { on: false, limit: 50, secs: 30 }, loss: { on: false, limit: 2, secs: 60 }, down: { on: false, limit: 0, secs: 20 } };
const clampN = (v, lo, hi, d) => (Number.isFinite(+v) ? Math.min(hi, Math.max(lo, +v)) : d);
function alertsSane(a) {
  const r = (k, lo, hi, slo, shi) => ({ on: Boolean(a[k] && a[k].on), limit: clampN(a[k] && a[k].limit, lo, hi, ALERT_DEFAULTS[k].limit), secs: clampN(a[k] && a[k].secs, slo, shi, ALERT_DEFAULTS[k].secs) });
  return { ping: r('ping', 10, 5000, 5, 3600), router: r('router', 2, 5000, 5, 3600), loss: { ...r('loss', 0.5, 100, 60, 60) }, down: r('down', 0, 0, 5, 3600) };
}
const alertsAny = (a) => ALERT_RULES.some((k) => a[k] && a[k].on);
const durText = (ms) => { const s = Math.round(ms / 1000); return s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`; };
const outageDominant = (c) => { let best = 3; for (let i = 0; i < 4; i++) if (c.counts[i] > c.counts[best] || (c.counts[i] === c.counts[best] && i < best)) best = i; return OUTAGE_LAYERS[best]; };
const outageDown = (c) => (c.last - c.start) + (c.tick || OUTAGE.interval) >= OUTAGE.downMs;
const outageClose = (c, end, open) => ({ start: c.start, end, layer: outageDominant(c), fails: c.fails, ...(c.adapter ? { adapter: c.adapter } : {}), ...(c.gateway ? { gateway: c.gateway } : {}), ...(open ? { open: true } : {}) });
function outagePrune(log, now) {
  const cut = now - OUTAGE.keep;
  log.outages = log.outages.filter((o) => o.end >= cut);
  log.blips = log.blips.filter((b) => b >= cut).slice(-5000);
  log.coverage = log.coverage.filter((c) => c[1] >= cut);
}
function outageLoad() {
  let log = {};
  try { log = JSON.parse(fs.readFileSync(OUTAGE_FILE, 'utf8')); } catch { /* none yet */ }
  log = { enabled: false, notify: false, tray: true, coverage: [], outages: [], blips: [], gatewayAnswers: false, current: null, ...log };
  log.alerts = alertsSane({ ...ALERT_DEFAULTS, ...(log.alerts || {}) });
  if (log.current) { if (outageDown(log.current)) log.outages.push(outageClose(log.current, log.current.last, true)); log.current = null; }
  outagePrune(log, Date.now());
  return log;
}
let outage = outageLoad();
let outageRunning = false;
let liveUntil = 0;
const outageRun = { lastCtx: 0, lastSave: 0, watchStart: 0 };
function outageSave() {
  try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(`${OUTAGE_FILE}.tmp`, JSON.stringify(outage)); fs.renameSync(`${OUTAGE_FILE}.tmp`, OUTAGE_FILE); } catch { /* read-only folder: the log lives for this session */ }
}
function outageStatus() {
  const c = outage.current;
  return {
    enabled: outage.enabled, notify: outage.notify, running: outageRunning, now: Date.now(), intervalMs: OUTAGE.interval, minFails: 2,
    coverage: outage.coverage, outages: outage.outages, blips: outage.blips, gatewayAnswers: outage.gatewayAnswers,
    current: c ? { start: c.start, last: c.last, fails: c.fails, down: outageDown(c), layer: outageDominant(c) } : null, notifyNative: false,
  };
}

/* sensors: one accumulator per reading since the last reset (latest, lowest, highest, average, loss overall and per minute) */
const newAcc = () => ({ last: null, min: null, max: null, sum: 0, n: 0, sent: 0, lost: 0, bStart: 0, bSent: 0, bLost: 0, worst: 0 });
function accAdd(a, v, now) {
  if (now - a.bStart >= 60000) { if (a.bSent >= 10) a.worst = Math.max(a.worst, (100 * a.bLost) / a.bSent); a.bSent = 0; a.bLost = 0; a.bStart = now; }
  a.sent++; a.bSent++;
  if (v == null) { a.last = null; a.lost++; a.bLost++; return; }
  a.last = v; a.min = a.min == null ? v : Math.min(a.min, v); a.max = a.max == null ? v : Math.max(a.max, v); a.sum += v; a.n++;
}
const accJson = (a) => ({ last: a.last, min: a.min, max: a.max, avg: a.n ? a.sum / a.n : null, sent: a.sent, lost: a.lost, lossPct: a.sent ? (100 * a.lost) / a.sent : 0, worstMinutePct: Math.max(a.worst, a.bSent >= 10 ? (100 * a.bLost) / a.bSent : 0) });
const sensors = { since: Date.now(), router: newAcc(), internet: newAcc(), jitter: newAcc(), prevInternet: null, ring: [], failStart: null, tick: OUTAGE.interval, gateway: null, state: 'unknown', active: [false, false, false, false], activeSince: [0, 0, 0, 0], events: [] };
function checkAlerts(now) {
  const cfg = outage.alerts, s = sensors;
  if (!alertsAny(cfg)) return;
  const win = (secs) => s.ring.filter((e) => now - e[0] <= secs * 1000);
  const mean = (v) => (v.length ? v.reduce((a, b) => a + b, 0) / v.length : 0);
  const res = [];
  for (const [idx, k, col, what] of [[0, 'ping', 2, 'Internet ping'], [1, 'router', 1, 'Router ping']]) {
    const rule = cfg[k], w = win(Math.max(5, rule.secs));
    const ok = w.map((e) => e[col]).filter((v) => v != null && v >= 0);
    const covered = w.length && (now - w[0][0]) * 10 >= rule.secs * 1000 * 7;
    const tail = ok.slice(-3).reverse();
    res.push([idx, rule.on, covered && ok.length >= 2 && ok.every((v) => v > rule.limit), tail.length >= 2 && tail.every((v) => v <= rule.limit),
      `NetDeck: ${what.toLowerCase()} high`, `${Math.round(mean(ok))} ms on average over the last ${rule.secs} s (your limit: ${rule.limit} ms).`,
      `NetDeck: ${what.toLowerCase()} back to normal`, `${Math.round(tail[0] || 0)} ms now.`]);
  }
  { const rule = cfg.loss, w = win(60); const pct = w.length >= 10 ? (100 * w.filter((e) => e[2] == null).length) / w.length : 0;
    res.push([2, rule.on, w.length >= 10 && pct >= Math.max(0.1, rule.limit), pct < rule.limit / 2, 'NetDeck: packet loss', `${Math.round(pct)}% of internet pings lost in the last minute (your limit: ${rule.limit}%).`, 'NetDeck: packet loss has stopped', `${Math.round(pct)}% lost in the last minute.`]); }
  { const rule = cfg.down, downFor = s.failStart != null ? now - s.failStart : 0;
    res.push([3, rule.on, downFor >= Math.max(5, rule.secs) * 1000, s.failStart == null, 'NetDeck: internet down', `No internet reply for ${durText(downFor)} — ${s.router.last != null ? 'past your router' : 'your router is not answering either'}.`, 'NetDeck: internet is back', '']); }
  for (const [idx, on, exceeded, cleared, at, ab, ct, cb] of res) {
    if (!on) { s.active[idx] = false; continue; }
    if (!s.active[idx] && exceeded) { s.active[idx] = true; s.activeSince[idx] = now; s.events.push({ t: now, rule: ALERT_RULES[idx], kind: 'alert', title: at, text: ab }); }
    else if (s.active[idx] && cleared) { s.active[idx] = false; const lasted = durText(now - s.activeSince[idx]); s.events.push({ t: now, rule: ALERT_RULES[idx], kind: 'clear', title: ct, text: cb ? `${cb} It lasted ${lasted}.` : `It lasted ${lasted}.` }); }
  }
  if (s.events.length > 30) s.events.splice(0, s.events.length - 30);
}
function recordSensors(now, tick, gateway, gw, internet) {
  const s = sensors;
  s.tick = tick; s.gateway = gateway || null;
  if (gateway) accAdd(s.router, gw, now);
  accAdd(s.internet, internet, now);
  if (s.prevInternet != null && internet != null) accAdd(s.jitter, Math.abs(internet - s.prevInternet), now);
  s.prevInternet = internet;
  if (internet != null) s.failStart = null; else if (s.failStart == null) s.failStart = now;
  s.ring.push([now, gateway ? gw : -1, internet]);
  if (s.ring.length > OUTAGE.ring) s.ring.splice(0, s.ring.length - OUTAGE.ring);
  const recentLoss = s.ring.filter((e) => now - e[0] <= 60000 && e[2] == null).length;
  s.state = !gateway ? 'offline' : s.failStart != null ? (now - s.failStart + tick >= OUTAGE.downMs ? 'down' : 'warn') : recentLoss || internet > 150 || gw > 60 ? 'warn' : 'ok';
}
function sensorsStatus() {
  const s = sensors, now = Date.now();
  return {
    now, since: s.since, intervalMs: s.tick, gateway: s.gateway, state: s.state === 'warn' && s.failStart != null && now - s.failStart + s.tick >= OUTAGE.downMs ? 'down' : s.state,
    router: accJson(s.router), internet: accJson(s.internet), jitter: accJson(s.jitter),
    downSince: s.failStart != null && now - s.failStart + s.tick >= OUTAGE.downMs ? s.failStart : null,
    ring: s.ring, tray: false, trayNative: false,
    alerts: outage.alerts, alertActive: s.active, alertEvents: s.events,
  };
}

async function outageTick(tick) {
  let test = null;
  if (process.env.NETDECK_OUTAGE_TEST) { try { test = fs.readFileSync(process.env.NETDECK_OUTAGE_TEST, 'utf8').trim(); } catch { test = ''; } }
  const now = Date.now();
  const logging = outage.enabled;
  if (logging) {
    const last = outage.coverage[outage.coverage.length - 1];
    if (last && now - last[1] <= OUTAGE.gap && outageRun.watchStart) last[1] = now;
    else {
      outage.coverage.push([now, now]);
      outageRun.watchStart = now;
      if (outage.current) { if (outageDown(outage.current)) outage.outages.push(outageClose(outage.current, outage.current.last, true)); outage.current = null; }
      outageSave();
    }
  }
  const failing = sensors.failStart != null;
  if (now - outageRun.lastCtx > OUTAGE.ctxEvery) { await getContext(true).catch(() => null); outageRun.lastCtx = now; }
  let ctx = contextCache || {};
  const gwTarget = test === 'lan' ? '203.0.113.252' : ctx.gateway;
  const fake = test === 'isp' || test === 'lan';
  const [gw, internet] = await Promise.all([
    pingOnce(gwTarget),
    pingOnce(fake ? '203.0.113.251' : '1.1.1.1').then((v) => v ?? pingOnce(fake ? '198.51.100.251' : '8.8.8.8')),
  ]);
  if (internet == null && !failing) { ctx = await getContext(true).catch(() => ctx) || ctx; outageRun.lastCtx = now; }
  recordSensors(now, tick, ctx.gateway, gw, internet);
  checkAlerts(now);
  if (!logging) return;
  const settling = now - outageRun.watchStart < (test !== null ? 0 : OUTAGE.grace);
  if (gw != null) outage.gatewayAnswers = true;
  let ended = false, started = false;
  if (internet != null) {
    const c = outage.current;
    if (c) { if (outageDown(c)) { outage.outages.push(outageClose(c, now, false)); ended = true; } else outage.blips.push(c.start); outage.current = null; }
  } else if (!settling) {
    const layer = !ctx.gateway || !ctx.ip ? 2 : gw != null ? 0 : outage.gatewayAnswers ? 1 : 3;
    const c = outage.current || (outage.current = { start: now, last: now, fails: 0, counts: [0, 0, 0, 0], adapter: ctx.adapter || null, gateway: ctx.gateway || null, tick });
    const wasDown = outageDown(c);
    c.fails += 1; c.last = now; c.tick = tick; c.counts[layer] += 1;
    started = !wasDown && outageDown(c);
  }
  if (ended || started || now - outageRun.lastSave > OUTAGE.saveEvery) { outagePrune(outage, now); outageSave(); outageRun.lastSave = now; }
}
const outageShouldRun = () => outage.enabled || alertsAny(outage.alerts) || Date.now() < liveUntil;
function outageStart() {
  if (!outageShouldRun() || outageRunning) return;
  outageRunning = true;
  outageRun.watchStart = 0;
  const loop = async () => {
    if (!outageShouldRun()) { outageRunning = false; return; }
    const t0 = Date.now();
    const tick = Date.now() < liveUntil ? OUTAGE.liveInterval : OUTAGE.interval;
    try { await outageTick(tick); } catch { /* the next tick tries again */ }
    setTimeout(loop, Math.max(0, tick - (Date.now() - t0)));
  };
  loop();
}
async function handleOutage(req, res) {
  if (req.method === 'GET') return json(res, 200, outageStatus());
  if (req.method === 'DELETE') {
    outage.outages = []; outage.blips = []; outage.coverage = []; outage.current = null; outageRun.watchStart = 0;
    outageSave();
    return json(res, 200, outageStatus());
  }
  try {
    const body = JSON.parse(await readBody(req) || '{}');
    if (typeof body.notify === 'boolean') outage.notify = body.notify;
    if (typeof body.enabled === 'boolean') {
      outage.enabled = body.enabled;
      if (!body.enabled && outage.current) { if (outageDown(outage.current)) outage.outages.push(outageClose(outage.current, outage.current.last, true)); outage.current = null; }
    }
    outageSave();
    outageStart();
    json(res, 200, outageStatus());
  } catch (e) {
    res.writeHead(400).end('Invalid request.');
  }
}
async function handleAlerts(req, res) {
  try {
    const body = JSON.parse(await readBody(req) || '{}');
    const merged = { ...outage.alerts };
    for (const k of ALERT_RULES) if (body[k] && typeof body[k] === 'object') merged[k] = { ...merged[k], ...body[k] };
    outage.alerts = alertsSane(merged);
    sensors.active = [false, false, false, false];
    outageSave();
    outageStart();
    json(res, 200, outage.alerts);
  } catch (e) {
    res.writeHead(400).end('Invalid request.');
  }
}
function handleSensors(req, res, reset) {
  liveUntil = Date.now() + OUTAGE.liveHold;
  if (reset) Object.assign(sensors, { since: Date.now(), router: newAcc(), internet: newAcc(), jitter: newAcc(), prevInternet: null });
  outageStart();
  json(res, 200, sensorsStatus());
}

// ---------- run ----------
// {key} is ours; %{name} belongs to the tool (curl's -w format) and passes through untouched.
function fillParams(template, params, paramSpecs) {
  return String(template).replace(/(?<!%)\{(\w+)\}/g, (_, key) => {
    const def = (paramSpecs || []).find((p) => p.key === key);
    if (!def) throw new Error(`unknown param {${key}}`);
    const value = params?.[key];
    if (!VALIDATORS[def.type](value)) throw new Error(`Invalid value for "${key}".`);
    return String(value);
  });
}

function buildInvocation(cmd, payload) {
  let spec;
  if (payload.help) {
    spec = helpSpecFor(cmd);
    if (!spec) throw Object.assign(new Error('No built-in help is available for this command on this system.'), { status: 404 });
  } else {
    const base = runSpecFor(cmd);
    if (!base) throw Object.assign(new Error(IS_WIN ? 'This command is not runnable from the interface.' : 'This command has no Linux/macOS form to run.'), { status: 403 });
    spec = base;
    if (payload.preset !== undefined && payload.preset !== null) {
      const p = Number.isInteger(payload.preset) ? base.presets?.[payload.preset] : null;
      if (!p) throw Object.assign(new Error('Unknown preset.'), { status: 400 });
      if (p.admin && !contextCache?.admin) {
        throw Object.assign(new Error('This variant needs administrator rights — see the "How to run as admin" button next to the STANDARD USER badge.'), { status: 403 });
      }
      spec = { ...base, args: p.args ?? base.args, command: p.command ?? base.command, timeoutSec: p.timeoutSec ?? base.timeoutSec };
    }
  }
  const paramSpecs = (runSpecFor(cmd) || {}).params || [];
  // long-running commands (the stability monitor) declare their own limit; never more than 15 minutes
  const timeoutMs = Math.min(Math.max(Number(spec.timeoutSec) || 0, 0), 900) * 1000 || RUN_TIMEOUT_MS;
  if (spec.kind === 'ps') {
    return { exe: 'powershell.exe', args: ['-NoProfile', '-NonInteractive', '-Command', fillParams(spec.command, payload.params, paramSpecs)], timeoutMs };
  }
  return { exe: spec.exe, args: (spec.args || []).map((a) => fillParams(a, payload.params, paramSpecs)), timeoutMs };
}

function readBody(req, limit = 16384) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > limit) { req.destroy(); reject(new Error('too large')); }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

async function handleRun(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req, 8192));
  } catch {
    res.writeHead(400).end('Bad JSON');
    return;
  }
  const cmd = BY_ID.get(payload.id);
  if (!cmd) {
    res.writeHead(404).end('Unknown command.');
    return;
  }

  let exe, cmdArgs, timeoutMs;
  try {
    ({ exe, args: cmdArgs, timeoutMs } = buildInvocation(cmd, payload));
  } catch (e) {
    res.writeHead(e.status || 400).end(e.message);
    return;
  }

  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });

  const child = spawn(exe, cmdArgs, { windowsHide: true, shell: false });
  const timer = setTimeout(() => {
    child.kill();
    res.write(`\n[timed out after ${Math.round(timeoutMs / 60000)} minutes]\n`);
  }, timeoutMs);

  child.stdout.on('data', (d) => res.write(d));
  child.stderr.on('data', (d) => res.write(d));
  child.on('error', (err) => {
    clearTimeout(timer);
    res.end(`\n[could not start: ${err.code === 'ENOENT' ? exe + ' is not installed or not in PATH' : err.message}]\n`);
  });
  child.on('close', (code) => {
    clearTimeout(timer);
    if (!res.writableEnded) res.end(`\n[exited with code ${code ?? '?'}]\n`);
  });
  // res 'close' fires on client disconnect (Stop button) — req 'close' fires
  // as soon as the body is consumed, which would kill the child immediately.
  res.on('close', () => {
    clearTimeout(timer);
    if (!res.writableEnded && child.exitCode === null) child.kill();
  });
}

// ---------- custom (reference-only) commands ----------
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

function sanitizeCustom(input) {
  const name = str(input.name, 80);
  const purpose = str(input.purpose, 240);
  if (!name || !purpose) throw new Error('Name and purpose are required.');
  const unix = (Array.isArray(input.unix) ? input.unix : String(input.unix || '').split('\n'))
    .map((s) => str(s, 200)).filter(Boolean).slice(0, 6);
  const win = str(input.win, 200);
  if (!win && !unix.length) throw new Error('Give at least one command line (Windows or Linux/macOS).');
  const platforms = [];
  if (win) platforms.push(/^[A-Z][a-z]+-[A-Z]/.test(win) ? 'powershell' : 'windows');
  if (unix.length) platforms.push('unix');
  return {
    name, purpose, win: win || undefined, unix,
    category: str(input.category, 60) || 'Custom',
    note: str(input.note, 240) || undefined,
    platforms, safe: false, custom: true,
  };
}

async function handleCustomCreate(req, res) {
  try {
    const body = JSON.parse(await readBody(req));
    const entry = { id: `custom-${Date.now().toString(36)}${crypto.randomBytes(2).toString('hex')}`, ...sanitizeCustom(body) };
    CUSTOM.push(entry);
    saveCustom();
    json(res, 201, clientShape(entry));
  } catch (e) {
    res.writeHead(400).end(e.message || 'Invalid command.');
  }
}

function handleCustomDelete(req, res) {
  const id = new URL(req.url, 'http://x').searchParams.get('id') || '';
  const before = CUSTOM.length;
  CUSTOM = CUSTOM.filter((c) => c.id !== id);
  if (CUSTOM.length === before) {
    res.writeHead(404).end('No such custom command.');
    return;
  }
  saveCustom();
  json(res, 200, { ok: true });
}

// What the browser needs to know per command: which form runs here, its params/presets, help availability.
function clientShape(c) {
  const spec = runSpecFor(c);
  return {
    ...c,
    run: undefined,
    runUnix: undefined,
    help: undefined,
    helpUnix: undefined,
    runnable: spec ? { kind: spec.kind, exe: spec.exe, args: spec.args, command: spec.command, display: spec.display, params: spec.params || [], presets: (spec.presets || []).map((p) => ({ key: p.key, label: p.label, args: p.args, command: p.command, display: p.display, admin: Boolean(p.admin) })) } : null,
    hasHelp: Boolean(helpSpecFor(c)),
  };
}

function json(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache' });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const isApi = url.pathname.startsWith('/api/');

  if (isApi) {
    const corsOk = applyCors(req, res);
    if (req.method === 'OPTIONS') {
      res.writeHead(corsOk ? 204 : 403).end();
      return;
    }
    if (!authorized(req)) {
      res.writeHead(403).end(req.headers.origin && !isLocalOrigin(req.headers.origin)
        ? 'This origin is not paired with NetDeck. Start the server with NETDECK_ORIGIN set and enter the token it prints.'
        : 'Requests must come from the NetDeck page.');
      return;
    }
  }

  if (req.method === 'GET' && url.pathname === '/api/ping') return json(res, 200, { ok: true, name: 'NetDeck', platform: PLATFORM, hostname: os.hostname() });
  if (req.method === 'POST' && url.pathname === '/api/run') return handleRun(req, res);
  if (req.method === 'GET' && url.pathname === '/api/commands') return json(res, 200, { platform: PLATFORM, commands: COMMANDS.map(clientShape) });
  if (req.method === 'POST' && url.pathname === '/api/custom') return handleCustomCreate(req, res);
  if (req.method === 'DELETE' && url.pathname === '/api/custom') return handleCustomDelete(req, res);
  if (req.method === 'GET' && url.pathname === '/api/context') {
    return getContext(url.searchParams.get('refresh') === '1').then((ctx) => json(res, 200, ctx));
  }
  if (req.method === 'GET' && url.pathname === '/api/health') return handleHealth(req, res);
  if (url.pathname === '/api/outage' && ['GET', 'POST', 'DELETE'].includes(req.method)) return handleOutage(req, res);
  if (url.pathname === '/api/sensors' && req.method === 'GET') return handleSensors(req, res, false);
  if (url.pathname === '/api/sensors/reset' && req.method === 'POST') return handleSensors(req, res, true);
  if (url.pathname === '/api/alerts' && req.method === 'POST') return handleAlerts(req, res);
  if (req.method === 'GET') return serveStatic(req, res);
  res.writeHead(405).end('Method not allowed');
});

function openBrowser(url) {
  const cmd = IS_WIN ? ['cmd', ['/c', 'start', '', url]] : PLATFORM === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
  spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore', windowsHide: true }).on('error', () => {}).unref();
}

// If the preferred port is busy (another NetDeck, a dev server), walk up to the next free one
// instead of dying — a double-clicked exe has no other way to tell you.
const MAX_PORT_TRIES = 20;
let port = PORT;

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE' && port < PORT + MAX_PORT_TRIES) {
    console.log(`Port ${port} is already in use — trying ${port + 1}`);
    port += 1;
    setTimeout(() => server.listen(port, '127.0.0.1'), 50);
    return;
  }
  console.error(`\nNetDeck could not start: ${err.message}`);
  holdConsoleThenExit(1);
});

server.on('listening', () => {
  const url = `http://localhost:${port}`;
  console.log(`NetDeck running at ${url} (${PLATFORM}${sea ? ', packaged' : ''})`);
  if (port !== PORT) console.log(`(port ${PORT} was busy; use --port to choose a fixed one)`);
  if (CUSTOM.length) console.log(`Loaded ${CUSTOM.length} custom command(s) from ${CUSTOM_FILE}`);
  if (ALLOWED_ORIGIN) {
    console.log(`Hosted page allowed: ${ALLOWED_ORIGIN}`);
    console.log(`Pairing token: ${TOKEN}   (enter this in the hosted page's "Connect local NetDeck" dialog)`);
  }
  console.log('Keep this window open while you use NetDeck; close it (or press Ctrl+C) to stop.');
  getContext(false); // warm the cache so the first page load is instant
  outageStart(); // carries on from the last session when the outage log was left on
  if (OPEN_BROWSER) openBrowser(url);
});

server.listen(port, '127.0.0.1');
