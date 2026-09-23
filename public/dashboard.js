/* NetDeck dashboard: one screen that says how the network is right now.
   Every number on it comes from the same whitelisted commands and playbook checks as the rest of the app.
   The dashboard runs the quick ones itself (a few seconds, silently, all at once) and shows the last result
   of the slow ones — the network scan, the DNS honesty check, the router check-up — from the run history and
   the scan log. The last snapshot is kept in localStorage, so the page opens with something to show and says
   how old it is. Every card has a button that runs its source command or playbook in the terminal, so any
   figure can be traced back to real output. */
window.NetDeckDashboard = (() => {
  const KEY = 'netdeck.dashboard.v1';
  const STALE_MS = 2 * 60 * 1000;
  // The quick set: each one finishes in a few seconds and is safe to repeat.
  const QUICK = [
    { key: 'ip', cmd: 'ipconfig-all', check: 'ipconfig' },
    { key: 'gw', cmd: 'ping', params: { host: '{gateway}' }, check: 'ping', warnMs: 50 },
    { key: 'net', cmd: 'ping', params: { host: '1.1.1.1' }, check: 'ping', warnMs: 150 },
    { key: 'dns', cmd: 'nslookup', params: { host: 'example.com' }, check: 'nslookup' },
    { key: 'web', cmd: 'curl', preset: 'timing', params: { url: 'https://example.com/' }, check: 'curlTiming' },
    { key: 'wifi', cmd: 'netsh', check: 'wlan' },
    { key: 'os', cmd: 'os-health', check: 'osHealth' },
  ];
  const STATE = { pass: 'ok', warn: 'warn', fail: 'err', info: 'idle' };
  const TONE = { pass: 'ok', warn: 'warn', fail: 'err' };

  let D = null;       // what app.js lends us: execute, startRun, runPlaybook, context, health, history…
  let els = null;
  let snap = load();
  let busy = false;
  let shown = false;

  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const ago = (ts) => {
    if (!ts) return '';
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s} s ago`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    if (h < 36) return `${h} h ago`;
    return `${Math.round(h / 24)} days ago`;
  };
  const clock = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false });

  function load() {
    try { const j = JSON.parse(localStorage.getItem(KEY) || 'null'); if (j && j.tiles) return j; } catch (e) { /* blocked or corrupt */ }
    return { at: 0, tookMs: 0, tiles: {} };
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(snap)); } catch (e) { /* a convenience only */ } }

  function init(deps) {
    D = deps;
    els = { view: D.$('view-dashboard'), strip: D.$('dash-strip'), grid: D.$('dash-grid'), status: D.$('dash-status'), refresh: D.$('dash-refresh'), off: D.$('dash-static') };
    els.refresh.addEventListener('click', () => refresh());
    els.view.addEventListener('click', onClick);
  }

  /* Any button on the dashboard that names a command or playbook runs it in the terminal, visibly. */
  function onClick(e) {
    const b = e.target.closest('[data-run],[data-pb]');
    if (!b || !D.canRun()) return;
    if (b.dataset.pb) { const pb = D.PB.get(b.dataset.pb); if (pb) D.runPlaybook(pb, {}); return; }
    const cmd = D.byId.get(b.dataset.run);
    if (!cmd || !cmd.runnable) return;
    let params = {};
    try { params = JSON.parse(b.dataset.params || '{}'); } catch (e) { params = {}; }
    D.startRun(cmd, params, { preset: presetIdx(cmd, b.dataset.preset) });
  }
  function presetIdx(cmd, key) {
    if (!key) return null;
    const i = ((cmd.runnable || {}).presets || []).findIndex((p) => p.key === key);
    return i === -1 ? null : i;
  }

  function show() { shown = true; render(); if (D.canRun() && (!snap.at || Date.now() - snap.at > STALE_MS)) refresh(); }
  function hide() { shown = false; }
  function poke(what) { if (!shown) return; if (what === 'health') updatePingChips(); else render(); }   // health tick: patch; anything else: redraw

  async function refresh() {
    if (busy || !D || !D.canRun()) return;
    busy = true;
    els.refresh.disabled = true;
    els.refresh.textContent = 'Refreshing…';
    els.status.textContent = 'Checking…';
    const ctx = D.context() || {};
    const started = Date.now();
    const tiles = { ...snap.tiles };
    await Promise.all(QUICK.map(async (q) => {
      const cmd = D.byId.get(q.cmd);
      const stamp = (t) => { tiles[q.key] = { ...t, at: Date.now(), params: q.params || null, preset: q.preset || null }; };
      if (!cmd || !cmd.runnable) { stamp({ status: 'info', summary: 'not available on this OS' }); return; }
      const params = {};
      for (const [k, v] of Object.entries(q.params || {})) {
        const val = v === '{gateway}' ? ctx.gateway : v;
        if (!val) { stamp({ status: 'fail', summary: 'no gateway detected — is this PC connected?' }); return; }
        params[k] = val;
      }
      const preset = presetIdx(cmd, q.preset);
      if (q.preset && preset === null) { stamp({ status: 'info', summary: 'this variant is not available on this OS' }); return; }
      const t0 = Date.now();
      let r;
      try { r = await D.execute(cmd, params, { preset }); } catch (err) { stamp({ status: 'fail', summary: String((err && err.message) || err).slice(0, 160) }); return; }
      const ms = Date.now() - t0;
      const check = r.refused || r.error
        ? { status: 'fail', summary: (r.output || '').trim().slice(0, 160) }
        : D.PB.check(q.check, r.output || '', params, ctx, { durationMs: ms, exitCode: r.exitCode, step: q, R: {} });
      const tile = { status: check.status, summary: check.summary, data: check.data || null, ms };
      if (q.key === 'ip') tile.info = adapterInfo(r.output || '', ctx);
      stamp(tile);
      tiles[q.key].params = params;
    }));
    snap = { at: Date.now(), tookMs: Date.now() - started, tiles };
    save();
    busy = false;
    els.refresh.disabled = false;
    els.refresh.textContent = 'Refresh';
    render();
  }

  /* The fields of YOUR adapter from ipconfig /all (Windows). Other editions fall back to the context strip. */
  function adapterInfo(out, ctx) {
    if (!D.isWin()) return null;
    const t = D.P.ipconfig(out);
    if (!t) return null;
    const groups = new Map();
    for (const [adapter, key, value] of t.rows) {
      const name = adapter.replace(/^.*adapter\s+/i, '');
      if (!groups.has(name)) groups.set(name, {});
      const g = groups.get(name);
      (g[key] = g[key] || []).push(value.replace(/\((Preferred|Duplicate|Tentative)\)$/i, '').trim());
    }
    const usable = (n) => { const g = groups.get(n); return g && g['IPv4 Address'] && (g['Default Gateway'] || []).some((x) => /^\d/.test(x)); };
    const name = (ctx.adapter && groups.has(ctx.adapter)) ? ctx.adapter : [...groups.keys()].find(usable);
    if (!name) return null;
    const g = groups.get(name);
    const one = (k) => (g[k] || [])[0] || '';
    const expires = Date.parse(one('Lease Expires').replace(/^[A-Za-z]+,\s*/, ''));
    const host = ((groups.get('Windows IP Configuration') || {})['Host Name'] || [])[0] || '';
    return {
      adapter: name, description: one('Description'), mac: one('Physical Address'),
      ip: one('IPv4 Address'), mask: one('Subnet Mask'),
      gateway: (g['Default Gateway'] || []).find((x) => /^\d/.test(x)) || one('Default Gateway'),
      dns: (g['DNS Servers'] || []).filter(Boolean), dhcp: /yes/i.test(one('DHCP Enabled')), dhcpServer: one('DHCP Server'),
      leaseExpires: Number.isFinite(expires) ? expires : null, ipv6: (g['IPv6 Address'] || [])[0] || '', host,
    };
  }

  function leaseLeft(expires) {
    const h = (expires - Date.now()) / 3600000;
    if (h < 0) return 'lease expired';
    if (h < 1) return `${Math.max(1, Math.round(h * 60))} min of lease left`;
    if (h < 48) return `${Math.round(h)} h of lease left`;
    return `${Math.round(h / 24)} days of lease left`;
  }

  /* ---------- render ---------- */
  function render() {
    if (!els) return;
    const live = D.canRun();
    els.off.hidden = live;
    els.strip.hidden = !live;
    els.grid.hidden = !live;
    els.refresh.hidden = !live;
    if (!live) { els.status.textContent = ''; return; }
    els.status.textContent = snap.at
      ? `Last check ${clock(snap.at)} (${ago(snap.at)}) · ${(snap.tookMs / 1000).toFixed(1)} s · router and internet pings update every 10 s`
      : busy ? 'Checking…' : 'No check yet — press Refresh';
    const ctx = D.context() || {};
    els.strip.innerHTML = chips(ctx).join('');
    els.grid.innerHTML = [computerCard(ctx), connectionCard(ctx), lanCard(ctx)].join('');
  }

  function chip({ key, label, val, sub, state, title, run, pb, params, preset }) {
    const attrs = pb ? ` data-pb="${esc(pb)}"` : run ? ` data-run="${esc(run)}" data-params="${esc(JSON.stringify(params || {}))}"${preset ? ` data-preset="${esc(preset)}"` : ''}` : '';
    return `<button type="button" class="dash-chip" data-key="${esc(key || '')}" data-state="${state}"${attrs} title="${esc(title || '')}"><span class="dash-chip-label">${esc(label)}</span><span class="dash-chip-val">${esc(val)}</span><span class="dash-chip-sub">${esc(sub || '')}</span></button>`;
  }

  const lastPlaybook = (id) => (D.history() || []).find((h) => h.kind === 'playbook' && h.pbId === id && h.verdict);

  /* Router and internet: the live 10-second ping if there is one, else the last 4-ping check. */
  function pingSpec(label, key, hkey, host, warnMs, badMs) {
    const T = snap.tiles;
    const s = (D.health() || {})[hkey] || [];
    const t = T[key], h = host && s.length ? s[s.length - 1] : null;
    let state = 'idle', val = '—', sub = t ? t.summary : 'not checked yet';
    if (!host) { sub = 'no gateway detected'; }
    else if (h) {
      if (h.v === null) { state = 'err'; val = 'no reply'; } else { val = `${h.v} ms`; state = h.v > badMs ? 'err' : h.v > warnMs ? 'warn' : 'ok'; }
      sub = `${host} · ${t ? t.summary : 'pinged every 10 s'}`;
    } else if (t) {
      state = STATE[t.status] || 'idle';
      val = t.data && t.data.avg != null ? `${t.data.avg} ms` : t.status === 'fail' ? 'no reply' : '—';
      sub = `${host} · ${t.summary}`;
    }
    return { key, label, val, sub, state, title: host ? `Run "ping ${host}" in the terminal` : '', run: host ? 'ping' : null, params: { host } };
  }
  const pingSpecs = (ctx) => [pingSpec('Router', 'gw', 'gateway', ctx.gateway, 50, 200), pingSpec('Internet', 'net', 'internet', '1.1.1.1', 100, 300)];

  /* Every 10 s the health strip pings again; only the two ping tiles change, so patch them in place
     (a full redraw would wipe hover, focus and tooltips every 10 s). */
  function updatePingChips() {
    for (const spec of pingSpecs(D.context() || {})) {
      const el = els.strip.querySelector(`.dash-chip[data-key="${spec.key}"]`);
      if (!el) continue;
      el.dataset.state = spec.state;
      el.querySelector('.dash-chip-val').textContent = spec.val;
      el.querySelector('.dash-chip-sub').textContent = spec.sub;
    }
  }

  function chips(ctx) {
    const T = snap.tiles;
    const out = pingSpecs(ctx).map(chip);

    const dns = T.dns;
    out.push(chip({
      key: 'dns', label: 'DNS', state: dns ? STATE[dns.status] : 'idle',
      val: dns ? (dns.data && dns.data.durationMs ? (dns.data.durationMs < 1000 ? `${dns.data.durationMs} ms` : `${(dns.data.durationMs / 1000).toFixed(1)} s`) : dns.status === 'pass' ? 'answers' : 'failing') : '—',
      sub: dns ? dns.summary : 'not checked yet', title: 'Run "nslookup example.com" in the terminal', run: 'nslookup', params: { host: 'example.com' },
    }));

    const web = T.web;
    out.push(chip({
      key: 'web', label: 'HTTPS', state: web ? STATE[web.status] : 'idle',
      val: web ? (web.data && web.data.total != null ? `${web.data.total.toFixed(2)} s` : web.status === 'fail' ? 'failing' : '—') : '—',
      sub: web ? `example.com · ${web.summary}` : 'not checked yet', title: 'Time a request to https://example.com/ in the terminal', run: 'curl', preset: 'timing', params: { url: 'https://example.com/' },
    }));

    const w = T.wifi, wd = w && w.data;
    let wState = 'idle', wVal = '—', wSub = w ? w.summary : 'not checked yet';
    if (wd && wd.wifi) { wState = STATE[w.status]; wVal = `${wd.signal}% signal`; }
    else if (wd && wd.blocked) { wVal = 'withheld'; wSub = 'turn on Location services to read signal and channel'; }
    else if (w) { wVal = 'not in use'; wSub = 'this PC is on a cable (or Wi-Fi is off)'; }
    out.push(chip({ key: 'wifi', label: 'Wi-Fi', state: wState, val: wVal, sub: wSub, title: 'Run "netsh wlan show interfaces" in the terminal', run: 'netsh' }));

    const dh = lastPlaybook('dnshonest');
    out.push(chip({
      key: 'dnshonest', label: 'DNS honesty', state: dh ? TONE[dh.verdict.tone] || 'idle' : 'idle',
      val: dh ? ({ pass: 'honest', warn: 'look', fail: 'tampered' }[dh.verdict.tone] || '—') : 'not run',
      sub: dh ? `${(dh.steps && dh.steps[0] && dh.steps[0].summary) || ''} · ${ago(dh.endedAt || dh.startedAt)}` : 'run "Is my DNS honest?" — takes about a minute',
      title: 'Run the "Is my DNS honest?" playbook', pb: 'dnshonest',
    }));

    const rc = lastPlaybook('routercheck');
    out.push(chip({
      key: 'routercheck', label: 'Router check-up', state: rc ? TONE[rc.verdict.tone] || 'idle' : 'idle',
      val: rc ? ({ pass: 'healthy', warn: 'attention', fail: 'exposed' }[rc.verdict.tone] || '—') : 'not run',
      sub: rc ? `${(rc.steps && rc.steps[0] && rc.steps[0].summary) || ''} · ${ago(rc.endedAt || rc.startedAt)}` : 'run "Router check-up" — about half a minute',
      title: 'Run the "Router check-up" playbook', pb: 'routercheck',
    }));

    const L = window.NetDeckScanLog && window.NetDeckScanLog.latest ? window.NetDeckScanLog.latest() : null;
    const lan = L ? lanDiff(L, ctx) : null;
    out.push(chip({
      key: 'lan', label: 'Devices', state: L ? (lan.added.length ? 'warn' : 'ok') : 'idle',
      val: L ? `${lan.others.length} other${lan.others.length === 1 ? '' : 's'}` : 'not scanned',
      sub: L ? `${L.range} · ${lan.added.length ? `${lan.added.length} new · ` : ''}scanned ${ago(L.ts)}` : 'run "Scan my network" — about a minute',
      title: 'Run the "Scan my network" playbook', pb: 'scan',
    }));
    return out;
  }

  function card(title, meta, body, foot) {
    return `<article class="card dash-card"><header class="card-head"><h2 class="card-name">${esc(title)}</h2><span class="card-cat">${esc(meta || '')}</span></header>${body}<footer class="dash-foot">${foot}</footer></article>`;
  }
  const btn = (label, run, params, preset) => `<button type="button" class="tbtn tbtn-sm" data-run="${esc(run)}" data-params="${esc(JSON.stringify(params || {}))}"${preset ? ` data-preset="${esc(preset)}"` : ''}>${esc(label)}</button>`;
  const pbBtn = (label, id) => `<button type="button" class="tbtn tbtn-sm" data-pb="${esc(id)}">${esc(label)}</button>`;

  function computerCard(ctx) {
    const T = snap.tiles;
    const t = T.ip, info = t && t.info, w = T.wifi && T.wifi.data, os = T.os && T.os.data;
    const oui = window.NetDeckOui;
    const rows = [];
    const row = (k, v, small) => { if (v) rows.push(`<dt>${esc(k)}</dt><dd>${esc(v)}${small ? ` <small>${esc(small)}</small>` : ''}</dd>`); };
    row('host', (info && info.host) || ctx.hostname);
    row('adapter', (info && info.adapter) || ctx.adapter, info && info.description);
    row('ip', (info && info.ip) || ctx.ip, info && info.mask ? `mask ${info.mask}` : '');
    row('gateway', (info && info.gateway) || ctx.gateway);
    row('dns', ((info && info.dns.length) ? info.dns : (ctx.dns || [])).join(', '));
    if (info) row('dhcp', info.dhcp ? (info.dhcpServer || 'yes') : 'static address', info.dhcp && info.leaseExpires ? leaseLeft(info.leaseExpires) : '');
    if (info && info.mac) row('mac', info.mac, oui ? oui.lookup(info.mac) : '');
    if (w && w.wifi) row('wi-fi', `${w.signal}% signal`, `${w.band}${w.channel ? ` ch ${w.channel}` : ''} · ${w.radio} · ${w.rx}/${w.tx} Mbps`);
    else if (w && w.blocked) row('wi-fi', 'details withheld', 'Location services are off');
    if (info && info.ipv6) row('ipv6', info.ipv6);
    if (os) { row('os', os.os, os.version); row('up', `${os.uptime} days`, `memory ${os.usedPct}% used · ${os.free} of ${os.total} GB free`); }
    const body = rows.length ? `<dl class="dash-kv">${rows.join('')}</dl>` : '<p class="dash-empty">Press Refresh to read this computer\'s configuration.</p>';
    const foot = `<span>ipconfig /all · netsh wlan show interfaces · Win32_OperatingSystem${t ? ` · ${ago(t.at)}` : ''}</span><span class="dash-links">${btn('ipconfig /all', 'ipconfig-all')}${btn('OS', 'os-health')}</span>`;
    return card('This computer', ctx.admin ? 'admin' : '', body, foot);
  }

  function connectionCard(ctx) {
    const T = snap.tiles;
    const items = [
      ['router', 'gw', ctx.gateway ? `ping ${ctx.gateway}` : 'ping (no gateway)', ctx.gateway ? btn('run', 'ping', { host: ctx.gateway }) : ''],
      ['internet', 'net', 'ping 1.1.1.1', btn('run', 'ping', { host: '1.1.1.1' })],
      ['dns', 'dns', 'nslookup example.com', btn('run', 'nslookup', { host: 'example.com' })],
      ['https', 'web', 'curl timing https://example.com/', btn('run', 'curl', { url: 'https://example.com/' }, 'timing')],
      ['wi-fi', 'wifi', 'netsh wlan show interfaces', btn('run', 'netsh')],
    ];
    const li = items.map(([label, key, what, b]) => {
      const t = T[key];
      return `<li class="dash-check" data-status="${t ? esc(t.status) : 'pending'}" title="${esc(what)}"><span class="dash-dot"></span><span class="dash-check-name">${esc(label)}</span><span class="dash-check-sum">${esc(t ? t.summary : 'not checked yet')}</span>${b}</li>`;
    }).join('');
    // One line that says what the checks add up to.
    const s = (k) => T[k] && T[k].status;
    let tone = 'idle', text = 'Press Refresh to check the connection.';
    if (T.gw || T.net) {
      if (s('gw') === 'fail' && ctx.gateway) { tone = 'err'; text = 'The router does not answer: nothing beyond this PC will work. Check the cable or the Wi-Fi connection.'; }
      else if (s('net') === 'fail') { tone = 'err'; text = 'The router answers but the internet does not: the problem is at the router or beyond it (modem, provider).'; }
      else if (s('dns') === 'fail') { tone = 'err'; text = 'The internet is reachable but names do not resolve: DNS is the problem. "Is DNS healthy?" narrows it down.'; }
      else if (s('web') === 'fail') { tone = 'err'; text = 'Ping and DNS work but an HTTPS request fails: a sign-in (captive) portal, a proxy or a firewall is in the way.'; }
      else if (['gw', 'net', 'dns', 'web'].some((k) => s(k) === 'warn')) { tone = 'warn'; text = 'Everything answers, but slowly. The rows below say which part; "Why is everything slow?" digs in.'; }
      else { tone = 'ok'; text = 'Everything answers promptly: router, internet, DNS and HTTPS.'; }
    }
    const body = `<p class="dash-verdict" data-tone="${tone}">${esc(text)}</p><ul class="dash-checks">${li}</ul>`;
    const foot = `<span>${snap.at ? `checked ${ago(snap.at)}` : 'not checked yet'}</span><span class="dash-links">${pbBtn('Can\'t reach the internet?', 'internet')}${pbBtn('Why is everything slow?', 'slow')}</span>`;
    return card('Connection', snap.at ? clock(snap.at) : '', body, foot);
  }

  function lanDiff(L, ctx) {
    const keyOf = window.NetDeckScanLog.keyOf;
    const others = L.devices.filter((d) => d.ip !== ctx.ip);
    const added = L.prev ? L.devices.filter((d) => L.firstSeen[keyOf(d)] === L.ts) : [];
    const gone = L.prev ? L.prev.devices.filter((d) => !L.devices.some((x) => keyOf(x) === keyOf(d))) : [];
    const moved = L.prev ? L.devices.filter((d) => { const p = L.prev.devices.find((x) => keyOf(x) === keyOf(d)); return p && p.ip !== d.ip; }) : [];
    return { others, added, gone, moved };
  }

  function lanCard(ctx) {
    const SL = window.NetDeckScanLog;
    const L = SL && SL.latest ? SL.latest() : null;
    const rc = lastPlaybook('routercheck');
    if (!L) {
      const body = '<p class="dash-empty">No scan recorded yet. "Scan my network" finds every device on this subnet — names, manufacturers, what is new — and the dashboard keeps the result.</p>';
      const foot = `<span>from the scan log</span><span class="dash-links">${pbBtn('Scan now', 'scan')}${pbBtn('Router check-up', 'routercheck')}</span>`;
      return card('Network', '', body, foot);
    }
    const { others, added, gone, moved } = lanDiff(L, ctx);
    const who = (d) => d.ip + (d.name ? ` (${d.name})` : d.maker ? ` (${d.maker})` : '');
    const byMaker = new Map();
    const oui = window.NetDeckOui;
    others.forEach((d) => { const k = d.maker || (oui && d.mac ? oui.lookup(d.mac) : '') || 'unrecognised'; byMaker.set(k, (byMaker.get(k) || 0) + 1); });
    const top = [...byMaker.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    const max = top.length ? top[0][1] : 1;
    const bars = top.map(([m, n]) => `<div class="dash-bar"><span class="dash-bar-name" title="${esc(m)}">${esc(m)}</span><span class="dash-bar-track"><span class="dash-bar-fill" style="width:${Math.round((n / max) * 100)}%"></span></span><span class="dash-bar-n">${n}</span></div>`).join('');
    const router = L.devices.find((d) => d.ip === ctx.gateway);
    const named = others.filter((d) => d.name).length;
    const rows = [];
    const row = (k, v, small) => { if (v) rows.push(`<dt>${esc(k)}</dt><dd>${v}${small ? ` <small>${esc(small)}</small>` : ''}</dd>`); };
    row('devices', esc(`${others.length} other${others.length === 1 ? '' : 's'}`), `on ${L.range}${named ? ` · ${named} with a name` : ''}`);
    if (router) row('router', esc(router.ip), router.maker || '');
    if (rc) row('router check', esc({ pass: 'healthy', warn: 'needs attention', fail: 'exposed' }[rc.verdict.tone] || rc.verdict.tone), `${(rc.steps && rc.steps[0] && rc.steps[0].summary) || ''} · ${ago(rc.endedAt || rc.startedAt)}`);
    const ch = [];
    if (added.length) ch.push(`<span class="dash-delta" data-state="warn" title="${esc(added.map(who).join(', '))}">${added.length} new</span>`);
    if (gone.length) ch.push(`<span class="dash-delta" data-state="idle" title="${esc(gone.map(who).join(', '))}">${gone.length} gone</span>`);
    if (moved.length) ch.push(`<span class="dash-delta" data-state="idle" title="${esc(moved.map((d) => d.ip).join(', '))}">${moved.length} moved</span>`);
    row('since last scan', L.prev ? (ch.length ? ch.join(' ') : '<span class="dash-delta" data-state="ok">no change</span>') : '<span class="dash-delta" data-state="idle">first scan recorded</span>', L.prev ? `previous ${ago(L.prev.ts)}, ${L.prev.devices.length} devices` : '');
    const body = `<dl class="dash-kv">${rows.join('')}</dl>${bars ? `<div class="dash-bars" aria-label="Devices by manufacturer">${bars}</div>` : ''}`;
    const foot = `<span>scanned ${ago(L.ts)} · hover a change for the addresses</span><span class="dash-links">${pbBtn('Scan now', 'scan')}${pbBtn('Router check-up', 'routercheck')}</span>`;
    return card('Network', `${L.devices.length} seen`, body, foot);
  }

  return { init, show, hide, poke, refresh };
})();
