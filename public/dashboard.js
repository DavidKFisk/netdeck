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
    { key: 'fw', cmd: 'netsh', preset: 'advfirewall-show-allprofiles', check: 'firewall' },
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
    document.addEventListener('visibilitychange', () => { if (!document.hidden && shown) pollTraffic(); });
    try { localStorage.removeItem('netdeck.dashboard.collapsed'); } catch (e) { /* 1.25.1 remembered folded cards; they now start folded every time */ }
    // snapshot: a small dialog for the anonymise choice, then one HTML file
    const modal = D.$('snapshot-modal'), snapBtn = D.$('dash-snapshot');
    if (modal && snapBtn) {
      snapBtn.addEventListener('click', () => { modal.hidden = false; });
      D.$('snapshot-cancel').addEventListener('click', () => { modal.hidden = true; });
      modal.addEventListener('click', (e) => { if (e.target === modal) modal.hidden = true; });
      D.$('snapshot-go').addEventListener('click', () => { modal.hidden = true; snapshot(D.$('snapshot-anon').checked); });
    }
    backfill();
  }

  /* Any button on the dashboard that names a command or playbook runs it in the terminal, visibly. */
  function onClick(e) {
    const fold = e.target.closest('[data-collapse]');
    if (fold) { toggleCollapse(fold.dataset.collapse); return; }
    const clear = e.target.closest('[data-clear]');
    if (clear) { clearSeries(clear.dataset.clear); return; }
    const r = e.target.closest('[data-range]');
    if (r) { range = r.dataset.range; try { localStorage.setItem('netdeck.dashboard.range', range); } catch (err) { /* fine */ } const c = els.grid.querySelector('#dash-latency'); if (c) c.outerHTML = latencyCard(); return; }
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

  // refresh on opening when the snapshot is stale — or predates a tile added in a newer version
  function show() { shown = true; render(); if (D.canRun() && (!snap.at || Date.now() - snap.at > STALE_MS || QUICK.some((q) => !snap.tiles[q.key]))) refresh(); if (D.canRun() && !collapsed.has('traffic')) startTraffic(); }
  function hide() { shown = false; stopTraffic(); }
  /* health tick: record the sample and patch the two ping tiles and the latency chart in place (a full redraw
     every 10 s would wipe hover and focus); a saved run: take what the charts need, then redraw. */
  function poke(what, entry) {
    if (what === 'health') {
      recordHealth();
      if (shown) {
        updatePingChips();
        const b = els.grid.querySelector('#dash-latency-body');
        if (b) b.innerHTML = latencyBody();
        else { const s = els.grid.querySelector('#dash-latency.is-collapsed .dash-collapsed-sum'); if (s) { const tmp = document.createElement('div'); tmp.innerHTML = latencyCard(); s.textContent = tmp.querySelector('.dash-collapsed-sum').textContent; } }
      }
      return;
    }
    if (what === 'history') { ingest(entry); }
    if (shown) render();
  }

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
    els.grid.innerHTML = [computerCard(ctx), connectionCard(ctx), lanCard(ctx), speedCard(), routeCard(), postureCard(), latencyCard(), trafficCard()].join('');
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

    const fw = T.fw, off = fw && fw.data && fw.data.off;
    out.push(chip({
      key: 'fw', label: 'Firewall', state: fw ? STATE[fw.status] : 'idle',
      val: fw ? (fw.status === 'pass' ? 'on' : off && off.length ? `off: ${off.join(', ')}` : 'unknown') : '—',
      sub: fw ? fw.summary : 'not checked yet', title: 'Run "netsh advfirewall show allprofiles" in the terminal', run: 'netsh', preset: 'advfirewall-show-allprofiles',
    }));

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

  function card(title, meta, body, foot, cls) {
    return `<article class="card dash-card${cls ? ' ' + cls : ''}"><header class="card-head"><h2 class="card-name">${esc(title)}</h2><span class="card-cat">${esc(meta || '')}</span></header>${body}<footer class="dash-foot">${foot}</footer></article>`;
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

  /* ================= over time: latency samples, speed tests, monitors, the last trace =================
     The health strip already pings the router and 1.1.1.1 every 10 s; the dashboard keeps those samples
     for 24 hours (only while NetDeck is open — gaps are drawn as gaps). Speed tests, stability monitors
     and traceroutes are read from the run history as they are saved, so the history's 30-entry limit
     does not lose them. Everything lives in localStorage under its own key. */
  const SKEY = 'netdeck.dashboard.series.v1';
  const SAMPLE_KEEP = 24 * 3600 * 1000;
  const RANGES = { '10m': 10 * 60000, '1h': 3600000, '6h': 6 * 3600000, '24h': 24 * 3600000 };
  let series = loadSeries();
  let range = (() => { try { return RANGES[localStorage.getItem('netdeck.dashboard.range')] ? localStorage.getItem('netdeck.dashboard.range') : '1h'; } catch (e) { return '1h'; } })();
  let saveTimer = null;

  function loadSeries() {
    try { const j = JSON.parse(localStorage.getItem(SKEY) || 'null'); if (j && Array.isArray(j.samples)) return { samples: j.samples, speed: j.speed || [], monitors: j.monitors || [], trace: j.trace || null, ingested: j.ingested || [], traffic: j.traffic || [] }; } catch (e) { /* blocked or corrupt */ }
    return { samples: [], speed: [], monitors: [], trace: null, ingested: [], traffic: [] };
  }
  function saveSeries() { clearTimeout(saveTimer); saveTimer = setTimeout(() => { try { localStorage.setItem(SKEY, JSON.stringify(series)); } catch (e) { /* quota: the charts just get shorter */ } }, 400); }
  const num = (x) => (Number.isFinite(+x) && +x >= 0 ? +x : null);

  /* One sample per health tick: [t, router ms | null (lost) | -1 (no gateway), internet ms | null]. */
  function recordHealth() {
    const H = D.health() || {};
    const g = (H.gateway || []).slice(-1)[0], n = (H.internet || []).slice(-1)[0];
    const s = n || g;
    if (!s) return;
    const last = series.samples[series.samples.length - 1];
    if (last && last[0] >= s.t) return;
    series.samples.push([s.t, g && g.t === s.t ? g.v : -1, n && n.t === s.t ? n.v : -1]);
    if (series.samples[0][0] < s.t - SAMPLE_KEEP) series.samples = series.samples.filter((x) => x[0] >= s.t - SAMPLE_KEEP);
    saveSeries();
  }

  /* A saved run or playbook: keep what the charts need. Returns true when something was taken. */
  function ingest(h) {
    if (!h || !h.hid || series.ingested.includes(h.hid)) return false;
    const t = h.endedAt || h.startedAt || Date.now();
    const ctx = D.context() || {};
    let used = false;
    const consider = (cmdId, out, params) => {
      if (!out) return;
      const summary = () => { const m = out.match(/^SUMMARY (\{.*\})\s*$/m); if (!m) return null; try { return JSON.parse(m[1]); } catch (e) { return null; } };
      if (cmdId === 'speed-test') {
        const d = summary(); if (!d) return;
        series.speed.push({ t, hid: h.hid, down: num(d.downMbps), up: num(d.upMbps), idle: num(d.idleMs), jitter: num(d.jitterMs), bloat: num(d.bloatMs), grade: String(d.grade || '').charAt(0), colo: d.colo || '' });
        used = true;
      } else if (cmdId === 'stability-monitor') {
        const d = summary(); if (!d || !d.internet) return;
        series.monitors.push({ t, hid: h.hid, router: d.router || null, internet: d.internet });
        used = true;
      } else if (cmdId === 'tracert') {
        const c = D.PB.check('tracertPath', out, params || {}, ctx, {});
        if (!c.data || !c.data.hops || !c.data.hops.length) return;
        const host = String((params && params.host) || '').replace(/\{(\w+)\}/g, (m, k) => (h.params && h.params[k]) || ctx[k] || m);
        series.trace = { t, hid: h.hid, host, target: c.data.target || '', hops: c.data.hops.map((x) => ({ n: x.n, addr: x.addr || '', ms: x.ms == null ? null : x.ms })), reached: c.data.reached, jump: c.data.jump ? { n: c.data.jump.at.n, delta: c.data.jump.delta } : null, where: c.data.where || '', summary: c.summary, status: c.status };
        used = true;
      }
    };
    if (h.kind === 'run') consider(h.cmdId, h.output, h.params);
    else if (h.kind === 'playbook') { const pb = D.PB.get(h.pbId); (h.steps || []).forEach((s, i) => { const spec = pb && pb.steps[i]; if (spec) consider(spec.cmd, s.output, spec.params); }); }
    series.ingested.push(h.hid);
    if (series.ingested.length > 120) series.ingested.splice(0, series.ingested.length - 120);
    if (series.speed.length > 100) series.speed.splice(0, series.speed.length - 100);
    if (series.monitors.length > 50) series.monitors.splice(0, series.monitors.length - 50);
    saveSeries();
    return used;
  }
  /* Forget kept results. The runs stay in History; their ids stay in the ingested list, so they are not picked up again. */
  function clearSeries(what) {
    if (what === 'speed') { if (!series.speed.length || !window.confirm(`Forget all ${series.speed.length} speed test${series.speed.length === 1 ? '' : 's'} kept on the dashboard? The runs themselves stay in History.`)) return; series.speed = []; }
    else if (what === 'trace') { if (!series.trace || !window.confirm('Forget the last traceroute shown on the dashboard? The run itself stays in History.')) return; series.trace = null; }
    else return;
    saveSeries();
    render();
  }
  function backfill() { let any = false; for (const h of (D.history() || []).slice().reverse()) if (ingest(h)) any = true; return any; }

  const clockShort = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
  const dayShort = (ts) => new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const when = (ts) => (Date.now() - ts < 20 * 3600 * 1000 ? clockShort(ts) : `${dayShort(ts)} ${clockShort(ts)}`);

  /* Router and internet latency over the chosen range: one line each (average per bin), red marks where pings were lost. */
  function latencyChart(to) {
    const from = to - RANGES[range];
    const W = 720, H = 150, padL = 34, padR = 8, padT = 8, padB = 18;
    const bins = Math.max(12, Math.min(180, Math.floor(RANGES[range] / 20000)));   // a bin is never shorter than two ticks
    const step = (to - from) / bins, plotW = W - padL - padR, plotH = H - padT - padB;
    const mk = () => Array.from({ length: bins }, () => ({ sum: 0, max: 0, cnt: 0, lost: 0 }));
    const rows = { g: mk(), n: mk() };
    const add = (b, v) => { if (v === -1 || v === undefined) return; if (v === null) { b.lost++; return; } b.sum += v; b.cnt++; if (v > b.max) b.max = v; };
    let samples = 0;
    for (const [t, g, n] of series.samples) { if (t < from || t > to) continue; const i = Math.min(bins - 1, Math.floor((t - from) / step)); add(rows.g[i], g); add(rows.n[i], n); samples++; }
    const avgs = [...rows.g, ...rows.n].filter((b) => b.cnt).map((b) => b.sum / b.cnt).sort((a, b) => a - b);
    const yMax = Math.max(20, Math.ceil(((avgs[Math.floor(avgs.length * 0.97)] || 0) * 1.2) / 10) * 10);
    const x = (i) => padL + ((i + 0.5) / bins) * plotW;
    const y = (v) => padT + (1 - Math.min(v, yMax) / yMax) * plotH;
    // one empty bin is bridged (a missed tick); a longer gap breaks the line
    const path = (bs) => { let d = '', open = false, empty = 0; bs.forEach((b, i) => { if (!b.cnt) { if (++empty > 1) open = false; return; } empty = 0; d += (open ? ' L' : ' M') + `${x(i).toFixed(1)} ${y(b.sum / b.cnt).toFixed(1)}`; open = true; }); return d.trim(); };
    const dots = (bs, cls) => bs.map((b, i) => (b.cnt && !(bs[i - 1] && bs[i - 1].cnt) && !(bs[i + 1] && bs[i + 1].cnt)) ? `<circle cx="${x(i).toFixed(1)}" cy="${y(b.sum / b.cnt).toFixed(1)}" r="2" class="dot ${cls}"/>` : '').join('');
    const loss = (bs) => bs.map((b, i) => { if (!b.lost) return ''; const hgt = Math.max(3, (b.lost / (b.cnt + b.lost)) * plotH); return `<rect x="${(x(i) - 1.5).toFixed(1)}" y="${(H - padB - hgt).toFixed(1)}" width="3" height="${hgt.toFixed(1)}" class="loss"/>`; }).join('');
    const fmt = (b) => (b.cnt ? `avg ${Math.round(b.sum / b.cnt)} ms, max ${Math.round(b.max)} ms${b.lost ? `, ${b.lost} lost` : ''}` : b.lost ? `${b.lost} lost` : '—');
    const hits = rows.g.map((b, i) => (b.cnt || b.lost || rows.n[i].cnt || rows.n[i].lost) ? `<rect x="${(x(i) - plotW / bins / 2).toFixed(1)}" y="0" width="${(plotW / bins).toFixed(2)}" height="${H}" class="hit"><title>${esc(when(from + i * step))} — router ${esc(fmt(b))} · internet ${esc(fmt(rows.n[i]))}</title></rect>` : '').join('');
    const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => `<text x="${(padL + f * plotW).toFixed(1)}" y="${H - 4}" class="ax" text-anchor="${f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}">${esc(clockShort(from + f * (to - from)))}</text>`).join('');
    const grid = [0.5, 1].map((f) => `<line x1="${padL}" y1="${y(yMax * f).toFixed(1)}" x2="${W - padR}" y2="${y(yMax * f).toFixed(1)}" class="grid"/><text x="${padL - 4}" y="${(y(yMax * f) + 3.5).toFixed(1)}" class="ax" text-anchor="end">${Math.round(yMax * f)}</text>`).join('');
    const stat = (bs) => { let sum = 0, cnt = 0, max = 0, lost = 0; for (const b of bs) { sum += b.sum; cnt += b.cnt; lost += b.lost; if (b.max > max) max = b.max; } return cnt || lost ? { avg: cnt ? Math.round(sum / cnt) : null, max: Math.round(max), lossPct: Math.round((lost / (cnt + lost)) * 1000) / 10, lost } : null; };
    const svg = samples
      ? `<svg class="dash-chart-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Router and internet latency over the last ${range}"><line x1="${padL}" y1="${H - padB}" x2="${W - padR}" y2="${H - padB}" class="base"/>${grid}${loss(rows.n)}${loss(rows.g)}<path d="${path(rows.n)}" class="line l-n"/><path d="${path(rows.g)}" class="line l-g"/>${dots(rows.n, 'l-n')}${dots(rows.g, 'l-g')}${ticks}${hits}</svg>`
      : `<p class="dash-empty">No samples in the last ${range} yet. NetDeck records the router and internet ping every 10 seconds while it is open.</p>`;
    return { svg, g: stat(rows.g), n: stat(rows.n), samples };
  }

  function latencyBody() {
    const now = Date.now();
    const c = latencyChart(now);
    const line = (label, s, cls) => s ? `<span class="dash-stat"><span class="dash-swatch ${cls}"></span>${esc(label)} <b>${s.avg != null ? `${s.avg} ms` : '—'}</b> avg · worst ${s.max} ms · ${s.lossPct ? `<span class="dash-loss">${s.lossPct}% lost</span>` : 'no loss'}</span>` : `<span class="dash-stat"><span class="dash-swatch ${cls}"></span>${esc(label)} —</span>`;
    const mons = series.monitors.slice(-4).reverse().map((m) => {
      const one = (k, d) => d ? `${k} ${d.sent - d.lost}/${d.sent}${d.pct ? ` (${d.pct}% lost)` : ''}, ${d.avg} ms, jitter ${d.jitter} ms${d.bursts ? `, ${d.bursts} loss run${d.bursts === 1 ? '' : 's'}` : ''}` : '';
      const bad = (d) => d && (d.bursts >= 1 || (d.lost >= 3 && d.pct >= 1));
      return `<li class="dash-check" data-status="${bad(m.router) ? 'fail' : bad(m.internet) ? 'warn' : 'pass'}"><span class="dash-dot"></span><span class="dash-check-name">${esc(when(m.t))}</span><span class="dash-check-sum">${esc([one('router', m.router), one('internet', m.internet)].filter(Boolean).join(' — '))}</span></li>`;
    }).join('');
    return `<div class="dash-chart">${c.svg}</div><div class="dash-stats">${line('router', c.g, 'l-g')}${line('internet', c.n, 'l-n')}<span class="dash-stat dim">${c.samples} samples</span></div>${mons ? `<p class="dash-sub">Longer monitors (one ping a second):</p><ul class="dash-checks">${mons}</ul>` : ''}`;
  }

  /* The two chart cards start folded to their header with a one-line summary, every time NetDeck opens;
     unfolding one lasts for the session. */
  const collapsed = new Set(['latency', 'traffic']);
  const collapseBtn = (key) => `<button type="button" class="dash-collapse" data-collapse="${key}" aria-expanded="${!collapsed.has(key)}" title="${collapsed.has(key) ? 'Expand' : 'Collapse'} this card">${collapsed.has(key) ? '&#x25B8;' : '&#x25BE;'}</button>`;
  function toggleCollapse(key) {
    if (collapsed.has(key)) collapsed.delete(key); else collapsed.add(key);
    const el = els.grid.querySelector(`#dash-${key}`);
    if (el) el.outerHTML = key === 'latency' ? latencyCard() : trafficCard();
    if (key === 'traffic') { if (collapsed.has(key)) stopTraffic(); else if (shown && D.canRun()) startTraffic(); }
  }

  function latencyCard() {
    const folded = collapsed.has('latency');
    if (folded) {
      const c = latencyChart(Date.now());
      const one = (label, s) => (s && s.avg != null ? `${label} ${s.avg} ms${s.lossPct ? ` (${s.lossPct}% lost)` : ''}` : `${label} —`);
      return `<article class="card dash-card dash-wide is-collapsed" id="dash-latency"><header class="card-head"><h2 class="card-name">Latency &amp; loss</h2><span class="dash-collapsed-sum">${esc(one('router', c.g))} · ${esc(one('internet', c.n))} · last ${esc(range)}</span>${collapseBtn('latency')}</header></article>`;
    }
    const ranges = Object.keys(RANGES).map((r) => `<button type="button" class="tbtn tbtn-sm${r === range ? ' is-on' : ''}" data-range="${r}" aria-pressed="${r === range}">${r}</button>`).join('');
    const foot = `<span>router and internet ping every 10 s while NetDeck is open · hover the chart for a moment's figures</span><span class="dash-links">${pbBtn('Does my connection drop out?', 'dropouts')}${pbBtn('Why is everything slow?', 'slow')}</span>`;
    return `<article class="card dash-card dash-wide" id="dash-latency"><header class="card-head"><h2 class="card-name">Latency &amp; loss</h2><span class="dash-head-tools"><span class="dash-ranges" role="group" aria-label="Range">${ranges}</span>${collapseBtn('latency')}</span></header><div id="dash-latency-body">${latencyBody()}</div><footer class="dash-foot">${foot}</footer></article>`;
  }

  const GRADE = { A: 'ok', B: 'ok', C: 'warn', D: 'err' };
  function speedCard() {
    const runs = series.speed.slice(-20);
    const last = runs[runs.length - 1];
    const foot = (extra, clear) => `<span>${extra}</span><span class="dash-links">${btn('Run speed test', 'speed-test')}${pbBtn('Why is everything slow?', 'slow')}${clear ? '<button type="button" class="tbtn tbtn-sm dash-clear" data-clear="speed" title="Forget every speed test kept here">Clear</button>' : ''}</span>`;
    if (!last) return card('Speed tests', '', '<p class="dash-empty">No speed test yet. Each run (about half a minute, against speed.cloudflare.com) is kept here: download, upload, idle latency and the bufferbloat grade, so you can see whether the line is getting better or worse.</p>', foot('from the run history'));
    const mb = (v) => (v == null ? '—' : v >= 100 ? Math.round(v) : v.toFixed(1));
    const big = `<div class="dash-big"><div><span class="dash-big-n">${mb(last.down)}</span><span class="dash-big-l">down Mbit/s</span></div><div><span class="dash-big-n">${mb(last.up)}</span><span class="dash-big-l">up Mbit/s</span></div><div><span class="dash-big-n">${last.idle == null ? '—' : last.idle}</span><span class="dash-big-l">idle ms</span></div><div><span class="dash-big-n" data-state="${GRADE[last.grade] || 'idle'}">${esc(last.grade || '—')}</span><span class="dash-big-l">bufferbloat${last.bloat != null ? ` +${last.bloat} ms` : ''}</span></div></div>`;
    const W = 320, H = 90, padB = 14, padT = 4;
    const max = Math.max(1, ...runs.map((r) => Math.max(r.down || 0, r.up || 0)));
    const slot = W / Math.max(runs.length, 6), bw = Math.max(3, slot * 0.32);
    const bars = runs.map((r, i) => {
      const x0 = i * slot + slot * 0.15;
      const hD = ((r.down || 0) / max) * (H - padT - padB), hU = ((r.up || 0) / max) * (H - padT - padB);
      return `<g><title>${esc(when(r.t))} — down ${mb(r.down)}, up ${mb(r.up)} Mbit/s, idle ${r.idle == null ? '—' : r.idle + ' ms'}, bufferbloat ${esc(r.grade || '—')}${r.colo ? ` · via ${esc(r.colo)}` : ''}</title><rect x="${x0.toFixed(1)}" y="${(H - padB - hD).toFixed(1)}" width="${bw.toFixed(1)}" height="${hD.toFixed(1)}" class="bar-d"/><rect x="${(x0 + bw + 1).toFixed(1)}" y="${(H - padB - hU).toFixed(1)}" width="${bw.toFixed(1)}" height="${hU.toFixed(1)}" class="bar-u"/></g>`;
    }).join('');
    const labels = runs.length > 1 ? `<text x="0" y="${H - 2}" class="ax">${esc(dayShort(runs[0].t))}</text><text x="${((runs.length - 1) * slot + slot * 0.15 + bw).toFixed(1)}" y="${H - 2}" class="ax" text-anchor="end">${esc(dayShort(last.t))}</text>` : '';
    const chart = `<svg class="dash-chart-svg dash-bars-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Past speed tests"><line x1="0" y1="${H - padB}" x2="${W}" y2="${H - padB}" class="base"/>${bars}${labels}</svg><div class="dash-stats"><span class="dash-stat"><span class="dash-swatch bar-d"></span>download</span><span class="dash-stat"><span class="dash-swatch bar-u"></span>upload</span><span class="dash-stat dim">${runs.length} run${runs.length === 1 ? '' : 's'} · hover a bar</span></div>`;
    return card('Speed tests', when(last.t), big + chart, foot(`last run ${ago(last.t)}${last.colo ? ` · via ${esc(last.colo)}` : ''}`, true));
  }

  function routeCard() {
    const tr = series.trace;
    const host = (tr && tr.host) || '1.1.1.1';
    const links = `${btn('Trace now', 'tracert', { host }, 'quick')}${pbBtn('Where does the path break?', 'path')}`;
    if (!tr) return card('Route to the internet', '', '<p class="dash-empty">No traceroute yet. "Trace now" follows the path to 1.1.1.1 hop by hop — your router first, then your provider, then the internet — and shows where the delay is added.</p>', `<span>from the run history</span><span class="dash-links">${links}</span>`);
    const answered = tr.hops.filter((h) => h.ms != null);
    const max = Math.max(1, ...answered.map((h) => h.ms));
    const chain = tr.hops.map((h) => {
      const net = h.addr ? D.P.classifyIp(h.addr) : 'silent';
      const jump = tr.jump && tr.jump.n === h.n;
      const hgt = h.ms == null ? 0 : Math.max(2, Math.round((h.ms / max) * 28));
      return `<div class="dash-hop${jump ? ' is-jump' : ''}" data-net="${net}" title="hop ${h.n}: ${h.addr || 'no reply'}${h.ms != null ? `, ${h.ms} ms` : ''}${jump ? ` — latency jumps +${tr.jump.delta} ms here` : ''}"><span class="dash-hop-bar" style="height:${hgt}px"></span><span class="dash-hop-n">${h.n}</span><span class="dash-hop-ms">${h.ms == null ? '*' : `${h.ms} ms`}</span><span class="dash-hop-addr">${esc(h.addr || 'no reply')}</span></div>`;
    }).join('');
    const legend = '<div class="dash-stats"><span class="dash-stat"><span class="dash-swatch net-private"></span>your network</span><span class="dash-stat"><span class="dash-swatch net-cgnat"></span>provider</span><span class="dash-stat"><span class="dash-swatch net-public"></span>internet</span><span class="dash-stat"><span class="dash-swatch net-silent"></span>no reply</span></div>';
    const body = `<p class="dash-verdict" data-tone="${TONE[tr.status] || 'idle'}">${esc(tr.summary || '')}</p><div class="dash-chain">${chain}</div>${legend}`;
    return card('Route to the internet', `${esc(host)} · ${when(tr.t)}`, body, `<span>tracert -d ${esc(host)} · ${ago(tr.t)} · the bar over each hop is its round-trip time</span><span class="dash-links">${links}<button type="button" class="tbtn tbtn-sm dash-clear" data-clear="trace" title="Forget this trace">Clear</button></span>`);
  }

  /* ================= traffic: adapter byte counters every few seconds while the dashboard is showing ================= */
  const TRAFFIC_MS = 6000, TRAFFIC_KEEP = 60 * 60000;
  let trafficTimer = null, trafficPrev = null, trafficBusy = false, trafficLatest = null;

  async function pollTraffic() {
    if (trafficBusy || !shown || document.hidden || !D.canRun()) return;
    const cmd = D.byId.get('adapter-stats');
    if (!cmd || !cmd.runnable) return;
    trafficBusy = true;
    try {
      const r = await D.execute(cmd, {});
      const m = (r.output || '').match(/^STATS (\{.*\})\s*$/m);
      if (m) {
        const d = JSON.parse(m[1]);
        const now = Number(d.t) || Date.now();
        const adapters = Array.isArray(d.adapters) ? d.adapters : [d.adapters].filter(Boolean);
        if (trafficPrev && now > trafficPrev.t) {
          const dt = (now - trafficPrev.t) / 1000;
          for (const a of adapters) {
            const p = trafficPrev.by[a.name];
            if (!p || a.rx < p.rx || a.tx < p.tx) continue;   // counters reset (adapter bounced): skip one interval
            series.traffic.push([now, a.name, Math.round(((a.rx - p.rx) * 8) / dt), Math.round(((a.tx - p.tx) * 8) / dt)]);
          }
          if (series.traffic.length && series.traffic[0][0] < now - TRAFFIC_KEEP) series.traffic = series.traffic.filter((x) => x[0] >= now - TRAFFIC_KEEP);
          saveSeries();
        }
        trafficPrev = { t: now, by: Object.fromEntries(adapters.map((a) => [a.name, a])) };
        trafficLatest = { t: now, adapters };
        if (shown) { const el = els.grid.querySelector('#dash-traffic-body'); if (el) el.innerHTML = trafficBody(); }
      }
    } catch (e) { /* next tick */ }
    trafficBusy = false;
  }
  function startTraffic() { if (trafficTimer) return; pollTraffic(); trafficTimer = setInterval(pollTraffic, TRAFFIC_MS); }
  function stopTraffic() { clearInterval(trafficTimer); trafficTimer = null; }

  const fmtBps = (b) => (b == null ? '—' : b >= 1e9 ? `${(b / 1e9).toFixed(2)} Gbit/s` : b >= 1e6 ? `${(b / 1e6).toFixed(b >= 1e8 ? 0 : 1)} Mbit/s` : b >= 1e3 ? `${Math.round(b / 1e3)} kbit/s` : `${b} bit/s`);
  const fmtBytes = (n) => (n >= 1e12 ? `${(n / 1e12).toFixed(2)} TB` : n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n >= 1e6 ? `${Math.round(n / 1e6)} MB` : `${Math.round(n / 1e3)} kB`);

  function trafficChart(name, to) {
    const from = to - 10 * 60000;
    const pts = series.traffic.filter((x) => x[1] === name && x[0] >= from);
    if (pts.length < 2) return '';
    const W = 720, H = 80, padL = 46, padR = 8, padT = 6, padB = 16, plotW = W - padL - padR, plotH = H - padT - padB;
    const max = Math.max(1e6, ...pts.map((p) => Math.max(p[2], p[3])));
    const x = (t) => padL + ((t - from) / (to - from)) * plotW;
    const y = (v) => padT + (1 - Math.min(v, max) / max) * plotH;
    const path = (k) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(p[0]).toFixed(1)} ${y(p[k]).toFixed(1)}`).join(' ');
    const peakRx = Math.max(...pts.map((p) => p[2])), peakTx = Math.max(...pts.map((p) => p[3]));
    const ticks = [0, 0.5, 1].map((f) => `<text x="${(padL + f * plotW).toFixed(1)}" y="${H - 3}" class="ax" text-anchor="${f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}">${esc(clockShort(from + f * (to - from)))}</text>`).join('');
    return `<svg class="dash-chart-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Traffic on ${esc(name)} over the last 10 minutes"><title>${esc(name)}, last 10 min — peak down ${esc(fmtBps(peakRx))}, peak up ${esc(fmtBps(peakTx))}</title><line x1="${padL}" y1="${H - padB}" x2="${W - padR}" y2="${H - padB}" class="base"/><line x1="${padL}" y1="${y(max).toFixed(1)}" x2="${W - padR}" y2="${y(max).toFixed(1)}" class="grid"/><text x="${padL - 4}" y="${(y(max) + 3.5).toFixed(1)}" class="ax" text-anchor="end">${esc(fmtBps(max))}</text><path d="${path(3)}" class="line l-n"/><path d="${path(2)}" class="line l-g"/>${ticks}</svg>`;
  }

  function trafficBody() {
    const ctx = D.context() || {};
    const L = trafficLatest;
    if (!L) return '<p class="dash-empty">Reading the adapter counters — a sample every 6 seconds while the dashboard is showing.</p>';
    const primary = L.adapters.find((a) => a.name === ctx.adapter) || L.adapters.find((a) => !a.virtual) || L.adapters[0];
    if (!primary) return '<p class="dash-empty">No adapter is up.</p>';
    const last = series.traffic.filter((x) => x[1] === primary.name).slice(-1)[0];
    const rx = last ? last[2] : null, tx = last ? last[3] : null;
    const util = primary.speed && rx != null ? Math.round((Math.max(rx, tx) / primary.speed) * 1000) / 10 : null;
    const big = `<div class="dash-big"><div><span class="dash-big-n">${esc(fmtBps(rx))}</span><span class="dash-big-l">down</span></div><div><span class="dash-big-n">${esc(fmtBps(tx))}</span><span class="dash-big-l">up</span></div><div><span class="dash-big-n">${primary.speed ? esc(fmtBps(primary.speed)) : '—'}</span><span class="dash-big-l">link${util != null ? ` · ${util}% used` : ''}</span></div><div><span class="dash-big-n">${esc(fmtBytes(primary.rx))}</span><span class="dash-big-l">received since boot · ${esc(fmtBytes(primary.tx))} sent</span></div></div>`;
    const chart = trafficChart(primary.name, L.t) || '<p class="dash-sub">The chart appears after a second sample.</p>';
    const others = L.adapters.filter((a) => a !== primary).map((a) => { const p = series.traffic.filter((x) => x[1] === a.name).slice(-1)[0]; return `<li class="dash-check" data-status="info"><span class="dash-dot"></span><span class="dash-check-name">${esc(a.name)}</span><span class="dash-check-sum">${p ? `↓ ${esc(fmtBps(p[2]))} · ↑ ${esc(fmtBps(p[3]))}` : 'waiting for a second sample'}${a.virtual ? ' · virtual' : ''}</span></li>`; }).join('');
    return `${big}<div class="dash-chart">${chart}</div><div class="dash-stats"><span class="dash-stat"><span class="dash-swatch l-g"></span>down</span><span class="dash-stat"><span class="dash-swatch l-n"></span>up</span><span class="dash-stat dim">${esc(primary.name)} · last 10 min</span></div>${others ? `<ul class="dash-checks">${others}</ul>` : ''}`;
  }

  function trafficCard() {
    if (collapsed.has('traffic')) {
      const ctx = D.context() || {};
      const name = (trafficLatest && ((trafficLatest.adapters.find((a) => a.name === ctx.adapter) || trafficLatest.adapters[0]) || {}).name) || ctx.adapter;
      const last = name ? series.traffic.filter((x) => x[1] === name).slice(-1)[0] : null;
      const sum = last ? `${esc(name)} ↓ ${esc(fmtBps(last[2]))} · ↑ ${esc(fmtBps(last[3]))} · ${esc(ago(last[0]))} · sampling paused` : 'sampling paused — expand to read the adapter';
      return `<article class="card dash-card dash-wide is-collapsed" id="dash-traffic"><header class="card-head"><h2 class="card-name">Traffic</h2><span class="dash-collapsed-sum">${sum}</span>${collapseBtn('traffic')}</header></article>`;
    }
    const foot = `<span>Get-NetAdapterStatistics every 6 s while this view is open · rates are over each interval</span><span class="dash-links">${btn('Throughput monitor', 'throughput')}${pbBtn('Who is this PC talking to?', 'outbound')}</span>`;
    return `<article class="card dash-card dash-wide" id="dash-traffic"><header class="card-head"><h2 class="card-name">Traffic</h2><span class="dash-head-tools"><span class="card-cat">${trafficLatest ? esc(clock(trafficLatest.t)) : ''}</span>${collapseBtn('traffic')}</span></header><div id="dash-traffic-body">${trafficBody()}</div><footer class="dash-foot">${foot}</footer></article>`;
  }

  /* ================= security posture: the live firewall state plus the latest run of each security check ================= */
  const TONE_STATUS = { pass: 'pass', warn: 'warn', fail: 'fail' };
  function postureCard() {
    const T = snap.tiles;
    const H = D.history() || [];
    const lastRun = (cmdId) => H.find((h) => h.kind === 'run' && h.cmdId === cmdId && h.state !== 'error' && h.output);
    const rows = [];
    const row = (label, status, summary, at, action) => rows.push({ label, status, summary, at, action });
    const fw = T.fw;
    row('Firewall', fw ? fw.status : 'pending', fw ? fw.summary : 'not checked yet', fw && fw.at, btn('run', 'netsh', {}, 'advfirewall-show-allprofiles'));
    const ex = lastPlaybook('exposure');
    row('Exposed services', ex ? TONE_STATUS[ex.verdict.tone] || 'info' : 'pending', ex ? ((ex.steps && ex.steps[1] && ex.steps[1].summary) || ex.verdict.text.slice(0, 160)) : 'run "What is this PC exposing?"', ex && (ex.endedAt || ex.startedAt), pbBtn('run', 'exposure'));
    const fa = lastRun('fw-audit');
    if (fa) {
      const line = fa.output.split(/\r?\n/).find((l) => /^(Reasonable|Attention|PROBLEM|Wide open|Exposed|Danger)/i.test(l.trim())) || '';
      row('Firewall rules', /^Reasonable/i.test(line.trim()) ? 'pass' : /^Attention/i.test(line.trim()) ? 'warn' : line ? 'fail' : 'info', line.trim().slice(0, 200) || 'audit ran — open it for the verdict', fa.endedAt || fa.startedAt, btn('run', 'fw-audit'));
    } else row('Firewall rules', 'pending', 'run the firewall rule audit', null, btn('run', 'fw-audit'));
    const px = lastPlaybook('proxy');
    row('Proxy & HTTPS inspection', px ? TONE_STATUS[px.verdict.tone] || 'info' : 'pending', px ? px.verdict.text.slice(0, 160) : 'run "Proxy & HTTPS inspection"', px && (px.endedAt || px.startedAt), pbBtn('run', 'proxy'));
    const dh = lastPlaybook('dnshonest');
    row('DNS honesty', dh ? TONE_STATUS[dh.verdict.tone] || 'info' : 'pending', dh ? ((dh.steps && dh.steps[0] && dh.steps[0].summary) || '') : 'run "Is my DNS honest?"', dh && (dh.endedAt || dh.startedAt), pbBtn('run', 'dnshonest'));
    if (dh && dh.steps && dh.steps[1]) row('Hosts file & DNS cache', dh.steps[1].status || 'info', dh.steps[1].summary || '', dh.endedAt || dh.startedAt, btn('run', 'hosts-audit'));
    const rc = lastPlaybook('routercheck');
    row('Router', rc ? TONE_STATUS[rc.verdict.tone] || 'info' : 'pending', rc ? ((rc.steps && rc.steps[0] && rc.steps[0].summary) || '') : 'run "Router check-up"', rc && (rc.endedAt || rc.startedAt), pbBtn('run', 'routercheck'));
    const n = { pass: 0, warn: 0, fail: 0, pending: 0 };
    rows.forEach((r) => { n[r.status in n ? r.status : 'pending']++; });
    let tone = 'idle', text;
    if (n.fail) { tone = 'err'; text = `${n.fail} check${n.fail === 1 ? '' : 's'} found a problem${n.warn ? ` and ${n.warn} want${n.warn === 1 ? 's' : ''} a look` : ''}.`; }
    else if (n.warn) { tone = 'warn'; text = `Nothing broken, but ${n.warn} check${n.warn === 1 ? '' : 's'} want${n.warn === 1 ? 's' : ''} a look.`; }
    else if (n.pass && !n.pending) { tone = 'ok'; text = 'All security checks pass.'; }
    else if (n.pass) { tone = 'ok'; text = `${n.pass} check${n.pass === 1 ? ' passes' : 's pass'}; ${n.pending} not run yet.`; }
    else text = 'No security checks run yet — each row has a run button.';
    const li = rows.map((r) => `<li class="dash-check dash-check-stack" data-status="${esc(r.status)}"><span class="dash-dot"></span><span class="dash-check-body"><span class="dash-check-name">${esc(r.label)}</span><span class="dash-check-sum">${esc(r.summary)}${r.at ? ` <small class="dash-age">· ${esc(ago(r.at))}</small>` : ''}</span></span>${r.action}</li>`).join('');
    const body = `<p class="dash-verdict" data-tone="${tone}">${esc(text)}</p><ul class="dash-checks">${li}</ul>`;
    const foot = `<span>firewall state is live; the rest shows the latest run of each check</span><span class="dash-links">${btn('Listening ports', 'listeners')}${pbBtn('What is this PC exposing?', 'exposure')}</span>`;
    return card('Security posture', `${n.pass} / ${rows.length} pass`, body, foot);
  }

  /* ================= snapshot: the dashboard as one self-contained HTML page ================= */
  async function snapshot(anonymise) {
    const anon = anonymise && D.anonymiser ? D.anonymiser() : (t) => t;
    let css = '';
    try { css = await (await fetch('styles.css')).text(); } catch (e) { css = ''; }
    const clone = document.createElement('div');
    clone.innerHTML = `<section class="dash-strip">${els.strip.innerHTML}</section><section class="grid dash-grid">${els.grid.innerHTML}</section>`;
    clone.querySelectorAll('.dash-links, .dash-ranges, button.tbtn').forEach((el) => el.remove());
    clone.querySelectorAll('button.dash-chip').forEach((b) => {
      const d = document.createElement('div');
      for (const a of b.attributes) if (!/^(type|data-run|data-params|data-preset|data-pb)$/.test(a.name)) d.setAttribute(a.name, a.value);
      d.innerHTML = b.innerHTML;
      b.replaceWith(d);
    });
    const walker = document.createTreeWalker(clone, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const t of nodes) t.nodeValue = anon(t.nodeValue);
    clone.querySelectorAll('[title]').forEach((el) => el.setAttribute('title', anon(el.getAttribute('title'))));
    const theme = document.documentElement.dataset.theme || '';
    const when = new Date();
    const ctx = D.context() || {};
    const html = `<!doctype html><html lang="en"${theme ? ` data-theme="${esc(theme)}"` : ''}><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>NetDeck dashboard — ${esc(when.toLocaleString())}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>${css}
body { padding-block: 24px; }
.snap-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 14px; }
.snap-head h1 { margin: 0; font-size: 18px; color: var(--bright); }
.snap-meta { color: var(--muted); font-size: 12.5px; }
.snap-foot { margin-top: 24px; color: var(--muted); font-size: 12px; }
.print { font: 12px var(--mono); padding: 4px 10px; border: 1px solid var(--border); border-radius: 5px; background: var(--surface); color: var(--text); cursor: pointer; }
.dash-chip { cursor: default; }
@media print { .print { display: none; } .dash-card { break-inside: avoid; } }
</style></head><body>
<div class="snap-head"><div><h1>NetDeck dashboard snapshot</h1><div class="snap-meta">${esc(when.toLocaleString())}${ctx.hostname ? ` · ${esc(anon(ctx.hostname))}` : ''} · NetDeck ${esc(window.NETDECK_VERSION || '')}${anonymise ? ' · anonymised: computer name, addresses and MACs replaced' : ''}</div></div><button class="print" onclick="window.print()">Print / save as PDF</button></div>
${clone.innerHTML}
<p class="snap-foot">Every figure came from a command NetDeck ran on this computer; the tiles and cards are as they were on screen when the snapshot was saved. Generated by NetDeck — network &amp; system command reference.</p>
</body></html>`;
    D.saveFile(`netdeck-dashboard-${when.toISOString().replace(/[:T]/g, '-').slice(0, 19)}.html`, html, 'text/html');
  }

  return { init, show, hide, poke, refresh, backfill, snapshot };
})();
