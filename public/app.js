/* NetDeck front end: reference browser, tabbed live terminal, table view, playbooks, history,
   presets, help viewer, health strip, find/wrap/save, command palette, pinning, deep links,
   custom commands, notifications, keyboard navigation, and a static (hosted) mode that can
   optionally pair with a local NetDeck server. */
(() => {
  const P = window.NetDeckParsers;
  const PB = window.NetDeckPlaybooks;

  const $ = (id) => document.getElementById(id);
  const grid = $('grid'), emptyMsg = $('empty'), resultCount = $('result-count');
  const searchInput = $('search'), platformRow = $('platform-filters'), categoryRow = $('category-filters');
  const template = $('card-template'), playbookGrid = $('playbook-grid'), pbGroupRow = $('pb-group-filters');
  const viewCommands = $('view-commands'), viewPlaybooks = $('view-playbooks'), viewDashboard = $('view-dashboard');
  const DASH = window.NetDeckDashboard;
  const terminal = $('terminal'), tabStrip = $('tab-strip'), tabStripEmpty = $('tab-strip-empty');
  const panes = $('panes'), paneEmpty = $('pane-empty');
  const viewBtn = $('term-view'), stopBtn = $('term-stop'), copyBtn = $('term-copy');
  const historyBtn = $('term-history'), sizeBtn = $('term-size'), toggleBtn = $('term-toggle');
  const closeAllBtn = $('term-close-all'), notifyBtn = $('term-notify');
  const historyPanel = $('history-panel'), historyList = $('history-list'), historyEmpty = $('history-empty');
  const palette = $('palette'), paletteInput = $('palette-input'), paletteList = $('palette-list');

  const COPY_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="9" height="9" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M11 3H3.5A1.5 1.5 0 0 0 2 4.5V12" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>';
  const CHECK_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8.5 6.5 12 13 4.5" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>';
  const LINK_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 9.5 9.5 6.5M7 4.5l1.2-1.2a2.5 2.5 0 0 1 3.5 3.5L10.5 8M9 11.5l-1.2 1.2a2.5 2.5 0 0 1-3.5-3.5L5.5 8" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';

  const PARAM_CHECKS = {
    host: (v) => /^[A-Za-z0-9_]([A-Za-z0-9._\-]{0,251}[A-Za-z0-9])?$/.test(v),
    port: (v) => /^\d{1,5}$/.test(v) && +v >= 1 && +v <= 65535,
    url: (v) => /^https?:\/\/\S+$/.test(v),
  };

  const HISTORY_KEY = 'netdeck.history.v1';
  const MAX_HISTORY = 30;
  const MAX_STORED_OUTPUT = 60000;
  const HEALTH_INTERVAL = 10000;
  const HEALTH_SAMPLES = 40;

  /* ---------- mode: Tauri desktop app, local server, or a static copy on a web host ---------- */
  const BACKEND = window.NetDeckAPI;
  const TAURI = BACKEND.kind === 'tauri';
  const STATIC = !TAURI && window.NETDECK_STATIC === true;
  let API = STATIC ? readPref('netdeck.agent.url', '') : '';
  let TOKEN = STATIC ? readPref('netdeck.agent.token', '') : '';
  if (STATIC) BACKEND.configure({ base: API, token: TOKEN });
  let canRun = false;

  let commands = [];
  let platform = 'win32';
  const byId = new Map();
  let context = null;
  let activePlatform = 'all', activeCategory = 'all', query = '', activeView = 'commands', activePbGroup = 'all';
  const tabs = [];
  let activeTabId = null;
  let tabSeq = 0;
  let history = loadHistory();
  const processCache = { at: 0, map: null, pending: null };
  let wrapLines = readPref('netdeck.wrap', 'on') !== 'off';
  let notifyOn = readPref('netdeck.notify', 'off') === 'on';
  let pins = new Set(readJson('netdeck.pins', []));
  let cursorCard = null;

  /* ================= helpers ================= */
  const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false });
  const fmtDur = (ms) => (ms < 1000 ? `${ms} ms` : ms < 60000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`);
  const isWin = () => platform === 'win32';

  function readPref(key, fallback) {
    try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
  }
  function writePref(key, value) {
    try { localStorage.setItem(key, value); } catch { /* per-viewer convenience only */ }
  }
  function readJson(key, fallback) {
    try { const v = localStorage.getItem(key); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
  }

  function displayFor(cmd, params) {
    let d = cmd.win || (cmd.unix || [])[0] || cmd.name;
    for (const [k, v] of Object.entries(params || {})) {
      if (k === 'port') d = d.replace(/<port>|(?<=-Port )\d+/, v);
      else if (k === 'host') d = d.replace(/<(host|domain|target)>/, v);
      else d = d.replace(`<${k}>`, v);
    }
    return d;
  }

  // Human-readable form of a run spec (or one of its presets), with {key} → value or <key>.
  function specDisplay(spec, preset, params) {
    let tpl;
    if (preset?.display) tpl = preset.display;
    else if (!preset && spec.display) tpl = spec.display;
    else if (spec.kind === 'ps') tpl = (preset?.command ?? spec.command).split('|')[0].trim();
    else tpl = [spec.exe.replace(/\.exe$/i, ''), ...(preset?.args ?? spec.args ?? [])].join(' ');
    // %{name} is the tool's own syntax (curl -w), not one of our placeholders.
    return tpl.replace(/(?<!%)\{(\w+)\}/g, (_, k) => params?.[k] ?? `<${k}>`);
  }

  function titleFor(cmd, params, presetIdx) {
    const spec = cmd.runnable;
    const preset = presetIdx != null && spec ? spec.presets[presetIdx] : null;
    if (spec && (preset || !isWin())) return specDisplay(spec, preset, params);
    return displayFor(cmd, params);
  }

  function usedKeys(spec, preset) {
    const src = JSON.stringify(preset ? (preset.args ?? preset.command) : (spec.args ?? spec.command)) || '';
    return new Set([...src.matchAll(/(?<!%)\{(\w+)\}/g)].map((m) => m[1]));
  }

  // {key} comes from, in order: values captured by earlier playbook steps, the detected
  // network context, then the playbook's own inputs. Unknown keys resolve to ''.
  // With `mark`, a key that has no value yet is shown as <key> instead of vanishing (for display).
  function resolveTemplate(value, params, captures, mark) {
    const c = context || {};
    const fromContext = { gateway: c.gateway, dns0: c.dns?.[0], dns1: c.dns?.[1], ip: c.ip, adapter: c.adapter, hostname: c.hostname };
    return String(value).replace(/\{(\w+)\}/g, (_, key) => {
      let v;
      if (captures && captures[key] != null) v = String(captures[key]);
      else if (key in fromContext) v = fromContext[key] || '';
      else v = params?.[key] ?? '';
      return v === '' && mark ? `<${key}>` : v;
    });
  }

  // Keys in a template that nothing can fill yet.
  function unresolvedKeys(value, params, captures) {
    return [...String(value).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).filter((k) => !resolveTemplate(`{${k}}`, params, captures));
  }

  function flashOk(btn, restore) {
    btn.innerHTML = CHECK_SVG;
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = restore; btn.classList.remove('copied'); }, 1200);
  }

  function makeCopyButton(text) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn copy-btn';
    btn.title = 'Copy to clipboard';
    btn.setAttribute('aria-label', `Copy ${text}`);
    btn.innerHTML = COPY_SVG;
    btn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); flashOk(btn, COPY_SVG); }
      catch { btn.title = 'Copy failed — select the text manually'; }
    });
    return btn;
  }

  function validateInputs(inputs, keys) {
    const params = {};
    for (const [key, { el, type }] of Object.entries(inputs)) {
      if (keys && !keys.has(key)) continue;
      let value = el.value.trim();
      if (type === 'host') {
        // People paste whole addresses; keep just the host part.
        value = value.replace(/^[a-z]+:\/\//i, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
        el.value = value;
      }
      if (!PARAM_CHECKS[type](value)) {
        el.classList.add('invalid');
        el.focus();
        return null;
      }
      params[key] = value;
    }
    return params;
  }

  function buildParamInputs(specs, idPrefix, box, onEnter) {
    const inputs = {};
    let lastHostInput = null;
    specs.forEach((p) => {
      const input = document.createElement('input');
      input.className = 'param-input';
      input.id = `${idPrefix}-${p.key}`;
      input.placeholder = `${p.key} — ${p.placeholder || ''}`;
      input.autocomplete = 'off';
      input.spellcheck = false;
      input.addEventListener('input', () => input.classList.remove('invalid'));
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') onEnter(); });
      if (p.type === 'host') input.addEventListener('focus', () => { lastHostInput = input; });
      inputs[p.key] = { el: input, type: p.type };
      box.appendChild(input);
    });
    return { inputs, target: () => (lastHostInput && !lastHostInput.hidden ? lastHostInput : Object.values(inputs).find((i) => i.type === 'host' && !i.el.hidden)?.el) };
  }

  /* ================= pins ================= */
  const pinKey = (kind, id) => `${kind}:${id}`;
  const isPinned = (kind, id) => pins.has(pinKey(kind, id));

  function togglePin(kind, id) {
    const k = pinKey(kind, id);
    if (pins.has(k)) pins.delete(k); else pins.add(k);
    writePref('netdeck.pins', JSON.stringify([...pins]));
    render();
    renderPlaybooks();
  }

  function makePinButton(kind, id) {
    const btn = document.createElement('button');
    const on = isPinned(kind, id);
    btn.className = `icon-btn pin-btn${on ? ' is-on' : ''}`;
    btn.setAttribute('aria-pressed', String(on));
    btn.title = on ? 'Unpin' : 'Pin to the top';
    btn.setAttribute('aria-label', btn.title);
    btn.textContent = on ? '★' : '☆';
    btn.addEventListener('click', () => togglePin(kind, id));
    return btn;
  }

  /* ================= deep links ================= */
  // Links only mean something where the page has an address other people can open. The desktop
  // app's pages live at tauri.localhost, which exists only inside its own window — so no link buttons there.
  const LINKABLE = !TAURI;

  function linkFor(kind, id, params, preset) {
    const q = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => { if (v) q.set(k, v); });
    if (preset != null) q.set('preset', String(preset));
    const qs = q.toString();
    return `${location.origin}${location.pathname}#${kind}/${id}${qs ? `?${qs}` : ''}`;
  }

  const BOOK_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 2.5h7.5A1.5 1.5 0 0 1 12 4v9.5H4.5A1.5 1.5 0 0 1 3 12V2.5z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M3 12a1.5 1.5 0 0 1 1.5-1.5H12M5.5 5h4M5.5 7.5h4" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>';

  // Opens the manual at the entry for one command (cmd-<id>) or playbook (pb-<id>).
  function makeManualButton(anchor, what) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn manual-btn';
    btn.title = `Open the manual at ${what}`;
    btn.setAttribute('aria-label', btn.title);
    btn.innerHTML = BOOK_SVG;
    btn.addEventListener('click', () => { BACKEND.openDoc('manual.html', anchor).catch(() => {}); });
    return btn;
  }

  function makeLinkButton(getLink) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn link-btn';
    btn.title = 'Copy a link to this';
    btn.setAttribute('aria-label', 'Copy link');
    btn.innerHTML = LINK_SVG;
    btn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(getLink()); flashOk(btn, LINK_SVG); }
      catch { btn.title = 'Copy failed'; }
    });
    return btn;
  }

  function applyHash() {
    const h = location.hash.slice(1);
    if (!h) return;
    const [route, qs] = h.split('?');
    const [kind, id] = route.split('/');
    const p = new URLSearchParams(qs || '');
    if (kind === 'cmd' && byId.has(id)) jumpTo('cmd', id, p);
    else if (kind === 'pb' && PB.get(id)) jumpTo('pb', id, p);
    else if (kind === 'playbooks') setView('playbooks');
    else if (kind === 'dashboard') setView('dashboard');
    else if (kind === 'pinned') { setView('commands'); setCategory('pinned'); }
  }

  function jumpTo(kind, id, params) {
    if (kind === 'cmd') {
      searchInput.value = ''; query = '';
      activePlatform = 'all'; setChip(platformRow, 'platform', 'all');
      setCategory('all');
      setView('commands');
    } else {
      // Clear the playbook filters too, so the card is guaranteed to be on the page.
      searchInput.value = ''; query = '';
      activePbGroup = 'all'; setChip(pbGroupRow, 'group', 'all');
      setView('playbooks');
    }
    const card = document.querySelector(kind === 'cmd' ? `.card[data-id="${id}"]` : `.card[data-pb="${id}"]`);
    if (!card) return;
    if (params) {
      card.querySelectorAll('.param-input').forEach((inp) => {
        const key = inp.id.split('-').pop();
        if (params.get(key)) inp.value = params.get(key);
      });
      const sel = card.querySelector('.preset-select');
      if (sel && params.get('preset') !== null) { sel.value = params.get('preset') ?? ''; sel.dispatchEvent(new Event('change')); }
    }
    card.scrollIntoView({ block: 'center' });
    setCursor(card, true);
    const focusTarget = card.querySelector('.param-input:not([hidden])') || card.querySelector('.run-btn') || card.querySelector('.copy-btn');
    focusTarget?.focus({ preventScroll: true });
  }

  window.addEventListener('hashchange', applyHash);

  /* ================= network context ================= */
  function quickPicks() {
    const picks = [];
    const seen = new Set();
    const add = (value, hint) => {
      if (!value || seen.has(value)) return;
      seen.add(value);
      picks.push({ value, hint });
    };
    add(context?.gateway, 'gateway');
    add(context?.dns?.[0], 'dns');
    add('1.1.1.1', 'cloudflare');
    add('localhost', '');
    history.filter((h) => h.params?.host).map((h) => h.params.host)
      .filter((v, i, a) => a.indexOf(v) === i).slice(0, 3).forEach((v) => add(v, 'recent'));
    return picks;
  }

  function renderQuickPicks(box, targetFn) {
    box.textContent = '';
    const picks = quickPicks();
    if (!picks.length) return;
    const label = document.createElement('span');
    label.className = 'pick-label';
    label.textContent = 'fill';
    box.appendChild(label);
    picks.forEach(({ value, hint }) => {
      const b = document.createElement('button');
      b.className = 'pick';
      b.type = 'button';
      b.innerHTML = `${value}${hint ? `<small>${hint}</small>` : ''}`;
      b.addEventListener('click', () => {
        const el = targetFn();
        if (!el) return;
        el.value = value;
        el.classList.remove('invalid');
        el.focus();
      });
      box.appendChild(b);
    });
  }

  function renderContext() {
    const set = (key, val) => {
      const el = document.querySelector(`[data-ctx="${key}"]`);
      el.textContent = val || '';
      el.classList.toggle('unknown', !val);
      el.title = val || 'not detected';
    };
    set('hostname', context?.hostname);
    set('adapter', context?.adapter);
    set('ip', context?.ip);
    set('gateway', context?.gateway);
    set('dns', (context?.dns || []).join(', '));
    const badge = $('ctx-admin');
    badge.dataset.admin = context ? String(Boolean(context.admin)) : 'unknown';
    badge.textContent = context ? (context.admin ? 'admin' : 'standard user') : '…';
    badge.title = context?.admin
      ? 'Running as administrator — admin-only variants (e.g. netstat -anob) are unlocked'
      : 'Not running as administrator — variants marked "admin only" are locked. Use the button beside this badge.';
    const elevateBtn = $('ctx-elevate');
    elevateBtn.hidden = !context || Boolean(context.admin);
    elevateBtn.textContent = TAURI ? 'Run as admin' : 'How to run as admin';
  }

  /* How to get administrator rights depends on which NetDeck this is: the desktop app can restart
     itself through Windows' UAC prompt; the server editions have to be started again by hand. */
  const elevateModal = $('elevate-modal');

  function openElevate() {
    const steps = $('elevate-steps'), code = $('elevate-code'), go = $('elevate-go'), copy = $('elevate-copy');
    code.hidden = true; go.hidden = true; copy.hidden = true;
    if (TAURI) {
      steps.textContent = 'NetDeck will close and start again, and Windows will ask for permission. Anything still running stops and open tabs close; your history, pins and custom commands are kept. If you decline the Windows prompt, NetDeck simply reopens as it is now. If Windows asks for a different account’s password, NetDeck runs as that account, with its own history and pins.';
      go.hidden = false;
    } else if (context?.platform !== 'win32') {
      steps.textContent = 'Stop NetDeck (Ctrl+C in its terminal) and start it again with sudo:';
      code.textContent = `cd "${context?.appDir || '<the NetDeck folder>'}"\nsudo node server.js`;
      code.hidden = false; copy.hidden = false;
    } else if (context?.packaged) {
      steps.textContent = `Close NetDeck’s console window, then right-click netdeck.exe (in ${context.appDir}) and choose “Run as administrator”.`;
    } else {
      steps.textContent = 'This NetDeck is running from its source folder. Stop it (Ctrl+C in its terminal), open a new terminal with “Run as administrator”, and start it from that folder:';
      code.textContent = `cd /d "${context?.appDir || '<the NetDeck folder>'}"\nnode server.js`;
      code.hidden = false; copy.hidden = false;
    }
    elevateModal.hidden = false;
  }

  function closeElevate() { elevateModal.hidden = true; }

  $('ctx-elevate').addEventListener('click', openElevate);
  $('elevate-cancel').addEventListener('click', closeElevate);
  elevateModal.addEventListener('click', (e) => { if (e.target === elevateModal) closeElevate(); });
  $('elevate-copy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('elevate-code').textContent); $('elevate-copy').textContent = 'Copied'; setTimeout(() => { $('elevate-copy').textContent = 'Copy commands'; }, 1200); } catch { /* select it by hand */ }
  });
  $('elevate-go').addEventListener('click', async () => {
    try { await BACKEND.elevate(); } catch (err) { $('elevate-steps').textContent = String(err); $('elevate-go').hidden = true; }
  });

  async function loadContext(refresh) {
    if (!canRun) return;
    const btn = $('ctx-refresh');
    btn.classList.add('spinning');
    try {
      context = await BACKEND.context(refresh);
    } catch {
      context = null;
    }
    btn.classList.remove('spinning');
    renderContext();
    render();
    renderPlaybooks();
    DASH.poke();
    if (refresh) pollHealth();
  }

  $('ctx-refresh').addEventListener('click', () => loadContext(true));

  /* ================= health strip ================= */
  const health = { gateway: [], internet: [], timer: null };
  const HEALTH_LIMITS = { gateway: [50, 200], internet: [100, 300] };

  function sparkline(samples, key) {
    const w = 84, h = 20, pad = 2;
    const vals = samples.map((s) => s.v);
    const finite = vals.filter((v) => v !== null);
    const max = Math.max(20, ...finite);
    const step = (w - pad * 2) / Math.max(1, HEALTH_SAMPLES - 1);
    const x = (i) => pad + (HEALTH_SAMPLES - samples.length + i) * step;
    const y = (v) => h - pad - (Math.min(v, max) / max) * (h - pad * 2);
    let d = '', area = '', open = false, last = null;
    samples.forEach((s, i) => {
      if (s.v === null) { open = false; return; }
      const px = x(i).toFixed(1), py = y(s.v).toFixed(1);
      d += (open ? ' L' : ' M') + `${px} ${py}`;
      area += open ? ` L${px} ${py}` : ` M${px} ${h - pad} L${px} ${py}`;
      if (i === samples.length - 1 || samples[i + 1]?.v === null) area += ` L${px} ${h - pad} Z`;
      open = true;
      last = i;
    });
    const gaps = samples.map((s, i) => (s.v === null ? `<line x1="${x(i).toFixed(1)}" y1="${pad}" x2="${x(i).toFixed(1)}" y2="${h - pad}" class="gap"/>` : '')).join('');
    const end = last !== null ? `<circle cx="${x(last).toFixed(1)}" cy="${y(samples[last].v).toFixed(1)}" r="2.5" class="end"/>` : '';
    const label = `${key}: ${finite.length ? `latest ${finite[finite.length - 1]} ms, max ${max} ms over ${samples.length} samples` : 'no replies yet'}`;
    return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${label}"><title>${label}</title>
      <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" class="base"/>
      <path d="${area.trim()}" class="area"/><path d="${d.trim()}" class="line"/>${gaps}${end}</svg>`;
  }

  function renderHealth() {
    for (const key of ['gateway', 'internet']) {
      const el = document.querySelector(`[data-health="${key}"]`);
      if (!el) continue;
      const samples = health[key];
      const latest = samples[samples.length - 1];
      const [warn, bad] = HEALTH_LIMITS[key];
      let state = 'idle', text = '—';
      if (latest) {
        if (latest.v === null) { state = 'err'; text = 'no reply'; }
        else { state = latest.v > bad ? 'err' : latest.v > warn ? 'warn' : 'ok'; text = `${latest.v} ms`; }
      }
      el.querySelector('.spark-wrap').innerHTML = sparkline(samples, key);
      const val = el.querySelector('.health-val');
      val.textContent = text;
      val.dataset.state = state;
      const host = key === 'gateway' ? context?.gateway : '1.1.1.1';
      el.title = host ? `Pinging ${host} every ${HEALTH_INTERVAL / 1000}s` : 'No gateway detected';
      el.dataset.state = state;
    }
    DASH.poke('health');
  }

  async function pollHealth() {
    if (document.hidden || !canRun) return;
    try {
      const r = await BACKEND.health();
      for (const key of ['gateway', 'internet']) {
        const v = r[key] === null ? null : Math.round(r[key] * 10) / 10;
        if (key === 'gateway' && !r.gatewayHost) continue;
        health[key].push({ t: r.t, v });
        if (health[key].length > HEALTH_SAMPLES) health[key].shift();
      }
      renderHealth();
    } catch { /* server unreachable; try again next tick */ }
  }

  function startHealth() {
    if (health.timer) return;
    pollHealth();
    health.timer = setInterval(pollHealth, HEALTH_INTERVAL);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) pollHealth(); });
  }

  /* ================= command cards ================= */
  // Hover text for the platform tag on each command row.
  const TAG_MEANING = {
    WIN: 'Windows (Command Prompt)',
    PS: 'Windows PowerShell',
    'L/M': 'Linux / macOS',
    ALL: 'All platforms — the same command everywhere',
  };

  function osTagFor(cmd) {
    return cmd.platforms.includes('powershell') ? 'PS' : cmd.platforms.includes('cross') ? 'ALL' : 'WIN';
  }

  function makeHelpButton(cmd) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn help-btn';
    btn.title = isWin() ? `Show built-in help (${cmd.name.split(' ')[0]} /?)` : 'Show built-in help (--help)';
    btn.setAttribute('aria-label', `Help for ${cmd.name}`);
    btn.textContent = '?';
    btn.addEventListener('click', () => startRun(cmd, {}, { help: true }));
    return btn;
  }

  function buildCard(cmd) {
    const node = template.content.firstElementChild.cloneNode(true);
    node.dataset.id = cmd.id;
    if (isPinned('cmd', cmd.id)) node.classList.add('is-pinned');
    const name = node.querySelector('.card-name');
    name.textContent = cmd.name;
    if (cmd.essential) {
      const star = document.createElement('span');
      star.className = 'star';
      star.title = 'Most useful on Windows';
      star.textContent = '★';
      name.appendChild(star);
    }
    if (cmd.custom) {
      const tag = document.createElement('span');
      tag.className = 'tag-custom';
      tag.textContent = 'custom';
      name.appendChild(tag);
    }
    node.querySelector('.card-cat').textContent = cmd.category;
    node.querySelector('.card-purpose').textContent = cmd.purpose;

    const rows = node.querySelector('.card-rows');
    const paramsBox = node.querySelector('.card-params');
    const picksBox = node.querySelector('.quick-picks');
    const presetBox = node.querySelector('.card-presets');
    const tools = node.querySelector('.card-tools');
    const spec = cmd.runnable;
    let presetIdx = null;

    const currentPreset = () => (presetIdx === null ? null : spec.presets[presetIdx]);
    const currentParams = () => Object.fromEntries(Object.entries(inputs).filter(([, i]) => !i.el.hidden).map(([k, i]) => [k, i.el.value.trim()]));
    const run = () => {
      const params = validateInputs(inputs, usedKeys(spec, currentPreset()));
      if (params) startRun(cmd, params, { preset: presetIdx });
    };
    const { inputs, target } = buildParamInputs(spec?.params || [], cmd.id, paramsBox, run);

    if (!cmd.custom) tools.appendChild(makeManualButton(`cmd-${cmd.id}`, `“${cmd.name}”`));
    if (LINKABLE) tools.appendChild(makeLinkButton(() => linkFor('cmd', cmd.id, currentParams(), presetIdx)));
    tools.appendChild(makePinButton('cmd', cmd.id));
    if (cmd.custom) {
      const del = document.createElement('button');
      del.className = 'icon-btn del-btn';
      del.title = 'Delete this custom command';
      del.setAttribute('aria-label', del.title);
      del.textContent = '×';
      del.addEventListener('click', () => deleteCustom(cmd));
      tools.appendChild(del);
    }

    // Which row carries the run button: WIN on Windows, the first L/M (Linux / macOS) row elsewhere (WIN if none).
    const runRow = isWin() || !(cmd.unix || []).length ? 'win' : 'nix0';
    let runCode = null;

    const addRow = (tag, text, isRunRow) => {
      const row = document.createElement('div');
      row.className = 'cmd-row';
      row.innerHTML = `<span class="os-tag" title="${TAG_MEANING[tag] || ''}">${tag}</span>`;
      const code = document.createElement('code');
      code.textContent = text;
      row.appendChild(code);
      row.appendChild(makeCopyButton(text));
      if (isRunRow && cmd.hasHelp && canRun) row.appendChild(makeHelpButton(cmd));
      if (isRunRow && spec && canRun) {
        const runBtn = document.createElement('button');
        runBtn.className = 'run-btn';
        runBtn.textContent = '▶ run';
        runBtn.addEventListener('click', run);
        row.appendChild(runBtn);
        runCode = code;
      }
      rows.appendChild(row);
    };

    if (cmd.win) addRow(osTagFor(cmd), cmd.win, runRow === 'win');
    (cmd.unix || []).forEach((syntax, i) => addRow('L/M', syntax, runRow === 'nix0' && i === 0));

    const applyPreset = () => {
      const keys = usedKeys(spec, currentPreset());
      for (const [key, { el }] of Object.entries(inputs)) el.hidden = !keys.has(key);
      if (runCode) runCode.textContent = presetIdx === null && isWin() ? cmd.win : specDisplay(spec, currentPreset(), {});
      picksBox.hidden = ![...keys].some((k) => inputs[k]?.type === 'host');
    };

    if (spec?.presets?.length && canRun) {
      const label = document.createElement('label');
      label.className = 'preset-label';
      label.textContent = 'variant';
      const select = document.createElement('select');
      select.className = 'preset-select';
      select.id = `${cmd.id}-preset`;
      label.htmlFor = select.id;
      const base = document.createElement('option');
      base.value = '';
      base.textContent = `default — ${specDisplay(spec, null, {})}`;
      select.appendChild(base);
      spec.presets.forEach((p, i) => {
        const opt = document.createElement('option');
        opt.value = String(i);
        const locked = p.admin && !context?.admin;
        opt.textContent = p.label + (p.admin ? (locked ? ' — admin only (locked: use “Run as admin”)' : ' — admin') : '');
        opt.disabled = locked;
        select.appendChild(opt);
      });
      select.addEventListener('change', () => { presetIdx = select.value === '' ? null : Number(select.value); applyPreset(); });
      presetBox.append(label, select);
    }

    if (canRun && Object.values(inputs).some((i) => i.type === 'host')) renderQuickPicks(picksBox, target);
    if (spec && canRun) applyPreset();
    else paramsBox.hidden = true;
    if (cmd.note) node.querySelector('.card-note').textContent = cmd.note;
    return node;
  }

  function matches(cmd) {
    if (cmd.hidden) return false;
    if (activePlatform !== 'all') {
      const set = cmd.platforms.includes('cross') ? ['windows', 'unix', 'powershell'] : cmd.platforms;
      if (!set.includes(activePlatform)) return false;
    }
    if (activeCategory === 'pinned') { if (!isPinned('cmd', cmd.id)) return false; }
    else if (activeCategory !== 'all' && cmd.category !== activeCategory) return false;
    if (query) {
      const hay = [cmd.name, cmd.win, ...(cmd.unix || []), cmd.purpose, cmd.category].join(' ').toLowerCase();
      if (!hay.includes(query)) return false;
    }
    return true;
  }

  function pinnedFirst(list, kind, idOf) {
    return [...list].sort((a, b) => Number(isPinned(kind, idOf(b))) - Number(isPinned(kind, idOf(a))));
  }

  function render() {
    if (!commands.length) return;
    grid.textContent = '';
    const visible = pinnedFirst(commands.filter(matches), 'cmd', (c) => c.id);
    visible.forEach((cmd) => grid.appendChild(buildCard(cmd)));
    emptyMsg.hidden = visible.length > 0;
    emptyMsg.textContent = activeCategory === 'pinned' && !pins.size ? 'Nothing pinned yet — use ☆ on a card to pin it.' : 'No commands match — try a shorter search.';
    const total = commands.filter((c) => !c.hidden).length;
    resultCount.textContent = `${visible.length} of ${total} commands`;
    cursorCard = null;
  }

  function buildCategoryChips() {
    categoryRow.textContent = '';
    const cats = [...new Set(commands.filter((c) => !c.hidden).map((c) => c.category))];
    const mk = (value, label) => {
      const chip = document.createElement('button');
      chip.className = `chip${value === activeCategory ? ' is-active' : ''}`;
      chip.dataset.category = value;
      chip.textContent = label;
      categoryRow.appendChild(chip);
    };
    mk('all', 'All categories');
    mk('pinned', '★ pinned');
    cats.forEach((cat) => mk(cat, cat));
  }

  function setChip(row, attr, value) {
    row.querySelectorAll('.chip').forEach((c) => c.classList.toggle('is-active', c.dataset[attr] === value));
  }

  function setCategory(value) {
    activeCategory = value;
    setChip(categoryRow, 'category', value);
    render();
  }

  platformRow.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    setChip(platformRow, 'platform', chip.dataset.platform);
    activePlatform = chip.dataset.platform;
    render();
  });

  categoryRow.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (chip) setCategory(chip.dataset.category);
  });

  // The one search box filters whichever view is showing.
  searchInput.addEventListener('input', () => {
    query = searchInput.value.trim().toLowerCase();
    // The dashboard has nothing to filter: typing there searches the commands.
    if (activeView === 'dashboard' && query) { setView('commands'); return; }
    if (activeView === 'playbooks') renderPlaybooks(); else render();
  });

  pbGroupRow.addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    activePbGroup = chip.dataset.group;
    setChip(pbGroupRow, 'group', activePbGroup);
    renderPlaybooks();
  });

  /* ================= view switch ================= */
  function setView(view) {
    activeView = view;
    document.querySelectorAll('.vtab').forEach((b) => {
      const on = b.dataset.view === view;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', String(on));
    });
    viewCommands.hidden = view !== 'commands';
    viewPlaybooks.hidden = view !== 'playbooks';
    viewDashboard.hidden = view !== 'dashboard';
    platformRow.hidden = view !== 'commands';
    categoryRow.hidden = view !== 'commands';
    pbGroupRow.hidden = view !== 'playbooks';
    searchInput.placeholder = view === 'playbooks' ? 'Search playbooks by symptom, name or command…' : 'Search commands, syntax or purpose…';
    cursorCard = null;
    if (view === 'dashboard') { DASH.show(); return; }
    DASH.hide();
    // A search typed in one view carries over to the other.
    if (view === 'playbooks') renderPlaybooks(); else render();
  }

  document.querySelector('.view-switch').addEventListener('click', (e) => {
    const b = e.target.closest('.vtab');
    if (b) setView(b.dataset.view);
  });

  /* ================= playbook cards ================= */
  function buildPlaybookCard(pb) {
    const card = document.createElement('article');
    card.className = `card pb-card${isPinned('pb', pb.id) ? ' is-pinned' : ''}`;
    card.dataset.pb = pb.id;

    const head = document.createElement('header');
    head.className = 'card-head';
    head.innerHTML = `<h2 class="card-name"></h2><span class="card-cat">${pb.steps.length} steps</span><span class="card-tools"></span>`;
    head.querySelector('.card-name').textContent = pb.name;
    card.appendChild(head);

    const desc = document.createElement('p');
    desc.className = 'card-purpose';
    desc.textContent = pb.description;
    card.appendChild(desc);

    const list = document.createElement('ol');
    list.className = 'pb-steps-preview';
    pb.steps.forEach((s, i) => {
      const li = document.createElement('li');
      const shown = stepDisplay(s, {}, {});
      if (s.when || s.skipIf) li.classList.add('is-conditional');
      li.innerHTML = `<span class="n">${i + 1}.</span><span class="pb-step-text">${s.label} <code></code></span>`;
      li.querySelector('code').textContent = shown;
      li.appendChild(makeCopyButton(shown));
      list.appendChild(li);
    });
    card.appendChild(list);

    const paramsBox = document.createElement('div');
    paramsBox.className = 'card-params';
    const picksBox = document.createElement('div');
    picksBox.className = 'quick-picks';
    const run = () => {
      const params = validateInputs(inputs);
      if (params) runPlaybook(pb, params);
    };
    const { inputs, target } = buildParamInputs(pb.params, `pb-${pb.id}`, paramsBox, run);
    card.appendChild(paramsBox);
    if (canRun && pb.params.some((p) => p.type === 'host')) renderQuickPicks(picksBox, target);
    card.appendChild(picksBox);

    const tools = head.querySelector('.card-tools');
    tools.appendChild(makeManualButton(`pb-${pb.id}`, `“${pb.name}”`));
    if (LINKABLE) tools.appendChild(makeLinkButton(() => linkFor('pb', pb.id, Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.el.value.trim()])))));
    tools.appendChild(makePinButton('pb', pb.id));

    const runRow = document.createElement('div');
    runRow.className = 'pb-run-row';
    if (canRun) {
      const runBtn = document.createElement('button');
      runBtn.className = 'run-btn';
      runBtn.textContent = '▶ run playbook';
      runBtn.addEventListener('click', run);
      runRow.appendChild(runBtn);
    } else {
      paramsBox.hidden = true;
      runRow.innerHTML = '<span class="static-note">Run these steps in a terminal, top to bottom — or connect a local NetDeck to run them here.</span>';
    }
    card.appendChild(runRow);

    const needsGateway = pb.steps.some((s) => Object.values(s.params || {}).some((v) => String(v).includes('{gateway}')));
    if (canRun && needsGateway && context && !context.gateway) {
      const note = document.createElement('p');
      note.className = 'card-note';
      note.textContent = 'No default gateway detected — the gateway step will be skipped.';
      card.appendChild(note);
    }
    return card;
  }

  function playbookMatches(pb) {
    if (activePbGroup === 'pinned') { if (!isPinned('pb', pb.id)) return false; }
    else if (activePbGroup !== 'all' && pb.group !== activePbGroup) return false;
    if (!query) return true;
    const hay = [pb.name, pb.description, pb.group, ...pb.steps.map((s) => `${s.label} ${byId.get(s.cmd)?.name || ''}`)].join(' ').toLowerCase();
    return query.split(/\s+/).every((t) => hay.includes(t));
  }

  function buildPlaybookGroupChips() {
    pbGroupRow.textContent = '';
    const mk = (value, label) => {
      const chip = document.createElement('button');
      chip.className = `chip${value === activePbGroup ? ' is-active' : ''}`;
      chip.dataset.group = value;
      chip.textContent = label;
      pbGroupRow.appendChild(chip);
    };
    mk('all', 'All playbooks');
    mk('pinned', '★ pinned');
    PB.groups().forEach((g) => mk(g, g));
  }

  // Playbooks are shown in their groups, pinned ones first within each group.
  function renderPlaybooks() {
    if (!commands.length) return;
    playbookGrid.textContent = '';
    const all = PB.list();
    const visible = all.filter(playbookMatches);
    PB.groups().forEach((group) => {
      const items = visible.filter((pb) => pb.group === group)
        .sort((a, b) => (Number(isPinned('pb', b.id)) - Number(isPinned('pb', a.id))) || a.order - b.order);
      if (!items.length) return;
      const section = document.createElement('section');
      section.className = 'pb-group';
      const head = document.createElement('h2');
      head.className = 'pb-group-title';
      head.innerHTML = '<span></span><small></small>';
      head.querySelector('span').textContent = group;
      head.querySelector('small').textContent = `${items.length} playbook${items.length === 1 ? '' : 's'}`;
      const gridEl = document.createElement('div');
      gridEl.className = 'grid grid-wide';
      items.forEach((pb) => gridEl.appendChild(buildPlaybookCard(pb)));
      section.append(head, gridEl);
      playbookGrid.appendChild(section);
    });
    $('pb-empty').hidden = visible.length > 0;
    $('pb-empty').textContent = activePbGroup === 'pinned' && !visible.length && !query ? 'No playbooks pinned yet — use ☆ on a playbook to pin it.' : 'No playbooks match — try a shorter search.';
    $('pb-count').textContent = `${visible.length} of ${all.length} playbooks — each step runs a command, checks the result, and the verdict names the problem`;
    cursorCard = null;
  }

  /* ================= custom commands ================= */
  const customModal = $('custom-modal');
  const customForm = $('custom-form');

  function localCustoms() {
    return readJson('netdeck.custom', []);
  }

  function shapeLocalCustom(input) {
    const unix = String(input.unix || '').split('\n').map((s) => s.trim()).filter(Boolean).slice(0, 6);
    const win = (input.win || '').trim();
    if (!input.name?.trim() || !input.purpose?.trim()) throw new Error('Name and purpose are required.');
    if (!win && !unix.length) throw new Error('Give at least one command line (Windows or Linux/macOS).');
    const platforms = [];
    if (win) platforms.push(/^[A-Z][a-z]+-[A-Z]/.test(win) ? 'powershell' : 'windows');
    if (unix.length) platforms.push('unix');
    return {
      id: `custom-${Date.now().toString(36)}`, name: input.name.trim().slice(0, 80), purpose: input.purpose.trim().slice(0, 240),
      win: win || undefined, unix, category: (input.category || '').trim().slice(0, 60) || 'Custom',
      note: (input.note || '').trim().slice(0, 240) || undefined, platforms, safe: false, custom: true, runnable: null, hasHelp: false,
    };
  }

  function openCustom() {
    customForm.reset();
    const dl = $('category-options');
    dl.textContent = '';
    [...new Set(commands.map((c) => c.category))].forEach((c) => { const o = document.createElement('option'); o.value = c; dl.appendChild(o); });
    $('custom-error').textContent = '';
    customModal.hidden = false;
    customForm.elements.name.focus();
  }

  function closeCustom() { customModal.hidden = true; }

  async function submitCustom(e) {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(customForm).entries());
    const errBox = $('custom-error');
    try {
      let entry;
      if (canRun) {
        entry = await BACKEND.addCustom(data);
      } else {
        entry = shapeLocalCustom(data);
        writePref('netdeck.custom', JSON.stringify([...localCustoms(), entry]));
      }
      commands.push(entry);
      byId.set(entry.id, entry);
      buildCategoryChips();
      closeCustom();
      render();
      jumpTo('cmd', entry.id);
    } catch (err) {
      errBox.textContent = err.message || 'Could not save the command.';
    }
  }

  async function deleteCustom(cmd) {
    if (!confirm(`Delete the custom command "${cmd.name}"?`)) return;
    if (canRun) {
      try { await BACKEND.deleteCustom(cmd.id); } catch { return; }
    } else {
      writePref('netdeck.custom', JSON.stringify(localCustoms().filter((c) => c.id !== cmd.id)));
    }
    commands = commands.filter((c) => c.id !== cmd.id);
    byId.delete(cmd.id);
    pins.delete(pinKey('cmd', cmd.id));
    buildCategoryChips();
    render();
  }

  $('custom-open').addEventListener('click', openCustom);
  $('custom-cancel').addEventListener('click', closeCustom);
  customModal.addEventListener('click', (e) => { if (e.target === customModal) closeCustom(); });
  customForm.addEventListener('submit', submitCustom);

  /* ================= execution ================= */
  function execute(cmd, params, { onChunk, signal, preset = null, help = false } = {}) {
    return BACKEND.run({ id: cmd.id, params, preset, help }, { onChunk, signal });
  }

  async function getProcessMap() {
    if (processCache.map && Date.now() - processCache.at < 30000) return processCache.map;
    if (processCache.pending) return processCache.pending;
    const cmd = byId.get('tasklist-csv');
    if (!cmd?.runnable) return new Map();
    processCache.pending = execute(cmd, {}).then((r) => {
      processCache.map = P.processMap(r.output);
      processCache.at = Date.now();
      processCache.pending = null;
      return processCache.map;
    });
    return processCache.pending;
  }

  /* ================= tabs ================= */
  function createTab({ kind, title, cmdId, pbId, params, preset = null, help = false }) {
    const tab = {
      id: `t${++tabSeq}`, kind, title, cmdId, pbId, params, preset, help,
      output: '', state: 'running', exitCode: null, note: '', hid: null,
      startedAt: Date.now(), endedAt: null, controller: new AbortController(),
      view: 'raw', table: null, els: {}, find: '', findTimer: null, tick: null,
    };
    const pane = document.createElement('div');
    pane.className = `pane${kind === 'playbook' ? ' pane-playbook' : ''}`;
    pane.dataset.tab = tab.id;
    tab.els.pane = pane;

    const link = () => (kind === 'run' ? linkFor('cmd', cmdId, params, preset) : linkFor('pb', pbId, params));

    if (kind === 'run') {
      const meta = document.createElement('div');
      meta.className = 'pane-meta';
      meta.innerHTML = `<span class="prompt"></span><span class="started"></span><span class="dur"></span><span class="exit"></span>
        <span class="pane-tools">
          <span class="find-wrap"><input class="find-input" type="search" placeholder="find in output" aria-label="Find in output" spellcheck="false"><span class="find-count"></span></span>
          <button class="tbtn tbtn-sm wrap-btn" aria-pressed="${wrapLines}" title="Wrap long lines">wrap</button>
          <span class="note-slot"></span>
          <button class="tbtn tbtn-sm save-btn" title="Save output as a text file">save</button>
          <button class="tbtn tbtn-sm link-tbtn" title="Copy a link that opens this command pre-filled">link</button>
        </span>`;
      meta.querySelector('.prompt').textContent = `> ${title}`;
      meta.querySelector('.started').textContent = fmtTime(tab.startedAt);
      const raw = document.createElement('pre');
      raw.className = 'pane-raw';
      raw.classList.toggle('nowrap', !wrapLines);
      const tableWrap = document.createElement('div');
      tableWrap.className = 'pane-table';
      tableWrap.hidden = true;
      pane.append(meta, raw, tableWrap);
      Object.assign(tab.els, { meta, raw, tableWrap, find: meta.querySelector('.find-input'), findCount: meta.querySelector('.find-count') });
      meta.querySelector('.note-slot').replaceWith(attachNote(tab, meta));

      tab.els.find.addEventListener('input', () => { tab.find = tab.els.find.value; rehighlight(tab); });
      tab.els.find.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); nextMatch(tab, e.shiftKey ? -1 : 1); } if (e.key === 'Escape') { tab.els.find.value = ''; tab.find = ''; rehighlight(tab); } });
      meta.querySelector('.wrap-btn').addEventListener('click', () => setWrap(!wrapLines));
      meta.querySelector('.save-btn').addEventListener('click', () => saveOutput(tab));
      const linkBtn = meta.querySelector('.link-tbtn');
      linkBtn.hidden = help || !LINKABLE;
      linkBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(link()); linkBtn.textContent = 'copied'; setTimeout(() => { linkBtn.textContent = 'link'; }, 1200); } catch { /* ignore */ } });

      tab.tick = setInterval(() => { meta.querySelector('.dur').textContent = fmtDur(Date.now() - tab.startedAt); }, 500);
    } else {
      const bar = document.createElement('div');
      bar.className = 'pb-bar';
      pane.appendChild(bar);
      bar.appendChild(attachNote(tab, bar));
      if (LINKABLE) {
        const linkBtn = document.createElement('button');
        linkBtn.className = 'tbtn tbtn-sm';
        linkBtn.textContent = 'link';
        linkBtn.title = 'Copy a link that opens this playbook pre-filled';
        linkBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(link()); linkBtn.textContent = 'copied'; setTimeout(() => { linkBtn.textContent = 'link'; }, 1200); } catch { /* ignore */ } });
        bar.appendChild(linkBtn);
      }
    }

    panes.appendChild(pane);
    tabs.push(tab);
    renderTabStrip();
    activateTab(tab.id);
    openTerminal();
    return tab;
  }

  function activateTab(id) {
    activeTabId = id;
    tabs.forEach((t) => { t.els.pane.hidden = t.id !== id; });
    paneEmpty.hidden = tabs.length > 0;
    renderTabStrip();
    syncActions();
  }

  function closeTab(id) {
    const idx = tabs.findIndex((t) => t.id === id);
    if (idx === -1) return;
    const tab = tabs[idx];
    if (tab.state === 'running') tab.controller.abort();
    clearInterval(tab.tick);
    tab.els.pane.remove();
    tabs.splice(idx, 1);
    if (activeTabId === id) activateTab(tabs[Math.min(idx, tabs.length - 1)]?.id ?? null);
    else renderTabStrip();
  }

  function renderTabStrip() {
    tabStrip.querySelectorAll('.tab').forEach((el) => el.remove());
    tabStripEmpty.hidden = tabs.length > 0;
    tabs.forEach((t) => {
      const el = document.createElement('div');
      el.className = `tab${t.id === activeTabId ? ' is-active' : ''}`;
      el.setAttribute('role', 'tab');
      el.tabIndex = 0;
      el.setAttribute('aria-selected', String(t.id === activeTabId));
      el.innerHTML = `<span class="status-dot" data-state="${dotFor(t.state)}"></span><span class="tab-title"></span><span class="tab-close" title="Close" aria-label="Close tab">×</span>`;
      el.querySelector('.tab-title').textContent = t.title;
      el.title = t.title;
      el.addEventListener('click', (e) => {
        if (e.target.closest('.tab-close')) closeTab(t.id);
        else activateTab(t.id);
      });
      el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activateTab(t.id); }
        if (e.key === 'Delete' || e.key === 'Backspace') closeTab(t.id);
      });
      tabStrip.appendChild(el);
    });
    tabStrip.querySelector('.tab.is-active')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  function dotFor(state) {
    return { running: 'running', done: 'done', warn: 'warn', error: 'error', stopped: 'idle' }[state] || 'idle';
  }

  function activeTab() {
    return tabs.find((t) => t.id === activeTabId) || null;
  }

  function syncActions() {
    const tab = activeTab();
    stopBtn.disabled = !tab || tab.state !== 'running';
    copyBtn.disabled = !tab;
    closeAllBtn.disabled = tabs.length === 0;
    const canTable = tab && tab.kind === 'run' && !tab.help && tab.state !== 'running' && P.hasParser(tab.cmdId, platform);
    viewBtn.hidden = !canTable;
    if (canTable) {
      viewBtn.textContent = tab.view === 'table' ? 'Raw' : 'Table';
      viewBtn.setAttribute('aria-pressed', String(tab.view === 'table'));
    }
  }

  function finishTab(tab, state) {
    tab.state = state;
    tab.endedAt = Date.now();
    clearInterval(tab.tick);
    if (tab.els.meta) {
      tab.els.meta.querySelector('.dur').textContent = fmtDur(tab.endedAt - tab.startedAt);
      const exit = tab.els.meta.querySelector('.exit');
      exit.textContent = tab.exitCode === null ? (state === 'stopped' ? 'stopped' : '') : `exit ${tab.exitCode}`;
      exit.classList.toggle('exit-bad', tab.exitCode !== null && tab.exitCode !== 0);
    }
    renderTabStrip();
    syncActions();
    notifyFinished(tab);
  }

  /* ================= notifications ================= */
  function syncNotifyButton() {
    const blocked = !TAURI && typeof Notification !== 'undefined' && Notification.permission === 'denied';
    notifyBtn.setAttribute('aria-pressed', String(notifyOn && !blocked));
    notifyBtn.title = blocked ? 'Notifications are blocked for this site in the browser'
      : notifyOn ? 'Desktop notification when a run finishes in the background (on)' : 'Notify me when a run finishes while this window is in the background';
  }

  notifyBtn.addEventListener('click', async () => {
    if (!TAURI && typeof Notification === 'undefined') { notifyBtn.title = 'This browser has no notification support'; return; }
    notifyOn = !notifyOn;
    if (notifyOn && (await BACKEND.notifyPermission()) !== 'granted') notifyOn = false;
    writePref('netdeck.notify', notifyOn ? 'on' : 'off');
    syncNotifyButton();
  });

  function notifyFinished(tab) {
    if (!notifyOn || !document.hidden) return;
    const body = tab.kind === 'playbook'
      ? (tab.els.pane.querySelector('.pb-verdict-text')?.textContent || 'finished')
      : { done: 'finished', warn: `finished with exit ${tab.exitCode}`, error: 'could not run', stopped: 'stopped' }[tab.state] || 'finished';
    if (BACKEND.notify) {
      BACKEND.notify(`NetDeck: ${tab.title}`, body).catch(() => {});
      return;
    }
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
    const n = new Notification(`NetDeck: ${tab.title}`, { body, tag: tab.id });
    n.onclick = () => { window.focus(); activateTab(tab.id); openTerminal(); n.close(); };
  }

  /* ================= output: append, find, wrap, save ================= */
  function appendRaw(tab, text) {
    const raw = tab.els.raw;
    const stick = raw.scrollTop + raw.clientHeight >= raw.scrollHeight - 40;
    if (tab.find) {
      if (!tab.findTimer) tab.findTimer = setTimeout(() => { tab.findTimer = null; rehighlight(tab); }, 150);
    } else {
      raw.appendChild(document.createTextNode(text));
    }
    if (stick) raw.scrollTop = raw.scrollHeight;
  }

  function rehighlight(tab) {
    const raw = tab.els.raw;
    const q = tab.find.trim();
    raw.textContent = '';
    if (!q) {
      raw.appendChild(document.createTextNode(tab.output));
      tab.els.findCount.textContent = '';
      return;
    }
    const lower = tab.output.toLowerCase(), needle = q.toLowerCase();
    const frag = document.createDocumentFragment();
    let pos = 0, count = 0, idx;
    while ((idx = lower.indexOf(needle, pos)) !== -1) {
      frag.appendChild(document.createTextNode(tab.output.slice(pos, idx)));
      const mark = document.createElement('mark');
      mark.textContent = tab.output.slice(idx, idx + q.length);
      frag.appendChild(mark);
      pos = idx + q.length;
      count++;
    }
    frag.appendChild(document.createTextNode(tab.output.slice(pos)));
    raw.appendChild(frag);
    tab.findIdx = -1;
    tab.els.findCount.textContent = count ? `${count} match${count === 1 ? '' : 'es'}` : 'no matches';
    if (count) nextMatch(tab, 1);
  }

  function nextMatch(tab, dir) {
    const marks = tab.els.raw.querySelectorAll('mark');
    if (!marks.length) return;
    marks[tab.findIdx]?.classList.remove('current');
    tab.findIdx = ((tab.findIdx ?? -1) + dir + marks.length) % marks.length;
    marks[tab.findIdx].classList.add('current');
    marks[tab.findIdx].scrollIntoView({ block: 'center' });
    tab.els.findCount.textContent = `${tab.findIdx + 1} of ${marks.length}`;
  }

  function setWrap(on) {
    wrapLines = on;
    writePref('netdeck.wrap', on ? 'on' : 'off');
    tabs.forEach((t) => {
      if (!t.els.raw) return;
      t.els.raw.classList.toggle('nowrap', !on);
      t.els.meta.querySelector('.wrap-btn').setAttribute('aria-pressed', String(on));
    });
  }

  function saveOutput(tab) {
    const slug = tab.title.replace(/[^A-Za-z0-9.-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'output';
    const stamp = new Date(tab.startedAt).toISOString().replace(/[:T]/g, '-').slice(0, 19);
    const text = `> ${tab.title}\n${new Date(tab.startedAt).toString()}\n\n${tab.output}`;
    if (BACKEND.saveText) {
      BACKEND.saveText(`${slug}-${stamp}.txt`, text).catch(() => {});
      return;
    }
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${slug}-${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  /* ================= single command run ================= */
  async function startRun(cmd, params, { preset = null, help = false } = {}) {
    const title = help ? `${cmd.name.split(' ')[0]} — help` : titleFor(cmd, params, preset);
    const tab = createTab({ kind: 'run', title, cmdId: cmd.id, params, preset, help });
    const result = await execute(cmd, params, {
      signal: tab.controller.signal, preset, help,
      onChunk: (chunk) => { tab.output += chunk; appendRaw(tab, chunk); },
    });
    tab.exitCode = result.exitCode;
    if (result.aborted) {
      tab.output += '[stopped]\n';
      appendRaw(tab, '[stopped]\n');
      finishTab(tab, 'stopped');
    } else if (result.refused || result.error) {
      finishTab(tab, 'error');
    } else {
      // Built-in help text conventionally exits non-zero; that is not a failure.
      finishTab(tab, result.exitCode === 0 || help ? 'done' : 'warn');
    }
    if (tab.find) rehighlight(tab);
    saveHistory({
      kind: 'run', cmdId: cmd.id, title, params, preset, help,
      startedAt: tab.startedAt, endedAt: tab.endedAt, exitCode: tab.exitCode, state: tab.state,
      output: tab.output.slice(0, MAX_STORED_OUTPUT), note: tab.note,
    });
    tab.hid = lastSavedHid;
  }

  /* ================= table view ================= */
  async function showTable(tab) {
    tab.view = 'table';
    tab.els.raw.hidden = true;
    tab.els.tableWrap.hidden = false;
    syncActions();
    if (tab.table) return;
    tab.els.tableWrap.innerHTML = '<p class="pane-empty">Building the table...</p>';
    const parsed = await parseForTable(tab.cmdId, tab.output);
    if (!parsed) {
      tab.els.tableWrap.innerHTML = '<p class="pane-empty">Nothing table-shaped in this output.</p>';
      tab.table = { columns: [], rows: [] };
      return;
    }
    tab.table = parsed;
    renderTable(tab.els.tableWrap, parsed);
  }

  // Parse command output into {columns, rows}; PID columns are joined to process names.
  async function parseForTable(cmdId, output) {
    const parsed = P.parse(cmdId, output, platform);
    if (!parsed) return null;
    const pidIdx = P.pidColumn(parsed.columns);
    if (pidIdx !== -1) {
      const map = await getProcessMap();
      parsed.columns = [...parsed.columns, 'Process'];
      parsed.rows = parsed.rows.map((r) => [...r, map.get(r[pidIdx]) || '']);
    }
    return parsed;
  }

  function showRaw(tab) {
    tab.view = 'raw';
    tab.els.raw.hidden = false;
    tab.els.tableWrap.hidden = true;
    syncActions();
  }

  function renderTable(container, table) {
    container.textContent = '';
    const tools = document.createElement('div');
    tools.className = 'table-tools';
    const filter = document.createElement('input');
    filter.className = 'table-filter';
    filter.placeholder = 'Filter rows…';
    filter.setAttribute('aria-label', 'Filter rows');
    const count = document.createElement('span');
    count.className = 'table-count';
    tools.append(filter, count);

    const scroll = document.createElement('div');
    scroll.className = 'table-scroll';
    const tbl = document.createElement('table');
    tbl.className = 'data-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    table.columns.forEach((c, i) => {
      const th = document.createElement('th');
      th.textContent = c;
      th.dataset.sort = i;
      th.tabIndex = 0;
      th.addEventListener('click', () => sortBy(i));
      th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sortBy(i); } });
      hr.appendChild(th);
    });
    if (table.rowAction) { const th = document.createElement('th'); th.className = 'row-action-h'; th.textContent = ''; hr.appendChild(th); }
    thead.appendChild(hr);
    const tbody = document.createElement('tbody');
    tbl.append(thead, tbody);
    scroll.appendChild(tbl);
    container.append(tools, scroll);

    let sortIdx = -1, dir = 1, q = '';
    const isNum = (v) => v !== '' && !isNaN(Number(String(v).replace(/,/g, '')));
    const procIdx = table.columns.indexOf('Process');
    const wrapIdx = table.columns.findIndex((c) => /^(Value|Data|Transport Name|Command|Name|Info)$/.test(c));

    function sortBy(i) {
      if (sortIdx === i) dir = -dir; else { sortIdx = i; dir = 1; }
      hr.querySelectorAll('th').forEach((th) => { th.dataset.dir = +th.dataset.sort === sortIdx ? (dir === 1 ? 'asc' : 'desc') : ''; });
      draw();
    }

    function draw() {
      let rows = table.rows;
      if (q) rows = rows.filter((r) => r.join(' ').toLowerCase().includes(q));
      if (sortIdx !== -1) {
        rows = [...rows].sort((a, b) => {
          const x = a[sortIdx], y = b[sortIdx];
          if (isNum(x) && isNum(y)) return (Number(String(x).replace(/,/g, '')) - Number(String(y).replace(/,/g, ''))) * dir;
          return String(x).localeCompare(String(y), undefined, { numeric: true }) * dir;
        });
      }
      const frag = document.createDocumentFragment();
      rows.forEach((r) => {
        const tr = document.createElement('tr');
        r.forEach((v, i) => {
          const td = document.createElement('td');
          td.textContent = v;
          if (v === '') td.className = 'dim';
          if (i === procIdx && v) td.className = 'proc';
          if (i === wrapIdx) td.classList.add('wrap');
          tr.appendChild(td);
        });
        if (table.rowAction && canRun) {
          const td = document.createElement('td');
          td.className = 'row-action';
          const b = document.createElement('button');
          b.className = 'tbtn tbtn-sm';
          b.textContent = table.rowAction.label;
          b.title = table.rowAction.title || '';
          b.addEventListener('click', () => runRowAction(table.rowAction, table.columns, r));
          td.appendChild(b);
          tr.appendChild(td);
        }
        frag.appendChild(tr);
      });
      tbody.textContent = '';
      tbody.appendChild(frag);
      count.textContent = q || rows.length !== table.rows.length ? `${rows.length} of ${table.rows.length} rows` : `${rows.length} rows`;
    }

    filter.addEventListener('input', () => { q = filter.value.trim().toLowerCase(); draw(); });
    draw();
  }

  /* ================= playbooks ================= */
  const STEP_ICON = { pending: '○', running: '●', pass: '✓', warn: '!', fail: '✕', skip: '–' };

  STEP_ICON.info = 'i';

  function buildPlaybookPane(tab, pb, displays) {
    const pane = tab.els.pane;
    const stepEls = pb.steps.map((spec, i) => {
      const el = document.createElement('div');
      el.className = 'pb-step';
      el.dataset.status = 'pending';
      el.innerHTML = `<span class="pb-icon">${STEP_ICON.pending}</span>
        <span class="pb-label"></span>
        <span class="pb-btns"><button class="pb-toggle pb-table-btn" hidden>table</button><button class="pb-toggle pb-out-btn" disabled>output</button></span>
        <span class="pb-summary"></span>
        <pre class="pb-out" hidden></pre>
        <div class="pb-tablewrap" hidden></div>`;
      const label = el.querySelector('.pb-label');
      label.textContent = `${i + 1}. ${spec.label} `;
      const cmdEl = document.createElement('span');
      cmdEl.className = 'pb-cmd';
      cmdEl.textContent = displays[i];
      label.appendChild(cmdEl);
      const ui = {
        el, cmdEl, output: '',
        toggle: el.querySelector('.pb-out-btn'), out: el.querySelector('.pb-out'),
        tableBtn: el.querySelector('.pb-table-btn'), tableWrap: el.querySelector('.pb-tablewrap'),
        summary: el.querySelector('.pb-summary'), icon: el.querySelector('.pb-icon'),
      };
      ui.toggle.addEventListener('click', () => { ui.out.hidden = !ui.out.hidden; ui.toggle.textContent = ui.out.hidden ? 'output' : 'hide output'; });
      ui.tableBtn.addEventListener('click', () => toggleStepTable(ui, spec));
      pane.appendChild(el);
      return ui;
    });
    const verdict = document.createElement('div');
    verdict.className = 'pb-verdict';
    verdict.hidden = true;
    pane.appendChild(verdict);
    return { stepEls, verdict };
  }

  function setStep(ui, status, summary) {
    ui.el.dataset.status = status;
    ui.icon.textContent = STEP_ICON[status] || '';
    if (summary !== undefined) ui.summary.textContent = summary;
  }

  // A step flagged `table` gets a Table view of its own output once it has run.
  function offerStepTable(ui, spec) {
    // A step only asks for a table when its variant keeps the command's normal output shape.
    ui.tableBtn.hidden = !(spec.table && ui.output && P.hasParser(spec.cmd, platform));
  }

  async function toggleStepTable(ui, spec) {
    if (!ui.tableWrap.hidden) { ui.tableWrap.hidden = true; ui.tableBtn.textContent = 'table'; return; }
    ui.tableWrap.hidden = false;
    ui.tableBtn.textContent = 'hide table';
    if (ui.tableWrap.dataset.ready) return;
    ui.tableWrap.innerHTML = '<p class="pane-empty">Building the table...</p>';
    const parsed = await parseForTable(spec.cmd, ui.output);
    if (parsed) renderTable(ui.tableWrap, parsed);
    else ui.tableWrap.innerHTML = '<p class="pane-empty">Nothing table-shaped in this output.</p>';
    ui.tableWrap.dataset.ready = '1';
  }

  function showVerdict(el, v) {
    el.hidden = false;
    el.dataset.tone = v.tone;
    el.innerHTML = '<span class="pb-verdict-label"></span><span class="pb-verdict-text"></span><span class="pb-actions"></span>';
    el.querySelector('.pb-verdict-label').textContent = { pass: 'all clear', warn: 'attention', fail: 'problem found' }[v.tone] || 'verdict';
    el.querySelector('.pb-verdict-text').textContent = v.text;
    const box = el.querySelector('.pb-actions');
    (v.actions || []).forEach((a) => {
      const b = document.createElement('button');
      b.className = 'tbtn tbtn-sm';
      b.textContent = a.label;
      b.addEventListener('click', () => runVerdictAction(a, b));
      box.appendChild(b);
    });
  }

  // Verdict actions are plain data so they survive in history: copy text, run a playbook, or jump to a card.
  // Row actions come from parsers as plain data: which command to run, and which column fills which parameter.
  function runRowAction(action, columns, row) {
    const cmd = byId.get(action.cmd);
    if (!cmd || !canRun) return;
    const params = {};
    for (const [k, col] of Object.entries(action.params || {})) { const i = columns.indexOf(col); if (i !== -1 && row[i]) params[k] = row[i]; }
    startRun(cmd, params);
  }

  function runVerdictAction(a, btn) {
    if (a.copy) {
      navigator.clipboard.writeText(a.copy).then(() => {
        const label = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = label; }, 1200);
      }).catch(() => {});
    } else if (a.playbook) {
      const next = PB.get(a.playbook);
      if (!next) return;
      // Run it straight away when it needs no input or the verdict supplied the input; otherwise show its card.
      if (!canRun || (next.params.length && !a.params)) jumpTo('pb', next.id, new URLSearchParams(a.params || {}));
      else runPlaybook(next, a.params || {});
    } else if (a.command) {
      jumpTo('cmd', a.command, new URLSearchParams(a.params || {}));
    }
  }

  function stepPreset(spec, cmd) {
    if (!spec.preset) return { idx: null, preset: null, missing: false };
    const list = (cmd.runnable || cmd.displaySpec)?.presets || [];
    const idx = list.findIndex((p) => p.key === spec.preset);
    return idx === -1 ? { idx: null, preset: null, missing: true } : { idx, preset: list[idx], missing: false };
  }

  // What a step will run, as text. Unresolved values show as <name> until a capture or the context fills them.
  function stepDisplay(spec, params, captures) {
    const cmd = byId.get(spec.cmd);
    const shown = Object.fromEntries(Object.entries(spec.params || {}).map(([k, v]) => [k, resolveTemplate(v, params, captures, true)]));
    // Steps show what really runs (netsh wlan show interfaces), not the card's friendly syntax (netsh).
    const base = cmd.runnable || cmd.displaySpec;
    const { preset } = stepPreset(spec, cmd);
    return base ? specDisplay(base, preset, shown) : displayFor(cmd, shown);
  }

  function resolveStep(spec, params, captures) {
    const cmd = byId.get(spec.cmd);
    const resolved = {};
    let missing = null;
    for (const [k, v] of Object.entries(spec.params || {})) {
      const open = unresolvedKeys(v, params, captures);
      if (open.length) missing = `${open[0]} not detected`;
      resolved[k] = resolveTemplate(v, params, captures);
    }
    const { idx, missing: noPreset } = stepPreset(spec, cmd);
    if (!cmd.runnable) missing = 'not runnable on this OS';
    else if (noPreset) missing = 'this variant is not available on this OS';
    return { cmd, params: resolved, preset: idx, missing };
  }

  async function runPlaybook(pb, params) {
    const tab = createTab({ kind: 'playbook', title: pb.name, pbId: pb.id, params });
    const captures = {};
    const ctx = context || {};
    const { stepEls, verdict } = buildPlaybookPane(tab, pb, pb.steps.map((s) => stepDisplay(s, params, captures)));
    const results = [];   // by position, for older verdicts
    const R = {};         // by step id
    const stored = [];
    let aborted = false;
    let halted = null;

    for (let i = 0; i < pb.steps.length; i++) {
      const spec = pb.steps[i], ui = stepEls[i];
      const record = (res, extra) => {
        results.push(res);
        if (spec.id) R[spec.id] = res;
        stored.push({ status: res?.status || 'skip', summary: ui.summary.textContent, ...extra });
      };
      const skip = (summary) => { setStep(ui, 'skip', summary); record(null); };
      if (aborted) { skip('not run'); continue; }
      if (halted) { skip(`not run - "${halted}" failed`); continue; }
      if (spec.skipIf?.(params) || (spec.when && !spec.when(R, params, ctx))) { skip('not needed'); continue; }
      const step = resolveStep(spec, params, captures);
      ui.cmdEl.textContent = stepDisplay(spec, params, captures);
      if (step.missing) { skip(step.missing); continue; }

      setStep(ui, 'running', 'running…');
      const started = Date.now();
      const r = await execute(step.cmd, step.params, {
        signal: tab.controller.signal,
        preset: step.preset,
        onChunk: (chunk) => { ui.output += chunk; ui.out.appendChild(document.createTextNode(chunk)); ui.toggle.disabled = false; },
      });
      const durationMs = Date.now() - started;
      if (r.aborted) { aborted = true; skip('stopped'); continue; }
      const check = r.refused || r.error
        ? { status: 'fail', summary: r.output.trim().slice(0, 160) }
        : PB.check(spec.check, r.output, step.params, ctx, { durationMs, exitCode: r.exitCode, step: spec, R });
      if (check.capture) Object.assign(captures, check.capture);
      setStep(ui, check.status, check.summary);
      ui.el.title = `took ${fmtDur(durationMs)}`;
      offerStepTable(ui, spec);
      record(check, { output: r.output.slice(0, 20000), durationMs });
      if (spec.stopOnFail && check.status === 'fail') halted = spec.label;
    }

    let v = null;
    if (!aborted) {
      v = pb.verdict(results, params, ctx, R);
      showVerdict(verdict, v);
      finishTab(tab, { pass: 'done', warn: 'warn', fail: 'error' }[v.tone] || 'done');
    } else {
      finishTab(tab, 'stopped');
    }
    saveHistory({
      kind: 'playbook', pbId: pb.id, title: pb.name, params,
      startedAt: tab.startedAt, endedAt: tab.endedAt, state: tab.state, exitCode: null,
      steps: stored, verdict: v, note: tab.note,
    });
    tab.hid = lastSavedHid;
    return { tab, verdict: v, results, R };
  }

  /* ================= history ================= */
  function loadHistory() {
    return readJson(HISTORY_KEY, []);
  }

  function persistHistory() {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // storage full or blocked: drop the oldest outputs and try once more
      history = history.map((h) => ({ ...h, output: h.output?.slice(0, 4000), steps: h.steps?.map((s) => ({ ...s, output: '' })) }));
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(history)); } catch { /* give up quietly */ }
    }
  }

  let lastSavedHid = null;
  function saveHistory(entry) {
    const hid = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    lastSavedHid = hid;
    history.unshift({ hid, ...entry });
    history = history.slice(0, MAX_HISTORY);
    persistHistory();
    renderHistory();
    DASH.poke('history', history[0]);
    if (entry.params?.host) { render(); renderPlaybooks(); }
  }

  function renderHistory() {
    historyList.textContent = '';
    historyEmpty.hidden = history.length > 0;
    history.forEach((h) => {
      const li = document.createElement('li');
      li.className = 'history-item';
      li.tabIndex = 0;
      const dur = h.endedAt ? fmtDur(h.endedAt - h.startedAt) : '';
      const exit = h.kind === 'run' ? (h.exitCode === null ? h.state : `exit ${h.exitCode}`) : (h.verdict ? h.verdict.tone : h.state);
      li.innerHTML = `<span class="status-dot" data-state="${dotFor(h.state)}"></span><span class="h-title"></span>${h.note ? '<span class="h-note" title="">✎</span>' : ''}<button class="tbtn tbtn-sm" title="Run again">↻</button><span class="h-meta"></span>`;
      li.querySelector('.h-title').textContent = h.title;
      if (h.note) li.querySelector('.h-note').title = h.note;
      li.querySelector('.h-meta').textContent = [fmtTime(h.startedAt), dur, exit].filter(Boolean).join(' · ');
      li.querySelector('button').addEventListener('click', (e) => { e.stopPropagation(); rerun(h); });
      li.addEventListener('click', () => openHistoryEntry(h));
      li.addEventListener('keydown', (e) => { if (e.key === 'Enter') openHistoryEntry(h); });
      historyList.appendChild(li);
    });
  }

  function rerun(h) {
    if (!canRun) return;
    if (h.kind === 'run') {
      const cmd = byId.get(h.cmdId);
      if (cmd) startRun(cmd, h.params || {}, { preset: h.preset ?? null, help: Boolean(h.help) });
    } else {
      const pb = PB.get(h.pbId);
      if (pb) runPlaybook(pb, h.params || {});
    }
  }

  function openHistoryEntry(h) {
    if (h.kind === 'run') {
      const tab = createTab({ kind: 'run', title: h.title, cmdId: h.cmdId, params: h.params, preset: h.preset ?? null, help: Boolean(h.help) });
      tab.startedAt = h.startedAt;
      tab.els.meta.querySelector('.started').textContent = `${new Date(h.startedAt).toLocaleDateString()} ${fmtTime(h.startedAt)}`;
      tab.output = h.output || '';
      appendRaw(tab, tab.output);
      tab.exitCode = h.exitCode;
      tab.hid = h.hid;
      setNote(tab, h.note);
      finishTab(tab, h.state);
      tab.endedAt = h.endedAt;
      if (h.endedAt) tab.els.meta.querySelector('.dur').textContent = fmtDur(h.endedAt - h.startedAt);
    } else {
      const pb = PB.get(h.pbId);
      if (!pb) return;
      const tab = createTab({ kind: 'playbook', title: h.title, pbId: h.pbId, params: h.params });
      const { stepEls, verdict } = buildPlaybookPane(tab, pb, pb.steps.map((s) => stepDisplay(s, h.params || {}, {})));
      (h.steps || []).forEach((s, i) => {
        const ui = stepEls[i];
        if (!ui) return;
        setStep(ui, s.status, s.summary);
        if (s.durationMs != null) ui.el.title = `took ${fmtDur(s.durationMs)}`;
        if (s.output) {
          ui.output = s.output;
          ui.out.textContent = s.output;
          ui.toggle.disabled = false;
          offerStepTable(ui, pb.steps[i]);
        }
      });
      if (h.verdict) showVerdict(verdict, h.verdict);
      tab.hid = h.hid;
      setNote(tab, h.note);
      finishTab(tab, h.state);
    }
  }

  $('history-clear').addEventListener('click', () => {
    history = [];
    persistHistory();
    renderHistory();
  });

  historyBtn.addEventListener('click', () => {
    const open = historyPanel.hidden;
    historyPanel.hidden = !open;
    historyBtn.setAttribute('aria-pressed', String(open));
    if (open) openTerminal();
  });

  /* ================= terminal chrome ================= */
  function openTerminal() {
    terminal.dataset.collapsed = 'false';
    toggleBtn.textContent = 'Collapse';
    toggleBtn.setAttribute('aria-expanded', 'true');
    document.body.classList.add('terminal-open');
  }

  toggleBtn.addEventListener('click', () => {
    if (terminal.dataset.collapsed === 'true') openTerminal();
    else {
      terminal.dataset.collapsed = 'true';
      toggleBtn.textContent = 'Expand';
      toggleBtn.setAttribute('aria-expanded', 'false');
      document.body.classList.remove('terminal-open');
    }
  });

  sizeBtn.addEventListener('click', () => {
    const tall = terminal.dataset.size !== 'tall';
    terminal.dataset.size = tall ? 'tall' : 'half';
    document.body.classList.toggle('terminal-tall', tall);
    openTerminal();
  });

  stopBtn.addEventListener('click', () => activeTab()?.controller.abort());
  closeAllBtn.addEventListener('click', () => { [...tabs].forEach((t) => closeTab(t.id)); });

  viewBtn.addEventListener('click', () => {
    const tab = activeTab();
    if (!tab) return;
    if (tab.view === 'table') showRaw(tab); else showTable(tab);
  });

  copyBtn.addEventListener('click', async () => {
    const tab = activeTab();
    if (!tab) return;
    let text = tab.output;
    if (tab.kind === 'playbook') {
      text = [...tab.els.pane.querySelectorAll('.pb-step')]
        .map((el) => `${el.querySelector('.pb-icon').textContent} ${el.querySelector('.pb-label').textContent.trim()} — ${el.querySelector('.pb-summary').textContent}`)
        .concat(tab.els.pane.querySelector('.pb-verdict-text')?.textContent || [])
        .join('\n');
    }
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.textContent = 'Copied';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
    } catch {
      copyBtn.textContent = 'Copy failed';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    }
  });

  /* ================= working with results: notes, compare, report, schedules ================= */

  /* ---- notes (kept with the run in History) ---- */
  function updateHistoryNote(hid, note) {
    const h = history.find((x) => x.hid === hid);
    if (!h) return;
    h.note = note;
    persistHistory();
    renderHistory();
  }

  // Adds the note box after `host` (must already be in the pane) and returns the toggle button for the tools row.
  function attachNote(tab, host) {
    const box = document.createElement('div');
    box.className = 'pane-note';
    box.hidden = !tab.note;
    const ta = document.createElement('textarea');
    ta.className = 'pane-note-text';
    ta.rows = 2;
    ta.placeholder = 'Note for this run — what you were seeing, a ticket number, what you tried. Saved with the run in History and included in reports.';
    ta.value = tab.note || '';
    let timer = null;
    ta.addEventListener('input', () => {
      tab.note = ta.value;
      btn.setAttribute('aria-pressed', String(Boolean(tab.note) || !box.hidden));
      clearTimeout(timer);
      timer = setTimeout(() => { if (tab.hid) updateHistoryNote(tab.hid, tab.note); }, 400);
    });
    box.appendChild(ta);
    host.insertAdjacentElement('afterend', box);
    const btn = document.createElement('button');
    btn.className = 'tbtn tbtn-sm note-btn';
    btn.textContent = 'note';
    btn.title = 'Attach a note to this run (kept in History, included in reports)';
    btn.setAttribute('aria-pressed', String(Boolean(tab.note)));
    btn.addEventListener('click', () => { box.hidden = !box.hidden; btn.setAttribute('aria-pressed', String(!box.hidden || Boolean(tab.note))); if (!box.hidden) ta.focus(); });
    Object.assign(tab.els, { note: box, noteText: ta, noteBtn: btn });
    return btn;
  }

  function setNote(tab, text) {
    tab.note = text || '';
    if (!tab.els.noteText) return;
    tab.els.noteText.value = tab.note;
    tab.els.note.hidden = !tab.note;
    tab.els.noteBtn.setAttribute('aria-pressed', String(Boolean(tab.note)));
  }

  /* ---- compare two runs ---- */
  function pbText(pane) {
    return [...pane.querySelectorAll('.pb-step')]
      .map((el) => `${el.querySelector('.pb-icon').textContent} ${el.querySelector('.pb-label').textContent.trim()} — ${el.querySelector('.pb-summary').textContent}`)
      .concat(pane.querySelector('.pb-verdict-text')?.textContent || [])
      .join('\n');
  }
  const textOfTab = (tab) => (tab.kind === 'playbook' ? pbText(tab.els.pane) : tab.output);
  const textOfHistory = (h) => (h.kind === 'playbook'
    ? (h.steps || []).map((s) => `${STEP_ICON[s.status] || '○'} ${s.summary}`).concat(h.verdict ? [h.verdict.text] : []).join('\n')
    : (h.output || ''));

  // Line diff by longest common subsequence, capped so a 5,000-line capture cannot freeze the page.
  function diffLines(a, b) {
    const A = a.replace(/\r/g, '').split('\n'), B = b.replace(/\r/g, '').split('\n');
    const cap = 1500;
    const ta = A.slice(0, cap), tb = B.slice(0, cap);
    const n = ta.length, m = tb.length;
    const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
    for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = ta[i] === tb[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const ops = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (ta[i] === tb[j]) { ops.push(['=', ta[i]]); i++; j++; }
      else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push(['-', ta[i]]); i++; }
      else { ops.push(['+', tb[j]]); j++; }
    }
    while (i < n) ops.push(['-', ta[i++]]);
    while (j < m) ops.push(['+', tb[j++]]);
    return { ops, truncated: A.length > cap || B.length > cap };
  }

  const escHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function showDiff(a, b) {
    // a and b: { title, when, text }; a is the older one
    const { ops, truncated } = diffLines(a.text, b.text);
    const added = ops.filter((o) => o[0] === '+').length, removed = ops.filter((o) => o[0] === '-').length;
    const tab = createTab({ kind: 'run', title: `Compare: ${b.title}`, cmdId: null, params: {} });
    tab.els.meta.querySelector('.link-tbtn').hidden = true;
    // collapse long unchanged stretches
    const html = [];
    const unified = [];
    let run = [];
    const flushRun = () => {
      if (!run.length) return;
      if (run.length > 8) {
        run.slice(0, 3).forEach((l) => { html.push(`<span class="diff-ctx">  ${escHtml(l)}</span>`); unified.push('  ' + l); });
        html.push(`<span class="diff-skip">  … ${run.length - 6} unchanged lines …</span>`); unified.push(`  … ${run.length - 6} unchanged lines …`);
        run.slice(-3).forEach((l) => { html.push(`<span class="diff-ctx">  ${escHtml(l)}</span>`); unified.push('  ' + l); });
      } else run.forEach((l) => { html.push(`<span class="diff-ctx">  ${escHtml(l)}</span>`); unified.push('  ' + l); });
      run = [];
    };
    for (const [op, line] of ops) {
      if (op === '=') { run.push(line); continue; }
      flushRun();
      html.push(`<span class="${op === '+' ? 'diff-add' : 'diff-del'}">${op} ${escHtml(line)}</span>`);
      unified.push(`${op} ${line}`);
    }
    flushRun();
    const head = `− A: ${a.title}  (${a.when})\n+ B: ${b.title}  (${b.when})\n${removed} line${removed === 1 ? '' : 's'} only in A, ${added} only in B${truncated ? ' — compared the first 1,500 lines of each' : ''}${!added && !removed ? ' — identical' : ''}\n\n`;
    tab.output = head + unified.join('\n');
    tab.els.raw.innerHTML = `<span class="diff-head">${escHtml(head)}</span>` + html.join('\n');
    tab.exitCode = null;
    finishTab(tab, 'done');
    return tab;
  }

  const compareModal = $('compare-modal'), compareList = $('compare-list'), compareEmpty = $('compare-empty');
  function openCompare() {
    const cur = activeTab();
    if (!cur || cur.state === 'running') return;
    compareList.textContent = '';
    const key = cur.kind === 'playbook' ? ['pbId', cur.pbId] : ['cmdId', cur.cmdId];
    const cands = [];
    tabs.filter((t) => t !== cur && t.state !== 'running' && t[key[0]] === key[1] && t.kind === cur.kind && t.cmdId !== null).forEach((t) => cands.push({ id: 'tab:' + t.id, label: `${t.title} — open tab, ${fmtTime(t.startedAt)}`, when: t.startedAt, text: () => textOfTab(t), title: t.title }));
    history.filter((h) => h.kind === cur.kind && h[key[0]] === key[1] && h.hid !== cur.hid).slice(0, 25).forEach((h) => cands.push({ id: 'hist:' + h.hid, label: `${h.title} — ${new Date(h.startedAt).toLocaleDateString()} ${fmtTime(h.startedAt)}${h.note ? ' · ' + h.note.slice(0, 40) : ''}`, when: h.startedAt, text: () => textOfHistory(h), title: h.title }));
    compareEmpty.hidden = cands.length > 0;
    compareEmpty.textContent = `No other run of "${cur.title}" is open or in History yet. Run it again later and compare then.`;
    cands.forEach((c, i) => {
      const label = document.createElement('label');
      label.innerHTML = `<input type="radio" name="compare-pick" value="${c.id}"${i === 0 ? ' checked' : ''}><span></span>`;
      label.querySelector('span').textContent = c.label;
      compareList.appendChild(label);
    });
    compareModal.dataset.cands = '1';
    compareModal._cands = cands;
    compareModal._cur = cur;
    compareModal.hidden = false;
  }
  $('compare-cancel').addEventListener('click', () => { compareModal.hidden = true; });
  $('compare-go').addEventListener('click', () => {
    const pick = compareModal.querySelector('input[name="compare-pick"]:checked');
    const c = (compareModal._cands || []).find((x) => x.id === pick?.value);
    const cur = compareModal._cur;
    compareModal.hidden = true;
    if (!c || !cur) return;
    const mine = { title: cur.title, when: `${new Date(cur.startedAt).toLocaleDateString()} ${fmtTime(cur.startedAt)}`, text: textOfTab(cur), at: cur.startedAt };
    const other = { title: c.title, when: `${new Date(c.when).toLocaleDateString()} ${fmtTime(c.when)}`, text: c.text(), at: c.when };
    const [a, b] = other.at <= mine.at ? [other, mine] : [mine, other];
    showDiff(a, b);
  });

  /* ---- report: a self-contained HTML file of one run ---- */
  function makeAnonymiser() {
    const ipMap = new Map();
    let n = 0;
    const host = (context?.hostname || '').trim();
    const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;
    const keep = /^(127\.|0\.0\.0\.0$|255\.|224\.|239\.|1\.1\.1\.1$|1\.0\.0\.1$|8\.8\.8\.8$|8\.8\.4\.4$|9\.9\.9\.9$)/;
    return (text) => {
      let s = String(text);
      if (host) s = s.replace(new RegExp(host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), 'OFFICE-PC');
      s = s.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, (m) => { if (keep.test(m)) return m; if (!ipMap.has(m)) { n++; ipMap.set(m, (priv.test(m) ? '192.0.2.' : '203.0.113.') + n); } return ipMap.get(m); });
      s = s.replace(/\b([0-9A-Fa-f]{2})([-:])([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}\b/g, (m, a, sep, b, c) => `${a}${sep}${b}${sep}${c}${sep}xx${sep}xx${sep}xx`);
      s = s.replace(/\b[23][0-9a-f]{3}:[0-9a-f:]{3,}\b/gi, '2001:db8::1');
      return s;
    };
  }

  function buildReport(tab, { anonymise, fullOutputs }) {
    const anon = anonymise ? makeAnonymiser() : (t) => t;
    const e = (t) => escHtml(anon(t));
    const when = new Date(tab.startedAt);
    const dur = tab.endedAt ? fmtDur(tab.endedAt - tab.startedAt) : '';
    const edition = TAURI ? 'desktop app' : STATIC ? 'hosted reference' : 'local server';
    const params = Object.entries(tab.params || {}).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join(', ');
    let body = '';
    if (tab.kind === 'playbook') {
      const steps = [...tab.els.pane.querySelectorAll('.pb-step')];
      const v = tab.els.pane.querySelector('.pb-verdict');
      body += '<h2>Steps</h2><ol class="steps">' + steps.map((el, i) => {
        const status = el.dataset.status || '';
        const out = fullOutputs ? (el.querySelector('.pb-out')?.textContent || '') : '';
        return `<li class="step s-${status}"><span class="icon">${escHtml(el.querySelector('.pb-icon').textContent)}</span> <strong>${escHtml(el.querySelector('.pb-label').textContent.trim())}</strong><div class="sum">${e(el.querySelector('.pb-summary').textContent)}</div>${out ? `<details><summary>output</summary><pre>${e(out)}</pre></details>` : ''}</li>`;
      }).join('') + '</ol>';
      if (v && !v.hidden) body += `<h2>Verdict</h2><div class="verdict tone-${escHtml(v.dataset.tone || '')}"><span class="lbl">${escHtml(v.querySelector('.pb-verdict-label')?.textContent || '')}</span><p>${e(v.querySelector('.pb-verdict-text')?.textContent || '').replace(/\n/g, '<br>')}</p></div>`;
    } else {
      body += `<h2>Output</h2><pre>${e(tab.output)}</pre>`;
      if (tab.table && tab.table.rows.length) body += '<h2>Table</h2><table><thead><tr>' + tab.table.columns.map((c) => `<th>${e(c)}</th>`).join('') + '</tr></thead><tbody>' + tab.table.rows.map((r) => '<tr>' + r.map((c) => `<td>${e(c)}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
    }
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${e(tab.title)} — NetDeck report</title>
<style>
body{font:14px/1.5 system-ui,Segoe UI,sans-serif;color:#1e221e;background:#fff;max-width:960px;margin:32px auto;padding:0 20px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:#666;margin:28px 0 8px}
.meta{color:#555;font-size:13px}.meta span{margin-right:16px}.note{background:#f4f6f4;border-left:3px solid #8fb896;padding:8px 12px;margin:14px 0;white-space:pre-wrap}
pre{background:#f6f7f6;border:1px solid #dfe3df;border-radius:6px;padding:12px;overflow:auto;font:12.5px/1.45 ui-monospace,Consolas,monospace;white-space:pre-wrap}
table{border-collapse:collapse;font-size:12.5px;width:100%}th,td{border:1px solid #dfe3df;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f0f2f0}
ol.steps{list-style:none;padding:0;margin:0}.step{border:1px solid #dfe3df;border-radius:6px;padding:8px 12px;margin-bottom:8px}.step .icon{display:inline-block;width:1.4em;font-weight:600}
.s-pass .icon{color:#3d7a48}.s-warn .icon{color:#9a5a3c}.s-fail .icon{color:#a53c3c}.step .sum{color:#444;margin-left:1.4em}details{margin-left:1.4em;margin-top:6px}summary{cursor:pointer;color:#555;font-size:12.5px}
.verdict{border:1px solid #dfe3df;border-left-width:4px;border-radius:6px;padding:10px 14px}.verdict .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#666}.tone-pass{border-left-color:#3d7a48}.tone-warn{border-left-color:#9a5a3c}.tone-fail{border-left-color:#a53c3c}.verdict p{margin:6px 0 0;white-space:pre-wrap}
.foot{margin-top:36px;color:#888;font-size:12px}.print{float:right;font:13px system-ui;padding:6px 12px;border:1px solid #b6bab6;border-radius:6px;background:#fff;cursor:pointer}
@media print{.print{display:none}details{display:block}details>summary{display:none}details>*{display:block}}
</style></head><body>
<button class="print" onclick="window.print()">Print / save as PDF</button>
<h1>${e(tab.title)}</h1>
<div class="meta"><span>${when.toLocaleString()}</span>${dur ? `<span>took ${dur}</span>` : ''}${tab.exitCode !== null && tab.exitCode !== undefined ? `<span>exit ${tab.exitCode}</span>` : ''}${params ? `<span>${e(params)}</span>` : ''}<span>NetDeck ${window.NETDECK_VERSION || ''} (${edition})</span>${anonymise ? '<span>anonymised: computer name, addresses and MACs replaced</span>' : ''}</div>
${tab.note ? `<div class="note">${e(tab.note)}</div>` : ''}
${body}
<p class="foot">Generated by NetDeck — network &amp; system command reference.</p>
</body></html>`;
  }

  function saveFile(name, text, type) {
    if (BACKEND.saveText) { BACKEND.saveText(name, text).catch(() => {}); return; }
    const blob = new Blob([text], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  const reportModal = $('report-modal');
  $('report-cancel').addEventListener('click', () => { reportModal.hidden = true; });
  $('report-go').addEventListener('click', () => {
    const tab = activeTab();
    reportModal.hidden = true;
    if (!tab) return;
    const html = buildReport(tab, { anonymise: $('report-anon').checked, fullOutputs: $('report-full').checked });
    const slug = tab.title.replace(/[^A-Za-z0-9.-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'run';
    const stamp = new Date(tab.startedAt).toISOString().replace(/[:T]/g, '-').slice(0, 19);
    saveFile(`${slug}-report-${stamp}.html`, html, 'text/html');
  });

  /* ---- schedules: a playbook every N minutes while NetDeck is open, alert on change ---- */
  const SCHED_KEY = 'netdeck.schedules.v1';
  let schedules = readJson(SCHED_KEY, []);
  const schedRunning = new Set();
  const schedBadge = $('sched-badge'), schedModal = $('schedule-modal'), schedList = $('schedule-list'), schedPb = $('schedule-pb');
  function persistSchedules() { try { localStorage.setItem(SCHED_KEY, JSON.stringify(schedules)); } catch { /* fine */ } renderSchedBadge(); }
  function renderSchedBadge() {
    schedBadge.hidden = !schedules.length || !canRun;
    const alerts = schedules.filter((s) => s.alert).length;
    schedBadge.textContent = `⏱ ${schedules.length} schedule${schedules.length === 1 ? '' : 's'}${alerts ? ` · ${alerts} changed` : ''}`;
    schedBadge.classList.toggle('sched-alert', alerts > 0);
  }
  const signatureOf = (v, results, R) => `${v?.tone || 'none'}|${results.map((r) => r?.status || 'skip').join(',')}|${(R?.scan?.data?.fresh || []).length ? 'new-devices' : ''}`;
  function notifyChange(pb, v) {
    const body = (v?.text || 'result changed').slice(0, 200);
    if (BACKEND.notify) { BACKEND.notify(`NetDeck schedule: ${pb.name} changed`, body).catch(() => {}); return; }
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') new Notification(`NetDeck schedule: ${pb.name} changed`, { body });
  }
  async function runScheduled(s) {
    const pb = PB.get(s.pbId);
    if (!pb || !canRun || schedRunning.has(s.id)) return;
    schedRunning.add(s.id);
    try {
      const out = await runPlaybook(pb, s.params || {});
      const sig = signatureOf(out.verdict, out.results, out.R);
      const changed = Boolean(s.lastSig) && sig !== s.lastSig;
      s.lastRunAt = Date.now(); s.lastSig = sig; s.lastTone = out.verdict?.tone || out.tab.state; s.runs = (s.runs || 0) + 1;
      if (changed) {
        s.changes = (s.changes || 0) + 1; s.alert = true;
        out.tab.title = `! ${out.tab.title}`; renderTabStrip();
        if (s.notify) notifyChange(pb, out.verdict);
      } else if (s.prevTabId && tabs.some((t) => t.id === s.prevTabId) && s.prevTabId !== activeTabId) {
        closeTab(s.prevTabId);   // keep only the latest unchanged run open, so scheduled runs do not pile up
      }
      s.prevTabId = changed ? null : out.tab.id;
      persistSchedules();
    } catch (e) { /* the run itself reported */ } finally { schedRunning.delete(s.id); }
  }
  function schedTick() {
    if (!canRun || document.hidden && false) return;
    const now = Date.now();
    schedules.forEach((s) => { if (!s.lastRunAt || now - s.lastRunAt >= s.minutes * 60000) runScheduled(s); });
  }
  setInterval(schedTick, 15000);
  setTimeout(schedTick, 4000);

  function renderSchedules() {
    schedList.textContent = '';
    $('schedule-empty').hidden = schedules.length > 0;
    schedules.forEach((s) => {
      const pb = PB.get(s.pbId);
      const li = document.createElement('li');
      li.className = 'sched-item';
      const last = s.lastRunAt ? `last ${fmtTime(s.lastRunAt)}${s.lastTone ? ` (${s.lastTone})` : ''}` : 'not run yet';
      li.innerHTML = `<span class="grow"><strong></strong> every ${s.minutes} min — ${last}${s.runs ? `, ${s.runs} run${s.runs === 1 ? '' : 's'}` : ''}${s.changes ? `, <span class="changed">${s.changes} change${s.changes === 1 ? '' : 's'}</span>` : ''}${s.notify ? ' · notifies' : ''}</span><button class="tbtn tbtn-sm run-now">Run now</button><button class="tbtn tbtn-sm cancel">Remove</button>`;
      li.querySelector('strong').textContent = pb ? pb.name : s.pbId;
      li.querySelector('.run-now').addEventListener('click', () => { s.lastRunAt = 0; schedTick(); schedModal.hidden = true; });
      li.querySelector('.cancel').addEventListener('click', () => { schedules = schedules.filter((x) => x !== s); persistSchedules(); renderSchedules(); });
      schedList.appendChild(li);
    });
  }
  function openSchedules() {
    schedules.forEach((s) => { s.alert = false; });
    persistSchedules();
    schedPb.textContent = '';
    PB.list().forEach((pb) => {
      const lastParams = history.find((h) => h.kind === 'playbook' && h.pbId === pb.id && h.params && Object.values(h.params).some(Boolean))?.params;
      if (pb.params.length && !lastParams) return;   // needs input and was never run: nothing to schedule with
      const o = document.createElement('option');
      o.value = pb.id;
      o.textContent = pb.name + (pb.params.length ? ` (with ${Object.values(lastParams).filter(Boolean).join(', ')})` : '');
      o.dataset.params = JSON.stringify(lastParams || {});
      schedPb.appendChild(o);
    });
    renderSchedules();
    schedModal.hidden = false;
  }
  schedBadge.addEventListener('click', openSchedules);
  $('term-schedule').addEventListener('click', openSchedules);
  $('schedule-cancel').addEventListener('click', () => { schedModal.hidden = true; });
  $('schedule-add').addEventListener('click', async () => {
    const o = schedPb.selectedOptions[0];
    if (!o) return;
    const notify = $('schedule-notify').checked;
    if (notify && !TAURI && typeof Notification !== 'undefined' && Notification.permission !== 'granted') { try { await Notification.requestPermission(); } catch { /* fine */ } }
    schedules.push({ id: `s${Date.now()}`, pbId: o.value, params: JSON.parse(o.dataset.params || '{}'), minutes: Number($('schedule-every').value) || 15, notify, lastRunAt: 0, lastSig: '', runs: 0, changes: 0 });
    persistSchedules();
    renderSchedules();
    schedTick();
  });
  renderSchedBadge();

  /* ---- buttons in the terminal bar ---- */
  $('term-compare').addEventListener('click', openCompare);
  $('term-report').addEventListener('click', () => { const t = activeTab(); if (!t || t.state === 'running') return; $('report-full').parentElement.hidden = t.kind !== 'playbook'; reportModal.hidden = false; });
  const _syncActions = syncActions;
  syncActions = function () {
    _syncActions();
    const t = activeTab();
    const ready = Boolean(t) && t.state !== 'running';
    $('term-compare').disabled = !ready || (t.kind === 'run' && !t.cmdId);
    $('term-report').disabled = !ready || (t.kind === 'run' && !t.cmdId);
  };

  /* ================= command palette ================= */
  let paletteItems = [];
  let paletteIdx = 0;

  function paletteEntries() {
    const cmds = commands.filter((c) => !c.hidden).map((c) => ({ kind: 'cmd', id: c.id, title: c.name, sub: c.purpose, cat: c.category, pinned: isPinned('cmd', c.id), hay: `${c.name} ${c.win || ''} ${(c.unix || []).join(' ')} ${c.purpose} ${c.category}`.toLowerCase() }));
    const pbs = PB.list().map((p) => ({ kind: 'pb', id: p.id, title: p.name, sub: p.description, cat: 'playbook', pinned: isPinned('pb', p.id), hay: `${p.name} ${p.description} playbook`.toLowerCase() }));
    return [...cmds, ...pbs].sort((a, b) => Number(b.pinned) - Number(a.pinned));
  }

  function openPalette() {
    palette.hidden = false;
    paletteInput.value = '';
    filterPalette();
    paletteInput.focus();
  }

  function closePalette() { palette.hidden = true; }

  function filterPalette() {
    const q = paletteInput.value.trim().toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
    const all = paletteEntries();
    if (terms.length) {
      paletteItems = all.filter((e) => terms.every((t) => e.hay.includes(t))).slice(0, 40);
    } else {
      // nothing typed: pinned first, then what you ran recently, then every playbook, then every command
      const key = (e) => `${e.kind}:${e.id}`;
      const pinned = all.filter((e) => e.pinned);
      const taken = new Set(pinned.map(key));
      const recent = [];
      for (const h of history) {
        const k = h.kind === 'run' ? `cmd:${h.cmdId}` : `pb:${h.pbId}`;
        if (taken.has(k)) continue;
        const e = all.find((x) => key(x) === k);
        if (!e) continue;
        taken.add(k);
        recent.push({ ...e, cat: 'recent' });
        if (recent.length >= 6) break;
      }
      const rest = all.filter((e) => !taken.has(key(e)));
      paletteItems = [...pinned, ...recent, ...rest.filter((e) => e.kind === 'pb'), ...rest.filter((e) => e.kind === 'cmd')];
    }
    paletteIdx = 0;
    paletteList.textContent = '';
    paletteItems.forEach((e, i) => {
      const li = document.createElement('li');
      li.className = `palette-item${i === 0 ? ' is-active' : ''}`;
      li.setAttribute('role', 'option');
      li.innerHTML = `<span class="p-title"></span><span class="p-cat"></span><span class="p-sub"></span>`;
      li.querySelector('.p-title').textContent = (e.pinned ? '★ ' : '') + e.title;
      li.querySelector('.p-cat').textContent = e.cat;
      li.querySelector('.p-sub').textContent = e.sub;
      li.addEventListener('mouseenter', () => setPaletteIdx(i));
      li.addEventListener('click', () => choosePalette(i));
      paletteList.appendChild(li);
    });
    if (!paletteItems.length) paletteList.innerHTML = '<li class="palette-empty">No matches</li>';
  }

  function setPaletteIdx(i) {
    paletteIdx = i;
    paletteList.querySelectorAll('.palette-item').forEach((el, k) => el.classList.toggle('is-active', k === i));
    paletteList.querySelector('.palette-item.is-active')?.scrollIntoView({ block: 'nearest' });
  }

  function choosePalette(i) {
    const e = paletteItems[i];
    if (!e) return;
    closePalette();
    history.replaceState?.(null, '', `#${e.kind}/${e.id}`);
    jumpTo(e.kind, e.id);
  }

  paletteInput.addEventListener('input', filterPalette);
  paletteInput.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setPaletteIdx(Math.min(paletteIdx + 1, paletteItems.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setPaletteIdx(Math.max(paletteIdx - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); choosePalette(paletteIdx); }
    else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
  });
  palette.addEventListener('click', (e) => { if (e.target === palette) closePalette(); });
  $('palette-open').addEventListener('click', openPalette);

  /* ================= keyboard navigation through cards ================= */
  function setCursor(card, flash) {
    cursorCard?.classList.remove('cursor', 'flash');
    cursorCard = card;
    if (!card) return;
    card.classList.add('cursor');
    if (flash) { card.classList.add('flash'); setTimeout(() => card.classList.remove('flash'), 1600); }
  }

  function moveCursor(dir) {
    if (activeView === 'dashboard') return;
    const cards = [...(activeView === 'commands' ? grid : playbookGrid).querySelectorAll('.card')];
    if (!cards.length) return;
    const idx = cards.indexOf(cursorCard);
    const next = idx === -1 ? (dir > 0 ? 0 : cards.length - 1) : Math.max(0, Math.min(cards.length - 1, idx + dir));
    setCursor(cards[next], false);
    cards[next].scrollIntoView({ block: 'nearest' });
  }

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (palette.hidden) openPalette(); else closePalette();
      return;
    }
    if (!palette.hidden || !customModal.hidden || !$('agent-modal').hidden || !elevateModal.hidden) {
      if (e.key === 'Escape') { closePalette(); closeCustom(); closeAgent(); closeElevate(); }
      return;
    }
    if (e.target.closest?.('input, textarea, select, [contenteditable]')) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    switch (e.key) {
      case '/': e.preventDefault(); searchInput.focus(); break;
      case 'j': case 'ArrowDown': e.preventDefault(); moveCursor(1); break;
      case 'k': case 'ArrowUp': e.preventDefault(); moveCursor(-1); break;
      case 'Escape': setCursor(null); break;
      case 'Enter': {
        if (!cursorCard) break;
        const empty = [...cursorCard.querySelectorAll('.param-input:not([hidden])')].find((i) => !i.value.trim());
        if (empty) empty.focus(); else cursorCard.querySelector('.run-btn')?.click();
        break;
      }
      case 'c': cursorCard?.querySelector('.copy-btn')?.click(); break;
      case 'p': cursorCard?.querySelector('.pin-btn')?.click(); break;
      case 'h': cursorCard?.querySelector('.help-btn')?.click(); break;
      case 'l': cursorCard?.querySelector('.link-btn')?.click(); break;
      case 'm': cursorCard?.querySelector('.manual-btn')?.click(); break;
      default:
    }
  });

  /* ================= theme ================= */
  $('theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    writePref('netdeck.theme', next);
  });

  /* ================= static mode: pairing with a local NetDeck ================= */
  const agentModal = $('agent-modal');

  function setAgentStatus(state, detail) {
    const el = $('agent-status');
    if (!el) return;
    el.dataset.state = state;
    el.textContent = { connected: `connected to ${detail}`, offline: 'local NetDeck not reachable', none: 'reference mode — commands can’t run from a hosted page' }[state] || '';
    $('agent-disconnect').hidden = !API;
    $('agent-open').textContent = API ? 'Change connection' : 'Connect local NetDeck';
  }

  function openAgent() {
    $('agent-url').value = API || 'http://localhost:4573';
    $('agent-token').value = TOKEN || '';
    $('agent-error').textContent = '';
    agentModal.hidden = false;
    $('agent-url').focus();
  }

  function closeAgent() { agentModal.hidden = true; }

  async function submitAgent(e) {
    e.preventDefault();
    const url = $('agent-url').value.trim().replace(/\/$/, '');
    const token = $('agent-token').value.trim();
    const err = $('agent-error');
    err.textContent = 'Testing…';
    try {
      BACKEND.configure({ base: url, token });
      const info = await BACKEND.ping();
      API = url; TOKEN = token;
      writePref('netdeck.agent.url', API);
      writePref('netdeck.agent.token', TOKEN);
      closeAgent();
      await init();
      setAgentStatus('connected', info.hostname || url);
    } catch (ex) {
      BACKEND.configure({ base: API, token: TOKEN });
      err.textContent = `Could not connect: ${ex.message}. Is the local server running as  NETDECK_ORIGIN=${location.origin} node server.js  with this token? (Safari blocks localhost from https pages; use Chrome, Edge or Firefox.)`;
    }
  }

  if (STATIC) {
    $('agent-open').addEventListener('click', openAgent);
    $('agent-cancel').addEventListener('click', closeAgent);
    $('agent-form').addEventListener('submit', submitAgent);
    $('agent-disconnect').addEventListener('click', async () => {
      API = ''; TOKEN = '';
      BACKEND.configure({});
      writePref('netdeck.agent.url', '');
      writePref('netdeck.agent.token', '');
      await init();
    });
    agentModal.addEventListener('click', (e) => { if (e.target === agentModal) closeAgent(); });
  }

  /* ================= boot ================= */
  async function loadCommands() {
    if (!STATIC || API) {
      try {
        const data = await BACKEND.commands();
        return { platform: data.platform, commands: data.commands, live: true };
      } catch (e) {
        if (!STATIC) throw e;
        setAgentStatus('offline');
      }
    }
    const raw = await fetch('commands.json').then((r) => r.json());
    // displaySpec keeps the Windows run spec for showing variants in playbook steps; nothing can execute it here.
    const shaped = raw.map((c) => ({ ...c, run: undefined, runUnix: undefined, help: undefined, helpUnix: undefined, runnable: null, hasHelp: false, displaySpec: c.run || null }));
    return { platform: 'win32', commands: [...shaped, ...localCustoms()], live: false };
  }

  async function init() {
    let data;
    try {
      data = await loadCommands();
    } catch {
      emptyMsg.hidden = false;
      emptyMsg.textContent = 'Could not load command data — is the server running? (node server.js)';
      return;
    }
    platform = data.platform || 'win32';
    commands = data.commands;
    byId.clear();
    commands.forEach((c) => byId.set(c.id, c));
    canRun = data.live;
    document.body.dataset.mode = canRun ? 'live' : 'static';
    document.body.dataset.backend = BACKEND.kind;
    // the version comes from version.js, written by tools/bump.js; the tooltip says which edition this is
    const verEl = $('app-version');
    if (verEl && window.NETDECK_VERSION) {
      verEl.textContent = 'v' + window.NETDECK_VERSION;
      verEl.title = `NetDeck ${window.NETDECK_VERSION} — ${TAURI ? 'desktop app' : STATIC ? 'hosted reference' : 'local server'}`;
    }
    if (TAURI && !document.body.dataset.docLinks) {
      // In the desktop app the Manual and Cheat sheet open in their own window, so this one keeps its tabs.
      document.body.dataset.docLinks = '1';
      document.querySelectorAll('a.manual-link').forEach((a) => {
        a.addEventListener('click', (e) => { e.preventDefault(); BACKEND.openDoc(a.getAttribute('href')).catch(() => {}); });
      });
      // A webview has no tabs: hand the author's site to the default browser instead.
      $('site-link').addEventListener('click', (e) => { e.preventDefault(); BACKEND.openSite().catch(() => {}); });
    }
    if (STATIC && !API) setAgentStatus('none');
    buildCategoryChips();
    buildPlaybookGroupChips();
    DASH.init({
      $, byId, PB, P, execute, startRun, runPlaybook, isWin, saveFile, anonymiser: makeAnonymiser,
      bookSvg: BOOK_SVG, openDoc: (page, anchor) => BACKEND.openDoc(page, anchor).catch(() => {}),
      context: () => context, health: () => health, history: () => history, canRun: () => canRun,
    });
    render();
    renderPlaybooks();
    renderHistory();
    syncNotifyButton();
    if (canRun) {
      await loadContext(false);
      startHealth();
    } else {
      context = null;
    }
    applyHash();
  }

  init();
})();
