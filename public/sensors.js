/* NetDeck network sensors: shared by the Dashboard's Network sensors card and the mini monitor window.
   Latency and loss come from the backend's connection watcher (NetDeckAPI.sensors: readings since the last reset
   plus a rolling history); traffic and Wi-Fi are sampled here, by running the same read-only commands the rest of
   the app uses, only while a sensors view is open. */
window.NetDeckSensors = (() => {
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* A running statistic for page-side readings (traffic, Wi-Fi): latest, lowest, highest, average. */
  function acc() { return { last: null, min: null, max: null, sum: 0, n: 0, hist: [] }; }
  function accAdd(a, v, t) {
    if (v == null || !Number.isFinite(v)) { a.last = null; return; }
    a.last = v; a.min = a.min == null ? v : Math.min(a.min, v); a.max = a.max == null ? v : Math.max(a.max, v); a.sum += v; a.n++;
    a.hist.push([t, v]);
    if (a.hist.length > 600) a.hist.splice(0, a.hist.length - 600);
  }
  const accAvg = (a) => (a.n ? a.sum / a.n : null);

  /* Adapter byte counters → receive / send rates in bit/s, for the adapter the default route uses. */
  function trafficSampler(runStats, adapterName) {
    let prev = null;
    return async function sample() {
      const out = await runStats();
      const m = String(out || '').match(/^STATS (\{.*\})\s*$/m);
      if (!m) return null;
      const d = JSON.parse(m[1]);
      const list = Array.isArray(d.adapters) ? d.adapters : [d.adapters].filter(Boolean);
      const name = adapterName();
      const a = list.find((x) => x.name === name) || list.find((x) => !x.virtual) || list[0];
      if (!a) return null;
      const now = Number(d.t) || Date.now();
      let res = null;
      if (prev && prev.name === a.name && now > prev.t && a.rx >= prev.rx && a.tx >= prev.tx) {
        const dt = (now - prev.t) / 1000;
        res = { t: now, name: a.name, down: ((a.rx - prev.rx) * 8) / dt, up: ((a.tx - prev.tx) * 8) / dt, speed: a.speed };
      }
      prev = { t: now, name: a.name, rx: a.rx, tx: a.tx };
      return res;
    };
  }

  const fmtMs = (v) => (v == null ? '—' : v < 1 ? '<1' : String(Math.round(v)));
  const fmtRate = (bps) => {
    if (bps == null) return '—';
    const m = bps / 1e6;
    return m >= 100 ? String(Math.round(m)) : m >= 10 ? m.toFixed(1) : m >= 0.1 ? m.toFixed(2) : m > 0 ? '<0.1' : '0';
  };
  const clock = (ms) => { const s = Math.max(0, Math.floor(ms / 1000)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60; return `${h}:${String(m).padStart(2, '0')}:${String(x).padStart(2, '0')}`; };

  /* Latency graph from the watcher's history: router and internet lines, a red mark wherever a ping got no answer. */
  function latencyGraph(ring, { w = 600, h = 160, span = 5 * 60000, now = Date.now(), axis = true } = {}) {
    const from = now - span;
    const pts = (ring || []).filter((e) => e[0] >= from);
    const vals = [];
    for (const [, r, i] of pts) { if (r != null && r >= 0) vals.push(r); if (i != null) vals.push(i); }
    vals.sort((a, b) => a - b);
    const top = Math.max(20, Math.ceil(((vals[Math.floor(vals.length * 0.98)] || 0) * 1.25) / 10) * 10);
    const padL = axis ? 30 : 2, padR = 4, padT = 6, padB = axis ? 14 : 4;
    const x = (t) => padL + ((t - from) / span) * (w - padL - padR);
    const y = (v) => padT + (1 - Math.min(v, top) / top) * (h - padT - padB);
    // a lost ping, or a gap of more than 15 s (NetDeck not watching), breaks the line
    const line = (k) => {
      let d = '', prevT = null;
      for (const e of pts) {
        const v = e[k];
        if (v == null || v < 0) { prevT = null; continue; }
        d += `${prevT !== null && e[0] - prevT <= 15000 ? 'L' : 'M'}${x(e[0]).toFixed(1)} ${y(v).toFixed(1)} `;
        prevT = e[0];
      }
      return d.trim();
    };
    const loss = pts.filter((e) => e[2] == null).map((e) => `<rect x="${(x(e[0]) - 1.5).toFixed(1)}" y="${padT}" width="3" height="${h - padT - padB}" class="sn-loss"/>`).join('');
    const grid = axis ? [0.5, 1].map((f) => `<line x1="${padL}" x2="${w - padR}" y1="${y(top * f).toFixed(1)}" y2="${y(top * f).toFixed(1)}" class="sn-grid"/><text x="${padL - 4}" y="${(y(top * f) + 3.5).toFixed(1)}" class="sn-ax" text-anchor="end">${Math.round(top * f)}</text>`).join('') + `<text x="${padL}" y="${h - 2}" class="sn-ax">-${Math.round(span / 60000)} min</text><text x="${w - padR}" y="${h - 2}" class="sn-ax" text-anchor="end">now</text>` : '';
    return `<svg class="sn-graph" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Router and internet ping, last ${Math.round(span / 60000)} minutes">${grid}${loss}<path d="${line(1)}" class="sn-line sn-router"/><path d="${line(2)}" class="sn-line sn-internet"/></svg>`;
  }

  /* Traffic graph from sampled rates: download and upload lines. */
  function trafficGraph(hist, { w = 600, h = 160, span = 5 * 60000, now = Date.now(), axis = true } = {}) {
    const from = now - span;
    const pts = (hist || []).filter((e) => e.t >= from);
    const top = Math.max(1e6, ...pts.map((e) => Math.max(e.down, e.up))) * 1.15;
    const padL = axis ? 34 : 2, padR = 4, padT = 6, padB = axis ? 14 : 4;
    const x = (t) => padL + ((t - from) / span) * (w - padL - padR);
    const y = (v) => padT + (1 - v / top) * (h - padT - padB);
    const line = (k) => pts.map((e, i) => `${i ? 'L' : 'M'}${x(e.t).toFixed(1)} ${y(e[k]).toFixed(1)}`).join(' ');
    const grid = axis ? [0.5, 1].map((f) => `<line x1="${padL}" x2="${w - padR}" y1="${y((top / 1.15) * f).toFixed(1)}" y2="${y((top / 1.15) * f).toFixed(1)}" class="sn-grid"/><text x="${padL - 4}" y="${(y((top / 1.15) * f) + 3.5).toFixed(1)}" class="sn-ax" text-anchor="end">${fmtRate((top / 1.15) * f)}</text>`).join('') + `<text x="${padL}" y="${h - 2}" class="sn-ax">-${Math.round(span / 60000)} min · Mbit/s</text><text x="${w - padR}" y="${h - 2}" class="sn-ax" text-anchor="end">now</text>` : '';
    return `<svg class="sn-graph" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Download and upload, last ${Math.round(span / 60000)} minutes">${grid}<path d="${line('down')}" class="sn-line sn-down"/><path d="${line('up')}" class="sn-line sn-up"/></svg>`;
  }

  /* A tiny sparkline for a table row: [t, v] pairs over the last few minutes. */
  function spark(pairs, { w = 120, h = 22, span = 5 * 60000, now = Date.now(), cls = 'sn-internet' } = {}) {
    const from = now - span;
    const pts = pairs.filter((p) => p[0] >= from && p[1] != null && p[1] >= 0);
    if (pts.length < 2) return '';
    const top = Math.max(1, ...pts.map((p) => p[1])) * 1.1;
    const d = pts.map((p, i) => `${i ? 'L' : 'M'}${(((p[0] - from) / span) * w).toFixed(1)} ${(h - 1 - (p[1] / top) * (h - 2)).toFixed(1)}`).join(' ');
    return `<svg class="sn-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><path d="${d}" class="sn-line ${cls}"/></svg>`;
  }

  /* Share of pings lost in the last minute of the history (k: 1 router, 2 internet). */
  function recentLoss(ring, k, now = Date.now()) {
    const e = (ring || []).filter((x) => now - x[0] <= 60000 && !(k === 1 && x[1] === -1));
    return e.length ? (100 * e.filter((x) => x[k] == null).length) / e.length : null;
  }

  return { esc, acc, accAdd, accAvg, trafficSampler, fmtMs, fmtRate, clock, latencyGraph, trafficGraph, spark, recentLoss };
})();
