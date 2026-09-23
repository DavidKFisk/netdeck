/* NetDeck scan log: remembers the devices each network scan found, so the next scan can say what is new,
   what has gone, and what changed address — and when each device was first seen. Also keeps the names that
   discovery (mDNS/SSDP) learned, so the scan table can show them. Everything lives in this browser's
   localStorage; nothing leaves the machine. */
window.NetDeckScanLog = (() => {
  const KEY = 'netdeck.scanlog.v1';
  const MAX_SCANS = 30;
  const NAME_TTL = 7 * 24 * 3600 * 1000;

  function load() {
    try { const j = JSON.parse(localStorage.getItem(KEY) || 'null'); if (j && typeof j === 'object') return { firstSeen: j.firstSeen || {}, scans: j.scans || [], names: j.names || {} }; } catch (e) { /* storage blocked or corrupt */ }
    return { firstSeen: {}, scans: [], names: {} };
  }
  function save(db) { try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) { /* quota or blocked: the log is a convenience */ } }

  const key = (d) => (d.mac ? d.mac.toUpperCase().replace(/[^0-9A-F]/g, '') : '') || ('ip:' + d.ip);
  const fmtDate = (ts) => new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const ago = (ts) => { const m = Math.round((Date.now() - ts) / 60000); if (m < 2) return 'a moment ago'; if (m < 60) return `${m} min ago`; const h = Math.round(m / 60); if (h < 36) return `${h} h ago`; return `${Math.round(h / 24)} days ago`; };

  let lastDiff = null;

  /* When was this device first seen? '' if never — i.e. it is new right now. */
  function firstSeen(device) { const db = load(); const ts = db.firstSeen[key(device)]; return ts ? fmtDate(ts) : ''; }

  /* Record a finished scan; returns the difference from the previous scan of the same range (null on the first one).
     Called from the parser, which may run more than once for the same output — a scan identical to the last
     one within a minute is not recorded twice. */
  function record(range, devices) {
    const db = load();
    const now = Date.now();
    const keys = devices.map(key);
    const prev = db.scans.filter((s) => s.range === range).slice(-1)[0] || null;
    if (prev && now - prev.ts < 60000 && prev.devices.length === devices.length && prev.devices.every((d, i) => key(d) === keys[i] && d.ip === devices[i].ip)) { return lastDiff; }
    // first-seen stamps as they were before this scan, so a device new right now reads as new however often the table is rebuilt
    const first = {}; keys.forEach((k) => { first[k] = db.firstSeen[k] || 0; });
    let diff = null;
    if (prev) {
      const prevBy = new Map(prev.devices.map((d) => [key(d), d]));
      const nowBy = new Map(devices.map((d) => [key(d), d]));
      // "new" means never seen in any scan; a device that only missed the previous scan is "back"
      const added = devices.filter((d) => !prevBy.has(key(d)) && !db.firstSeen[key(d)]);
      const returned = devices.filter((d) => !prevBy.has(key(d)) && db.firstSeen[key(d)]);
      const gone = prev.devices.filter((d) => !nowBy.has(key(d)));
      const moved = devices.filter((d) => prevBy.has(key(d)) && prevBy.get(key(d)).ip !== d.ip).map((d) => ({ ...d, from: prevBy.get(key(d)).ip }));
      diff = { added, returned, gone, moved, prevTs: prev.ts, prevAgo: ago(prev.ts), prevCount: prev.devices.length, firstEver: false, first };
    } else {
      diff = { added: [], returned: [], gone: [], moved: [], prevTs: 0, prevAgo: '', prevCount: 0, firstEver: true, first };
    }
    keys.forEach((k) => { if (!db.firstSeen[k]) db.firstSeen[k] = now; });
    db.scans.push({ ts: now, range, devices: devices.map((d) => ({ ip: d.ip, mac: d.mac || '', name: d.name || '', maker: d.maker || '' })) });
    if (db.scans.length > MAX_SCANS) db.scans.splice(0, db.scans.length - MAX_SCANS);
    save(db);
    lastDiff = diff;
    return diff;
  }

  /* Names learned by discovery, by IP, kept for a week. */
  function rememberNames(map) { const db = load(); const now = Date.now(); for (const [ip, name] of Object.entries(map || {})) if (ip && name) db.names[ip] = { name: String(name).slice(0, 80), ts: now }; save(db); }
  function nameFor(ip) { const db = load(); const n = db.names[ip]; return n && Date.now() - n.ts < NAME_TTL ? n.name : ''; }

  function history() { return load().scans.map((s) => ({ ts: s.ts, range: s.range, count: s.devices.length })); }
  /* The most recent scan (for the dashboard): its devices, the previous scan of the same range, and the first-seen
     stamps — a device whose stamp equals the scan's own time was new in that scan. */
  function latest() {
    const db = load();
    const s = db.scans[db.scans.length - 1];
    if (!s) return null;
    const prev = db.scans.slice(0, -1).filter((x) => x.range === s.range).slice(-1)[0] || null;
    return { ts: s.ts, range: s.range, devices: s.devices, prev, firstSeen: db.firstSeen };
  }
  function clear() { try { localStorage.removeItem(KEY); } catch (e) { /* ignore */ } lastDiff = null; }

  return { firstSeen, record, rememberNames, nameFor, history, latest, clear, keyOf: key, get lastDiff() { return lastDiff; } };
})();
