/* NetDeck output parsers: turn raw command text into {columns, rows} for the table view.
   Registry is keyed by command id, with per-platform variants for Linux/macOS output formats. */
window.NetDeckParsers = (() => {
  const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

  function lines(text) {
    return text.replace(/\[exited with code [^\]]*\]\s*$/, '').split(/\r?\n/);
  }

  /* Generic fixed-width table: a header line followed by a ---- ==== ruler line
     (tasklist, getmac, every PowerShell Format-Table). Column spans come from the ruler. */
  function fixedWidth(text) {
    const ls = lines(text);
    for (let i = 1; i < ls.length; i++) {
      if (!/^\s*[-=]+(?:\s+[-=]+)*\s*$/.test(ls[i]) || !ls[i - 1].trim()) continue;
      const header = ls[i - 1];
      const ruler = ls[i];
      const data = [];
      for (let j = i + 1; j < ls.length; j++) {
        if (!ls[j].trim()) {
          if (data.length) break;
          continue;
        }
        data.push(ls[j]);
      }
      // PowerShell's ruler is only as wide as each header word, and values are often wider (and numbers are
      // right-aligned), so widths cannot be read off the ruler. A column boundary is a position that is blank
      // in the header, the ruler and every data row; each run between boundaries that holds a ruler group is a column.
      const all = [header, ruler, ...data];
      const width = Math.max(...all.map((l) => l.length));
      const isGap = (pos) => all.every((l) => pos >= l.length || l[pos] === ' ');
      const spans = [];
      let start = -1;
      for (let pos = 0; pos <= width; pos++) {
        const gap = pos === width || isGap(pos);
        if (!gap && start === -1) start = pos;
        if (gap && start !== -1) { spans.push({ start, end: pos }); start = -1; }
      }
      // A run with no ruler beneath it is not a column of its own (a value that happens to be split): fold it into its neighbor.
      const columnsSpans = [];
      for (const s of spans) {
        const hasRuler = /[-=]/.test(ruler.slice(s.start, s.end));
        if (hasRuler || !columnsSpans.length) columnsSpans.push({ ...s, hasRuler });
        else columnsSpans[columnsSpans.length - 1].end = s.end;
      }
      if (columnsSpans.length && !columnsSpans[0].hasRuler && columnsSpans.length > 1) {
        columnsSpans[1].start = columnsSpans[0].start;
        columnsSpans.shift();
      }
      if (!columnsSpans.length) continue;
      const cut = (line, s, isLast) => line.slice(s.start, isLast ? undefined : s.end).trim();
      const lastIdx = columnsSpans.length - 1;
      const columns = columnsSpans.map((s, k) => cut(header, s, k === lastIdx));
      const rows = data.map((line) => columnsSpans.map((s, k) => cut(line, s, k === lastIdx))).filter((row) => row.some(Boolean));
      return { columns, rows };
    }
    return null;
  }

  /* Whitespace-separated table with a known header: split each row into `n` fields, last field absorbs the rest. */
  function splitTable(text, headerTest, columns, minFields) {
    const ls = lines(text);
    const start = ls.findIndex(headerTest);
    if (start === -1) return null;
    const rows = [];
    for (const line of ls.slice(start + 1)) {
      if (!line.trim()) continue;
      const parts = line.trim().split(/\s+/);
      if (parts.length < minFields) continue;
      const head = parts.slice(0, columns.length - 1);
      rows.push([...head, parts.slice(columns.length - 1).join(' ')]);
    }
    return rows.length ? { columns, rows } : null;
  }

  function portOf(addr) {
    const idx = addr.lastIndexOf(':');
    return idx === -1 ? '' : addr.slice(idx + 1);
  }

  /* ---------- Windows ---------- */
  function netstat(text) {
    const rows = [];
    for (const line of lines(text)) {
      const t = line.trim().split(/\s+/);
      if (t[0] === 'TCP' && t.length >= 5) rows.push([t[0], t[1], portOf(t[1]), t[2], t[3], t[4]]);
      else if (t[0] === 'UDP' && t.length >= 4) rows.push([t[0], t[1], portOf(t[1]), t[2], '', t[3]]);
    }
    return rows.length ? { columns: ['Proto', 'Local address', 'Port', 'Foreign address', 'State', 'PID'], rows } : null;
  }

  function arp(text) {
    const rows = [];
    let iface = '';
    for (const line of lines(text)) {
      const im = line.match(/^Interface:\s+(\S+)/);
      if (im) { iface = im[1]; continue; }
      const m = line.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\w+)/i);
      if (m) rows.push([iface, m[1], m[2], m[3]]);
    }
    return rows.length ? { columns: ['Interface', 'IP address', 'MAC address', 'Type'], rows } : null;
  }

  function route(text) {
    const rows = [];
    let inV4 = false;
    for (const line of lines(text)) {
      if (/IPv4 Route Table/.test(line)) inV4 = true;
      if (/IPv6 Route Table/.test(line)) inV4 = false;
      if (!inV4) continue;
      const t = line.trim().split(/\s+/);
      if (t.length === 5 && IPV4.test(t[0]) && IPV4.test(t[1])) rows.push(t);
    }
    return rows.length ? { columns: ['Destination', 'Netmask', 'Gateway', 'Interface', 'Metric'], rows } : null;
  }

  function ipconfig(text) {
    const rows = [];
    let adapter = 'Host';
    let key = '';
    for (const line of lines(text)) {
      if (!line.trim()) continue;
      if (!/^\s/.test(line)) { adapter = line.trim().replace(/:$/, ''); continue; }
      const m = line.match(/^\s+(.+?)\.(?:\s\.)*\s*:\s?(.*)$/);
      if (m) {
        key = m[1].trim();
        rows.push([adapter, key, m[2].trim()]);
      } else if (key) {
        rows.push([adapter, key, line.trim()]);
      }
    }
    return rows.length ? { columns: ['Adapter', 'Setting', 'Value'], rows } : null;
  }

  function displaydns(text) {
    const rows = [];
    const META = new Set(['Record Name', 'Record Type', 'Time To Live', 'Data Length', 'Section']);
    for (const block of text.split(/\r?\n\s*\r?\n/)) {
      const kv = {};
      let dataKey = '', data = '';
      for (const line of block.split(/\r?\n/)) {
        const m = line.match(/^\s+(.+?)(?:\s\.)*\s*:\s?(.*)$/);
        if (!m) continue;
        const k = m[1].replace(/[\s.]+$/, '');
        if (META.has(k)) kv[k] = m[2].trim();
        else { dataKey = k; data = m[2].trim(); }
      }
      if (kv['Record Name'] && dataKey) rows.push([kv['Record Name'], dataKey, data, kv['Time To Live'] || '', kv['Section'] || '']);
    }
    return rows.length ? { columns: ['Name', 'Record', 'Data', 'TTL (s)', 'Section'], rows } : null;
  }

  /* ---------- Linux / macOS ---------- */
  function ss(text) {
    // Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    const rows = [];
    for (const line of lines(text)) {
      const t = line.trim().split(/\s+/);
      if (t.length < 6 || !/^(tcp|udp|tcp6|udp6)$/i.test(t[0])) continue;
      const proc = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
      rows.push([t[0].toUpperCase(), t[1], t[4], portOf(t[4]), t[5], proc ? proc[2] : '', proc ? proc[1] : '']);
    }
    return rows.length ? { columns: ['Proto', 'State', 'Local address', 'Port', 'Peer address', 'PID', 'Process'], rows } : null;
  }

  function lsof(text) {
    // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
    const t = splitTable(text, (l) => /^COMMAND\s+PID/.test(l), ['Process', 'PID', 'User', 'FD', 'Type', 'Device', 'Size', 'Proto', 'Name'], 9);
    if (!t) return null;
    const rows = t.rows.map((r) => {
      const state = r[8].match(/\((\w+)\)\s*$/);
      return [r[0], r[1], r[2], r[7], r[8].replace(/\s*\(\w+\)\s*$/, ''), state ? state[1] : ''];
    });
    return { columns: ['Process', 'PID', 'User', 'Proto', 'Name', 'State'], rows };
  }

  function ipaddr(text) {
    // "2: wlan0: <BROADCAST,...>" then indented "inet 192.168.1.5/24 ..." / "link/ether aa:bb:.." lines
    const rows = [];
    let iface = '';
    for (const line of lines(text)) {
      const head = line.match(/^\d+:\s+([^:]+):\s+<([^>]*)>/);
      if (head) { iface = head[1]; rows.push([iface, 'flags', head[2]]); continue; }
      const mac = line.match(/^\s+link\/\w+\s+([0-9a-f:]{17})/i);
      if (mac) { rows.push([iface, 'MAC address', mac[1]]); continue; }
      const inet = line.match(/^\s+(inet6?)\s+(\S+)/);
      if (inet) rows.push([iface, inet[1] === 'inet' ? 'IPv4 address' : 'IPv6 address', inet[2]]);
    }
    return rows.length ? { columns: ['Interface', 'Setting', 'Value'], rows } : null;
  }

  function ifconfig(text) {
    // "en0: flags=8863<UP,...> mtu 1500" then indented "inet 192.168.1.5 netmask ..." / "ether aa:bb:..."
    const rows = [];
    let iface = '';
    for (const line of lines(text)) {
      const head = line.match(/^([A-Za-z0-9.]+):\s+flags=\d+<([^>]*)>/);
      if (head) { iface = head[1]; rows.push([iface, 'flags', head[2]]); continue; }
      const mac = line.match(/^\s+ether\s+([0-9a-f:]{17})/i);
      if (mac) { rows.push([iface, 'MAC address', mac[1]]); continue; }
      const inet = line.match(/^\s+(inet6?)\s+(\S+)/);
      if (inet) rows.push([iface, inet[1] === 'inet' ? 'IPv4 address' : 'IPv6 address', inet[2]]);
    }
    return rows.length ? { columns: ['Interface', 'Setting', 'Value'], rows } : null;
  }

  function arpUnix(text) {
    // "? (192.168.1.1) at f8:bb:bf:53:eb:32 on en0 ifscope [ethernet]"  |  "router (192.168.1.1) at f8:.. [ether] on wlan0"
    const rows = [];
    for (const line of lines(text)) {
      const m = line.match(/^(\S+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(\S+)(?:.*?\bon\s+(\S+))?/);
      if (!m) continue;
      const mac = /^[0-9a-f:]+$/i.test(m[3]) ? m[3] : '';
      rows.push([m[4] || '', m[2], mac, m[1] === '?' ? '' : m[1], mac ? 'dynamic' : 'incomplete']);
    }
    return rows.length ? { columns: ['Interface', 'IP address', 'MAC address', 'Name', 'Type'], rows } : null;
  }

  function iproute(text) {
    // "default via 192.168.1.1 dev wlan0 proto dhcp metric 600" / "192.168.1.0/24 dev wlan0 proto kernel scope link src ..."
    const rows = [];
    for (const line of lines(text)) {
      const t = line.trim().split(/\s+/);
      if (!t[0] || !/^(default|\d)/.test(t[0])) continue;
      const pick = (k) => { const i = t.indexOf(k); return i !== -1 ? t[i + 1] : ''; };
      rows.push([t[0], pick('via') || 'on-link', pick('dev'), pick('src'), pick('metric')]);
    }
    return rows.length ? { columns: ['Destination', 'Gateway', 'Interface', 'Source', 'Metric'], rows } : null;
  }

  function netstatRn(text) {
    // macOS: "Destination        Gateway            Flags       Netif Expire"
    return splitTable(text, (l) => /^Destination\s+Gateway/.test(l), ['Destination', 'Gateway', 'Flags', 'Interface'], 4);
  }

  function psaux(text) {
    return splitTable(text, (l) => /^USER\s+PID/.test(l), ['User', 'PID', '%CPU', '%MEM', 'VSZ', 'RSS', 'TTY', 'Stat', 'Started', 'Time', 'Command'], 11);
  }

  function dig(text) {
    // ";; ANSWER SECTION:" then "example.com.  300  IN  A  93.184.215.14"
    const rows = [];
    for (const line of lines(text)) {
      if (line.startsWith(';') || !line.trim()) continue;
      const t = line.trim().split(/\s+/);
      if (t.length >= 5 && /^\d+$/.test(t[1]) && t[2] === 'IN') rows.push([t[0], t[1], t[3], t.slice(4).join(' ')]);
    }
    return rows.length ? { columns: ['Name', 'TTL (s)', 'Type', 'Data'], rows } : null;
  }

  /* ---------- tracert / traceroute (both platforms) ---------- */
  function classifyIp(ip) {
    if (!IPV4.test(ip)) return 'public';
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a === 169 && b === 254) return 'apipa';
    if (a === 127) return 'loopback';
    return 'public';
  }

  const NETWORK_LABEL = { private: 'your network', cgnat: 'provider access (CGNAT)', public: 'internet', apipa: 'self-assigned', loopback: 'this machine' };

  function tracert(text) {
    // Windows: "  3    12 ms    11 ms    12 ms  68.85.107.33"   Unix: " 3  68.85.107.33  12.1 ms  11.8 ms  12.0 ms"
    const rows = [];
    for (const line of lines(text)) {
      const m = line.match(/^\s*(\d+)\s+(.*)$/);
      if (!m) continue;
      const rest = m[2];
      const addr = (rest.match(/\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+/i) || [])[0] || '';
      const times = [...rest.matchAll(/(<?[\d.]+)\s*ms/g)].map((t) => t[1]);
      if (!addr && !times.length && !rest.includes('*')) continue;
      rows.push([m[1], times[0] || '*', times[1] || '*', times[2] || '*', addr || '(no reply)', addr ? NETWORK_LABEL[classifyIp(addr)] : '']);
    }
    return rows.length ? { columns: ['Hop', 'RTT 1 (ms)', 'RTT 2 (ms)', 'RTT 3 (ms)', 'Address', 'Network'], rows } : null;
  }

  /* Local network scan: the script's own table, plus who made each device (from its MAC prefix). */
  function lanScan(text) {
    const t = fixedWidth(text);
    if (!t) return null;
    const macCol = t.columns.indexOf('MAC');
    if (macCol === -1 || !window.NetDeckOui) return t;
    const ipCol = t.columns.indexOf('IP'), nameCol = t.columns.indexOf('Name');
    const log = window.NetDeckScanLog;
    // names learned by discovery (mDNS/UPnP) fill blanks in the Name column
    const base = t.rows.map((r) => { const row = [...r]; if (log && nameCol !== -1 && ipCol !== -1 && !row[nameCol]) row[nameCol] = log.nameFor(row[ipCol]); return row; });
    const columns = [...t.columns.slice(0, macCol + 1), 'Manufacturer', ...t.columns.slice(macCol + 1)];
    let rows = base.map((r) => [...r.slice(0, macCol + 1), window.NetDeckOui.lookup(r[macCol]), ...r.slice(macCol + 1)]);
    // the scan log: when was each device first seen, and what changed since the last scan of this range
    if (log && ipCol !== -1) {
      const range = (text.match(/Scanned (\S+) on /) || [])[1] || '';
      const devices = base.map((r) => ({ ip: r[ipCol], mac: r[macCol], name: nameCol !== -1 ? r[nameCol] : '', maker: window.NetDeckOui.lookup(r[macCol]) }));
      const diff = log.record(range, devices);
      const seen = (d) => { if (!diff) return ''; if (diff.firstEver) return 'first scan'; const ts = diff.first[log.keyOf(d)]; return ts ? 'since ' + new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : 'NEW'; };
      const mi = columns.indexOf('Manufacturer');
      columns.splice(mi + 1, 0, 'Seen');
      rows = rows.map((r, i) => [...r.slice(0, mi + 1), seen(devices[i]), ...r.slice(mi + 1)]);
    }
    const out = { columns, rows };
    if (ipCol !== -1) out.rowAction = { label: 'probe', title: 'Test this device\'s common ports', cmd: 'device-probe', params: { host: 'IP' } };
    return out;
  }

  /* tasklist /fo csv /nh (Windows) or ps -eo pid,comm (Unix) → Map<pid, name> */
  function processMap(text) {
    const map = new Map();
    for (const line of lines(text)) {
      const csv = line.match(/^"([^"]*)","(\d+)"/);
      if (csv) { map.set(csv[2], csv[1]); continue; }
      const psl = line.match(/^\s*(\d+)\s+(\S.*?)\s*$/);
      if (psl) map.set(psl[1], psl[2].split('/').pop());
    }
    return map;
  }

  const WIN = {
    'netstat-ano': netstat,
    'arp-a': arp,
    'route-print': route,
    'ipconfig-all': ipconfig,
    'ipconfig-displaydns': displaydns,
    tasklist: fixedWidth,
    getmac: fixedWidth,
    'get-nettcpconnection': fixedWidth,
    'resolve-dnsname': fixedWidth,
    'disk-free': fixedWidth,
    'get-hotfix': fixedWidth,
    'lan-scan': lanScan,
    'discover': fixedWidth,
    'device-probe': fixedWidth,
    'capture-view': fixedWidth,
    'wifi-survey': fixedWidth,
    tracert,
  };
  const LINUX = {
    tracert,
    'netstat-ano': ss,
    'get-nettcpconnection': lsof,
    'arp-a': arpUnix,
    'route-print': iproute,
    'ipconfig-all': ipaddr,
    tasklist: psaux,
    'resolve-dnsname': dig,
  };
  const DARWIN = {
    tracert,
    'netstat-ano': lsof,
    'get-nettcpconnection': lsof,
    'arp-a': arpUnix,
    'route-print': netstatRn,
    'ipconfig-all': ifconfig,
    tasklist: psaux,
    'resolve-dnsname': dig,
  };
  const REGISTRY = { win32: WIN, linux: LINUX, darwin: DARWIN };

  // Columns whose values are process IDs — the table view joins these to process names.
  const PID_COLUMNS = new Set(['PID', 'OwningProcess']);

  const table = (platform) => REGISTRY[platform] || WIN;

  return {
    hasParser: (id, platform = 'win32') => Boolean(table(platform)[id]),
    parse: (id, text, platform = 'win32') => (table(platform)[id] ? table(platform)[id](text) : null),
    processMap,
    pidColumn: (columns) => (columns.includes('Process') ? -1 : columns.findIndex((c) => PID_COLUMNS.has(c))),
    ipconfig,
    fixedWidth,
    classifyIp,
  };
})();
