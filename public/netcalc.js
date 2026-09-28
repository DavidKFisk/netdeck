/* NetDeck network calculator: a popup with nine tools — IPv4 subnetting, splitting and summarizing, IPv6, MAC
   addresses, bandwidth and transfer time, throughput and latency, Wi-Fi planning, security helpers (certificate
   expiry, password strength, hashes) and infrastructure planning (rack and power, API rate limits, WAN
   optimization). Everything is calculated here in the page; nothing is sent anywhere. A few tools can fill their
   inputs from this PC (your address and mask, nearby Wi-Fi networks, a site's certificate) when NetDeck can run
   commands. Each tool is { key, label, manual, modes: [{ key, label, hint, fields, actions, compute }] }; compute()
   returns blocks — { type: 'kv', rows: [{ k, v, note, tone, html }] }, { type: 'table', columns, rows },
   { type: 'msg', tone, text } — that the one renderer draws, copies and saves. */
window.NetDeckCalc = (() => {
  const KEY = 'netdeck.calc.v1';
  let D = null, els = null, seq = 0, last = null, saveTimer = null;
  const files = {};   // file inputs (never persisted)
  let state = load();

  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  function load() {
    try { const j = JSON.parse(localStorage.getItem(KEY) || 'null'); if (j && typeof j === 'object') return { tool: j.tool || 'ipv4', modes: j.modes || {}, vals: j.vals || {}, explain: !!j.explain }; } catch (e) { /* blocked */ }
    return { tool: 'ipv4', modes: {}, vals: {}, explain: false };
  }
  function save() { clearTimeout(saveTimer); saveTimer = setTimeout(() => { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* a convenience */ } }, 300); }
  class Bad extends Error {}
  const bad = (msg) => { throw new Bad(msg); };

  /* ================= formatting ================= */
  const fmtInt = (n) => Number(n).toLocaleString('en-US');
  const fmtBig = (b) => b.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const round = (x, d = 1) => { const f = 10 ** d; return Math.round(x * f) / f; };
  function fmtRate(bps) {
    if (!isFinite(bps)) return 'no limit';
    if (bps >= 1e9) return `${round(bps / 1e9, bps >= 1e10 ? 1 : 2)} Gbit/s`;
    if (bps >= 1e6) return `${round(bps / 1e6, bps >= 1e8 ? 0 : 1)} Mbit/s`;
    if (bps >= 1e3) return `${Math.round(bps / 1e3)} kbit/s`;
    return `${Math.round(bps)} bit/s`;
  }
  function fmtBytes(b) {
    const u = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0; while (b >= 1000 && i < u.length - 1) { b /= 1000; i++; }
    return `${round(b, b >= 100 || i === 0 ? 0 : b >= 10 ? 1 : 2)} ${u[i]}`;
  }
  const YEAR = 31557600;
  function fmtTime(s) {
    if (!isFinite(s)) return 'never';
    if (s < 0) return '—';
    if (s < 1e-3) return `${round(s * 1e6, 0)} µs`;
    if (s < 1) return `${round(s * 1000, s < 0.01 ? 2 : 1)} ms`;
    if (s < 60) return `${round(s, s < 10 ? 2 : 1)} s`;
    const y = s / YEAR;
    if (y >= 1.38e10) return 'longer than the age of the universe';
    if (y >= 1000) {
      for (const [v, w] of [[1e12, 'trillion'], [1e9, 'billion'], [1e6, 'million'], [1e3, 'thousand']]) if (y >= v) return `${round(y / v, 1)} ${w} years`;
    }
    const units = [[YEAR, 'year', 'years'], [86400, 'day', 'days'], [3600, 'h', 'h'], [60, 'min', 'min'], [1, 's', 's']];
    const parts = [];
    let rest = Math.round(s);
    for (const [len, one, many] of units) {
      if (rest >= len) { const n = Math.floor(rest / len); parts.push(`${n} ${n === 1 ? one : many}`); rest -= n * len; }
      if (parts.length === 2) break;
    }
    return parts.join(' ');
  }
  const num = (v, name, { min = -Infinity, max = Infinity, int = false, allowEmpty = false } = {}) => {
    const s = String(v ?? '').trim();
    if (s === '' && allowEmpty) return null;
    const n = Number(s.replace(/,/g, ''));
    if (s === '' || !isFinite(n)) bad(`${name}: enter a number.`);
    if (int && !Number.isInteger(n)) bad(`${name}: enter a whole number.`);
    if (n < min || n > max) bad(`${name}: enter a value from ${fmtInt(min)} to ${fmtInt(max)}.`);
    return n;
  };

  /* ================= IPv4 ================= */
  const ip4 = {
    parse(s) {
      const m = String(s ?? '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      if (!m) return null;
      const o = m.slice(1).map(Number);
      if (o.some((x) => x > 255)) return null;
      return o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3];
    },
    str(n) { n >>>= 0; return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); },
    mask(p) { return p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0; },
    prefixOf(m) { m >>>= 0; let p = 0; while (p < 32 && (m & (0x80000000 >>> p)) !== 0) p++; return ip4.mask(p) === m ? p : null; },
    hex(n) { n >>>= 0; return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].map((x) => x.toString(16).toUpperCase().padStart(2, '0')).join('.'); },
    bin(n) { return (n >>> 0).toString(2).padStart(32, '0'); },
    usable(p) { return p === 32 ? 1 : p === 31 ? 2 : 2 ** (32 - p) - 2; },
  };
  function parseMask(s) {
    s = String(s ?? '').trim().replace(/^\//, '');
    if (!s) return null;
    if (/^\d{1,2}$/.test(s)) { const p = Number(s); return p <= 32 ? { prefix: p, kind: 'prefix' } : null; }
    let n = ip4.parse(s);
    if (n === null) {
      const h = s.replace(/^0x/i, '');
      if (/^[0-9a-f]{8}$/i.test(h)) n = parseInt(h, 16) >>> 0;
      else if (/^[0-9a-f]{1,2}(\.[0-9a-f]{1,2}){3}$/i.test(s)) n = s.split('.').reduce((a, x) => a * 256 + parseInt(x, 16), 0) >>> 0;
    }
    if (n === null) return null;
    let p = ip4.prefixOf(n);
    if (p !== null) return { prefix: p, kind: 'mask' };
    p = ip4.prefixOf(~n >>> 0);
    if (p !== null) return { prefix: p, kind: 'wildcard' };
    return { invalid: true };
  }
  const MASK_HELP = 'Enter a prefix (/26), a dotted mask (255.255.255.192), a wildcard mask (0.0.0.63) or hex (ff.ff.ff.c0).';
  function needMask(s) {
    const m = parseMask(s);
    if (!m) bad(`"${s}" is not a subnet mask. ${MASK_HELP}`);
    if (m.invalid) bad(`"${s}" is not a valid mask: a mask is a run of ones followed by zeros in binary (255.255.255.192 is valid, 255.255.0.255 is not).`);
    return m;
  }
  /* "a.b.c.d/p", "a.b.c.d p", "a.b.c.d 255.255.255.0" or a bare address (prefix defaults to fallback) */
  function parseCidr(s, fallback = null) {
    const t = String(s ?? '').trim();
    const m = t.match(/^(\S+?)\s*(?:\/\s*|\s+)(\S+)$/);
    const ipText = m ? m[1] : t;
    const ip = ip4.parse(ipText);
    if (ip === null) bad(`"${ipText}" is not an IPv4 address — four numbers from 0 to 255 separated by dots, such as 192.168.1.10.`);
    let prefix = fallback;
    if (m) prefix = needMask(m[2]).prefix;
    if (prefix === null) bad(`"${t}" needs a prefix length, such as ${ipText}/24.`);
    const net = (ip & ip4.mask(prefix)) >>> 0;
    return { ip, prefix, net, bc: (net | (~ip4.mask(prefix) >>> 0)) >>> 0, size: 2 ** (32 - prefix), normalized: net !== ip };
  }
  function fitPrefix(hosts) {
    if (hosts <= 1) return 32;
    for (let p = 30; p >= 0; p--) if (ip4.usable(p) >= hosts) return p;
    return null;
  }
  function classOf(ip) {
    const a = ip >>> 24;
    if (a < 128) return { cls: 'A', bits: 8, lead: '0', range: '1–126', note: '0 and 127 are set aside (127 is loopback)' };
    if (a < 192) return { cls: 'B', bits: 16, lead: '10', range: '128–191' };
    if (a < 224) return { cls: 'C', bits: 24, lead: '110', range: '192–223' };
    if (a < 240) return { cls: 'D', bits: null, lead: '1110', range: '224–239', note: 'Multicast' };
    return { cls: 'E', bits: null, lead: '1111', range: '240–255', note: 'Reserved' };
  }
  const V4_SPECIAL = [
    ['255.255.255.255/32', 'Limited broadcast — every device on this link', 'RFC 919'],
    ['0.0.0.0/8', '"This network" — 0.0.0.0 alone means "any address" or "no address yet"', 'RFC 1122'],
    ['10.0.0.0/8', 'Private — used inside homes and offices, never routed on the internet', 'RFC 1918'],
    ['100.64.0.0/10', 'Carrier-grade NAT shared space — an ISP-side private range', 'RFC 6598'],
    ['127.0.0.0/8', 'Loopback — this computer itself', 'RFC 1122'],
    ['169.254.0.0/16', 'Link-local (APIPA) — self-assigned when no DHCP server answered', 'RFC 3927'],
    ['172.16.0.0/12', 'Private — used inside homes and offices, never routed on the internet', 'RFC 1918'],
    ['192.0.0.0/24', 'IETF protocol assignments', 'RFC 6890'],
    ['192.0.2.0/24', 'Documentation (TEST-NET-1) — for examples only, never routed', 'RFC 5737'],
    ['192.88.99.0/24', 'Former 6to4 relay anycast (deprecated)', 'RFC 7526'],
    ['192.168.0.0/16', 'Private — used inside homes and offices, never routed on the internet', 'RFC 1918'],
    ['198.18.0.0/15', 'Benchmarking — for testing network equipment', 'RFC 2544'],
    ['198.51.100.0/24', 'Documentation (TEST-NET-2) — for examples only, never routed', 'RFC 5737'],
    ['203.0.113.0/24', 'Documentation (TEST-NET-3) — for examples only, never routed', 'RFC 5737'],
    ['224.0.0.0/4', 'Multicast — one sender, many receivers (class D)', 'RFC 5771'],
    ['240.0.0.0/4', 'Reserved for future use (class E)', 'RFC 1112'],
  ].map(([c, label, rfc]) => { const [a, p] = c.split('/'); return { net: ip4.parse(a), prefix: Number(p), label, rfc, cidr: c }; }).sort((a, b) => b.prefix - a.prefix);
  function v4Type(ip) {
    const hit = V4_SPECIAL.find((s) => ((ip & ip4.mask(s.prefix)) >>> 0) === s.net);
    return hit ? { label: hit.label, rfc: hit.rfc, special: true, private: /Private/.test(hit.label) } : { label: 'Public — a globally routable internet address', rfc: '', special: false };
  }
  function bitsHtml(ip, prefix, classBits) {
    const b = ip4.bin(ip);
    const cut = classBits === null ? prefix : Math.min(prefix, classBits);
    let html = '';
    for (let i = 0; i < 32; i++) {
      if (i && i % 8 === 0) html += '<span class="b-dot">.</span>';
      const cls = i < cut ? 'b-net' : i < prefix ? 'b-sub' : 'b-host';
      html += `<span class="${cls}">${b[i]}</span>`;
    }
    return html;
  }
  function bitmap(prefix, cls) {
    let s = '';
    for (let i = 0; i < 32; i++) {
      if (i && i % 8 === 0) s += '.';
      if (cls.bits !== null && i < cls.lead.length) s += cls.lead[i];
      else if (i < (cls.bits === null ? prefix : Math.min(prefix, cls.bits))) s += 'n';
      else if (i < prefix) s += 's';
      else s += 'h';
    }
    return s;
  }
  function subnetRow(i, net, p) {
    const bc = net + 2 ** (32 - p) - 1;
    const first = p >= 31 ? net : net + 1, lastH = p >= 31 ? bc : bc - 1;
    return [String(i), `${ip4.str(net)}/${p}`, ip4.str(first), ip4.str(lastH), p >= 31 ? '—' : ip4.str(bc), fmtInt(ip4.usable(p))];
  }
  function rangeToCidrs(a, b) {
    const out = [];
    while (a <= b) {
      let bits = 0;
      while (bits < 32 && Math.floor(a / 2 ** bits) % 2 === 0) bits++;
      while (bits > 0 && a + 2 ** bits - 1 > b) bits--;
      out.push([a, 32 - bits]);
      a += 2 ** bits;
      if (a > 0xFFFFFFFF) break;
    }
    return out;
  }
  const prefixList = () => { const l = []; for (let p = 8; p <= 32; p++) l.push([`/${p}`, `${ip4.str(ip4.mask(p))} — ${fmtInt(ip4.usable(p))} host${p === 32 ? '' : 's'}`]); return l; };

  /* ================= IPv6 ================= */
  const ALL6 = (1n << 128n) - 1n;
  function parse6(s) {
    s = String(s ?? '').trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
    if (!s || !s.includes(':')) return null;
    const m4 = s.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (m4) { const n = ip4.parse(m4[2]); if (n === null) return null; s = `${m4[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`; }
    const halves = s.split('::');
    if (halves.length > 2) return null;
    const part = (x) => (x === '' ? [] : x.split(':'));
    const L = part(halves[0]), R = halves.length === 2 ? part(halves[1]) : [];
    if ([...L, ...R].some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
    let groups;
    if (halves.length === 2) { const fill = 8 - L.length - R.length; if (fill < 1) return null; groups = [...L, ...Array(fill).fill('0'), ...R]; }
    else { if (L.length !== 8) return null; groups = L; }
    return groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n);
  }
  const groups6 = (n) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(112 - i * 16)) & 0xffffn));
  function fmt6(n) {
    const g = groups6(n);
    let bs = -1, bl = 0;
    for (let i = 0; i < 8;) {
      if (g[i] === 0) { let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bl && j - i >= 2) { bs = i; bl = j - i; } i = j; } else i++;
    }
    const h = g.map((x) => x.toString(16));
    if (bs < 0) return h.join(':');
    return `${h.slice(0, bs).join(':')}::${h.slice(bs + bl).join(':')}`;
  }
  const expand6 = (n) => groups6(n).map((x) => x.toString(16).padStart(4, '0')).join(':');
  const mask6 = (p) => (p === 0 ? 0n : ALL6 ^ ((1n << BigInt(128 - p)) - 1n));
  const V6_TYPES = [
    ['::/128', 'Unspecified — "no address yet"'],
    ['::1/128', 'Loopback — this computer itself'],
    ['::ffff:0:0/96', 'IPv4-mapped — an IPv4 address written in IPv6 form'],
    ['64:ff9b::/96', 'NAT64 well-known prefix — IPv6-only clients reaching IPv4 servers'],
    ['2001::/32', 'Teredo tunnel (IPv6 over IPv4 UDP)'],
    ['2001:db8::/32', 'Documentation — for examples only, never routed'],
    ['2002::/16', '6to4 tunnel (deprecated)'],
    ['fc00::/7', 'Unique local address (ULA) — private, the IPv6 cousin of 192.168.x.x'],
    ['fe80::/10', 'Link-local — every IPv6 interface has one; valid only on its own link'],
    ['ff00::/8', 'Multicast — one sender, many receivers (IPv6 has no broadcast)'],
    ['2000::/3', 'Global unicast — a public internet address'],
  ].map(([c, label]) => { const [a, p] = c.split('/'); return { net: parse6(a), prefix: Number(p), label }; }).sort((a, b) => b.prefix - a.prefix);
  // IPv4-mapped and NAT64 addresses end in an IPv4 address, which RFC 5952 (section 5) writes in dotted form
  const mixed6 = (n) => ((n >> 32n) === 0xffffn || (n & mask6(96)) === parse6('64:ff9b::')) ? fmt6(n).replace(/[0-9a-f]+:[0-9a-f]+$/, ip4.str(Number(n & 0xffffffffn))) : fmt6(n);
  const v6Type = (n) => (V6_TYPES.find((t) => (n & mask6(t.prefix)) === t.net) || { label: 'Reserved / unassigned', prefix: -1 });
  const MC_SCOPE = { 1: 'interface-local', 2: 'link-local', 4: 'admin-local', 5: 'site-local', 8: 'organization-local', 14: 'global' };

  /* ================= MAC ================= */
  function parseMac(s) {
    const h = String(s ?? '').trim().replace(/[:\-.\s]/g, '');
    if (!/^[0-9a-f]{12}$/i.test(h)) return null;
    return h.toLowerCase();
  }

  /* ================= hashing (MD5 and CRC32 here; SHA via the browser) ================= */
  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  function md5(bytes) {
    const K = new Uint32Array(64);
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
    const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const len = bytes.length, padLen = (Math.floor((len + 8) / 64) + 1) * 64;
    const buf = new Uint8Array(padLen); buf.set(bytes); buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    const bitLen = len * 8;
    dv.setUint32(padLen - 8, bitLen >>> 0, true); dv.setUint32(padLen - 4, Math.floor(bitLen / 2 ** 32), true);
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const M = new Uint32Array(16);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
      let A = a0, B = b0, C = c0, Dd = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & Dd); g = i; } else if (i < 32) { F = (Dd & B) | (~Dd & C); g = (5 * i + 1) % 16; } else if (i < 48) { F = B ^ C ^ Dd; g = (3 * i + 5) % 16; } else { F = C ^ (B | ~Dd); g = (7 * i) % 16; }
        const s = S[(i >> 4) * 4 + (i % 4)];
        F = ((F >>> 0) + A + K[i] + M[g]) >>> 0;
        A = Dd; Dd = C; C = B; B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + Dd) >>> 0;
    }
    const out = new DataView(new ArrayBuffer(16));
    [a0, b0, c0, d0].forEach((w, i) => out.setUint32(i * 4, w, true));
    return toHex(new Uint8Array(out.buffer));
  }
  let CRC_TABLE = null;
  function crc32(bytes) {
    if (!CRC_TABLE) { CRC_TABLE = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c >>> 0; } }
    let c = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return ((c ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0');
  }

  /* ================= password estimate ================= */
  const COMMON = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', '696969', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', 'fuckme', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'asshole', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'welcome', 'admin', 'passw0rd', 'p@ssw0rd', 'changeme', 'default', 'guest', 'login', 'administrator', 'root', 'secret'];
  const SEQS = ['abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  function passwordBits(pw) {
    const notes = [];
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[!-/:-@[-`{-~]/.test(pw)) pool += 33;
    if (/ /.test(pw)) pool += 1;
    if (/[^\x20-\x7e]/.test(pw)) pool += 100;
    // effective length: runs of one character and keyboard/alphabet sequences count as one symbol
    const lower = pw.toLowerCase();
    let eff = 0;
    for (let i = 0; i < pw.length;) {
      let j = i + 1;
      while (j < pw.length && pw[j] === pw[i]) j++;
      if (j - i >= 3) { eff += 1; i = j; notes.push('repeated characters'); continue; }
      let k = i + 1, run = 1;
      while (k < pw.length && SEQS.some((s) => { const a = s.indexOf(lower[k - 1]); return a >= 0 && (s[a + 1] === lower[k] || s[a - 1] === lower[k]); })) { k++; run++; }
      if (run >= 3) { eff += 1; i = k; notes.push('a keyboard or alphabet sequence'); continue; }
      eff += 1; i += 1;
    }
    let bits = pool ? eff * Math.log2(pool) : 0;
    const bare = lower.replace(/[^a-z0-9]/g, '');
    const stem = lower.replace(/[\d!@#$%^&*._-]+$/, '');
    if (COMMON.includes(lower) || COMMON.includes(bare)) { bits = Math.min(bits, 7); notes.push('it is on the list of the most common passwords'); }
    else if (stem.length >= 3 && COMMON.includes(stem)) { bits = Math.min(bits, 14); notes.push('it is a common password with characters added at the end'); }
    else if (/^[a-z]{3,}[\d!@#$%^&*]{1,5}$/i.test(pw)) { bits = Math.min(bits, 15 + 3.3 * (pw.length - stem.length)); notes.push('it looks like a word followed by numbers or a symbol — the first pattern crackers try'); }
    if (/(19|20)\d\d/.test(pw)) notes.push('it contains a year');
    return { bits: Math.max(0, bits), pool, notes: [...new Set(notes)] };
  }

  /* ================= live helpers ================= */
  const live = () => Boolean(D && D.canRun());
  async function runCmd(id, params = {}, presetKey = null) {
    const cmd = D.byId.get(id);
    if (!cmd || !cmd.runnable) bad(`The ${id} command is not available on this system.`);
    let preset = null;
    if (presetKey) { preset = ((cmd.runnable || {}).presets || []).findIndex((p) => p.key === presetKey); if (preset < 0) preset = null; }
    const r = await D.execute(cmd, params, { preset });
    if (r.refused || r.error) bad((r.output || 'The command could not run.').trim().slice(0, 200));
    return r.output || '';
  }
  const today = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
  const isoDate = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };

  /* ================= the tools ================= */
  const TOOLS = [];

  /* ---------- IPv4 subnet ---------- */
  TOOLS.push({
    key: 'ipv4', label: 'IPv4 subnet', manual: 'nc-ipv4',
    modes: [{
      key: 'main', label: 'Subnet',
      hint: 'Type an address and a mask in any form — /26, 255.255.255.192, a wildcard 0.0.0.63 or hex ff.ff.ff.c0 — or the two together as 192.168.1.100/26. Everything below updates as you type.',
      fields: [
        { id: 'ip', label: 'IP address', def: '192.168.1.100', placeholder: '192.168.1.100 or 192.168.1.100/26' },
        { id: 'mask', label: 'Mask or prefix', def: '/26', list: prefixList, placeholder: '/26 · 255.255.255.192 · 0.0.0.63' },
        { id: 'other', label: 'Same subnet as…', def: '', placeholder: 'optional' },
        { id: 'need', label: 'Hosts needed', def: '', placeholder: 'optional — e.g. 50' },
      ],
      actions: [{
        label: 'Use this PC', live: true, title: "Fill in this computer's address and mask",
        async run(api) {
          const ctx = D.context() || {};
          if (!ctx.ip) bad('No address detected for this PC.');
          let mask = '';
          try { const s = JSON.parse(localStorage.getItem('netdeck.dashboard.v1') || 'null'); const info = s && s.tiles && s.tiles.ip && s.tiles.ip.info; if (info && info.ip === ctx.ip && info.mask) mask = info.mask; } catch (e) { /* no snapshot */ }
          if (!mask) {
            const out = await runCmd('ipconfig-all');
            const at = out.indexOf(ctx.ip);
            const m = at >= 0 ? out.slice(at).match(/Subnet Mask[ .]*:\s*([\d.]+)/) : null;
            mask = m ? m[1] : '/24';
          }
          api.set({ ip: ctx.ip, mask });
        },
      }],
      compute(v) {
        let ipText = String(v.ip || '').trim();
        let prefix = null, maskFrom = '';
        if (ipText.includes('/')) { const [a, b] = ipText.split('/'); ipText = a.trim(); prefix = needMask(b).prefix; maskFrom = 'from the address field'; }
        const ip = ip4.parse(ipText);
        if (ip === null) bad(`"${ipText || '(empty)'}" is not an IPv4 address — four numbers from 0 to 255 separated by dots, such as 192.168.1.10.`);
        let kind = 'mask';
        if (prefix === null) { const m = needMask(v.mask); prefix = m.prefix; kind = m.kind; }
        const mask = ip4.mask(prefix), wild = ~mask >>> 0, net = (ip & mask) >>> 0, bc = (net | wild) >>> 0;
        const total = 2 ** (32 - prefix), usable = ip4.usable(prefix);
        const first = prefix >= 31 ? net : net + 1, lastH = prefix >= 31 ? bc : bc - 1;
        const cls = classOf(ip), type = v4Type(ip);
        // 192.168.001.010 is shown and reversed as 192.168.1.10; some tools would read 010 as octal (8)
        const zeros = ipText.split('.').some((o) => o.length > 1 && o.startsWith('0'));
        const canon = ip4.str(ip);
        const rows = [
          { k: 'Address', v: canon, note: `${type.label}${type.rfc ? ` (${type.rfc})` : ''}${zeros ? `. You typed ${ipText}: leading zeros removed — careful, some tools (ping on Windows among them) read a number with a leading zero as octal, so 010 would mean 8.` : ''}`, tone: (type.special && !type.private) || zeros ? 'warn' : '' },
          { k: 'Network', v: `${ip4.str(net)}/${prefix}`, note: prefix === 32 ? 'A /32 is this one address on its own.' : prefix === 31 ? 'The first of the two addresses — on a /31 it is usable, not reserved.' : 'The subnet\'s own address — the first one. It names the network; no device uses it.' },
          { k: 'Subnet mask', v: ip4.str(mask), note: `${kind === 'wildcard' ? 'Read your entry as a wildcard mask and inverted it. ' : ''}${maskFrom ? `Prefix taken ${maskFrom}. ` : ''}Ones in binary mark the network part, zeros the host part.` },
          { k: 'Prefix length', v: `/${prefix}`, note: `CIDR notation: ${prefix} network bit${prefix === 1 ? '' : 's'}, ${32 - prefix} host bit${32 - prefix === 1 ? '' : 's'}.` },
          { k: 'Wildcard mask', v: ip4.str(wild), note: 'The mask inverted — how router access lists and OSPF write the same thing.' },
          { k: 'Usable host range', v: `${ip4.str(first)} – ${ip4.str(lastH)}`, note: prefix === 32 ? 'A /32 is a single address (a host route).' : prefix === 31 ? 'A /31 is a point-to-point link: both addresses are usable, there is no broadcast (RFC 3021).' : 'The addresses you can give to devices.' },
          { k: 'Usable hosts', v: fmtInt(usable), note: prefix >= 31 ? '' : `${fmtInt(total)} addresses minus the network and broadcast addresses.` },
          { k: 'Total addresses', v: fmtInt(total), note: `2 to the power of ${32 - prefix}.` },
          { k: 'Broadcast', v: prefix >= 31 ? '—' : ip4.str(bc), note: prefix >= 31 ? 'None on a /31 or /32.' : 'The last address. A packet sent here reaches every device in the subnet.' },
        ];
        if (net + total <= 0xFFFFFFFF) rows.push({ k: 'Next subnet', v: `${ip4.str(net + total)}/${prefix}` });
        if (net >= total) rows.push({ k: 'Previous subnet', v: `${ip4.str(net - total)}/${prefix}` });
        const blocks = [{ type: 'kv', title: 'The subnet', rows }];
        const cl = [{ k: 'Class', v: `Class ${cls.cls}`, note: `First number ${cls.range}.${cls.note ? ` ${cls.note}.` : ''} Classes are history — networks have been classless (CIDR) since 1993 — but the words are still used.` }];
        if (cls.bits !== null) {
          cl.push({ k: 'Classful default mask', v: `${ip4.str(ip4.mask(cls.bits))} (/${cls.bits})` });
          if (prefix >= cls.bits) {
            cl.push({ k: 'Subnet bits', v: String(prefix - cls.bits), note: `Bits borrowed from the host part of a class ${cls.cls} network.` });
            cl.push({ k: 'Maximum subnets', v: fmtInt(2 ** (prefix - cls.bits)), note: `How many /${prefix} subnets fit in the class ${cls.cls} network ${ip4.str((ip & ip4.mask(cls.bits)) >>> 0)}/${cls.bits}.` });
          } else cl.push({ k: 'Supernet', v: `${cls.bits - prefix} bits shorter than classful`, note: `This prefix joins ${fmtInt(2 ** (cls.bits - prefix))} class ${cls.cls} networks into one.` });
        }
        cl.push({ k: 'Subnet bitmap', v: bitmap(prefix, cls), note: 'Fixed class bits, then n = network, s = subnet, h = host.' });
        blocks.push({ type: 'kv', title: 'Class', rows: cl });
        const enc = [
          { k: 'Binary', v: ip4.bin(ip).match(/.{8}/g).join('.'), html: bitsHtml(ip, prefix, cls.bits), note: 'Red: classful network bits · amber: subnet bits · green: host bits.' },
          { k: 'Hexadecimal', v: `${ip4.hex(ip)}  (0x${(ip >>> 0).toString(16).toUpperCase().padStart(8, '0')})` },
          { k: 'Decimal integer', v: String(ip), note: 'The address as one 32-bit number.' },
          { k: 'Mask in hex', v: ip4.hex(mask).toLowerCase() },
          { k: 'Mask in binary', v: ip4.bin(mask).match(/.{8}/g).join('.') },
          { k: 'Reverse DNS name', v: `${canon.split('.').reverse().join('.')}.in-addr.arpa`, note: 'The name a PTR lookup (address → name) asks for.' },
        ];
        blocks.push({ type: 'kv', title: 'Encodings', rows: enc });
        const extra = [];
        if (String(v.other || '').trim()) {
          const o = ip4.parse(v.other);
          if (o === null) extra.push({ k: 'Same subnet?', v: 'not an address', tone: 'err' });
          else {
            const same = ((o & mask) >>> 0) === net;
            extra.push({ k: 'Same subnet?', v: same ? `Yes — ${v.other.trim()} is in ${ip4.str(net)}/${prefix}` : `No — ${v.other.trim()} is in ${ip4.str((o & mask) >>> 0)}/${prefix}`, tone: same ? 'ok' : 'warn', note: same ? 'They can talk directly, without a router.' : 'Traffic between them has to go through a router.' });
          }
        }
        if (String(v.need || '').trim()) {
          const h = num(v.need, 'Hosts needed', { min: 1, max: 4294967294, int: true });
          const p = fitPrefix(h);
          extra.push(p === null ? { k: `Subnet for ${fmtInt(h)} hosts`, v: 'too many for IPv4', tone: 'err' }
            : { k: `Subnet for ${fmtInt(h)} host${h === 1 ? '' : 's'}`, v: `/${p}  (${ip4.str(ip4.mask(p))})`, note: `${fmtInt(ip4.usable(p))} usable addresses, ${fmtInt(ip4.usable(p) - h)} to spare.${h === 2 ? ' A /31 also works for a point-to-point link between two routers.' : ''}` });
        }
        if (extra.length) blocks.unshift({ type: 'kv', title: 'Checks', rows: extra, span: true });
        // class D and E are not host networks: say so above the arithmetic, which is still shown
        if (cls.bits === null) blocks.unshift({ type: 'msg', tone: 'warn', text: cls.cls === 'D' ? `${canon} is a multicast group address (class D), not a device's address: masks, host ranges and broadcast do not apply to it. The rows below are only the arithmetic.` : `${canon} is in the reserved class E range (240–255), which is not used on networks: the rows below are only the arithmetic.` });
        return blocks;
      },
    }],
  });

  /* ---------- Split & summarize ---------- */
  TOOLS.push({
    key: 'split', label: 'Split & summarize', manual: 'nc-split',
    modes: [
      {
        key: 'split', label: 'Split into subnets',
        hint: 'Start from a network, then say how to cut it: into a number of equal subnets, into subnets big enough for a number of hosts, or into subnets of a given prefix length. Every resulting subnet is listed.',
        fields: [
          { id: 'net', label: 'Network', def: '192.168.1.0/24', placeholder: '192.168.1.0/24' },
          { id: 'by', label: 'Split by', type: 'select', def: 'count', options: [['count', 'Number of subnets'], ['hosts', 'Hosts per subnet'], ['prefix', 'New prefix length']] },
          { id: 'val', label: 'Value', def: '4', placeholder: '4 · 50 · /26' },
        ],
        compute(v) {
          const n = parseCidr(v.net);
          let p;
          const raw = String(v.val || '').trim().replace(/^\//, '');
          if (v.by === 'count') { const c = num(raw, 'Number of subnets', { min: 1, int: true }); p = n.prefix + Math.ceil(Math.log2(c)); }
          else if (v.by === 'hosts') { const h = num(raw, 'Hosts per subnet', { min: 1, int: true }); p = fitPrefix(h); if (p === null) bad('That is more hosts than IPv4 has.'); }
          else p = needMask(raw).prefix;
          if (p > 32) bad('That many subnets do not fit: there are not enough host bits to borrow.');
          if (p < n.prefix) bad(`/${p} is bigger than the network itself (/${n.prefix}); pick fewer hosts or a longer prefix.`);
          const count = 2 ** (p - n.prefix), size = 2 ** (32 - p);
          const rows = [];
          for (let i = 0; i < Math.min(count, 1024); i++) rows.push(subnetRow(i + 1, n.net + i * size, p));
          const out = [{ type: 'kv', rows: [
            { k: 'Network', v: `${ip4.str(n.net)}/${n.prefix}`, note: n.normalized ? 'Host bits in your entry were cleared to get the network address.' : '' },
            { k: 'New prefix', v: `/${p}  (${ip4.str(ip4.mask(p))})`, note: `${p - n.prefix} bit${p - n.prefix === 1 ? '' : 's'} borrowed from the host part.` },
            { k: 'Subnets', v: fmtInt(count), note: v.by === 'count' && count !== Number(raw) ? `Subnets come in powers of two, so ${raw} becomes ${fmtInt(count)}.` : '' },
            { k: 'Block size', v: fmtInt(size), note: 'Each subnet starts this many addresses after the previous one.' },
            { k: 'Usable hosts each', v: fmtInt(ip4.usable(p)) },
          ] }, { type: 'table', columns: ['#', 'Subnet', 'First host', 'Last host', 'Broadcast', 'Hosts'], rows }];
          if (count > 1024) out.push({ type: 'msg', tone: 'warn', text: `Showing the first 1,024 of ${fmtInt(count)} subnets.` });
          return out;
        },
      },
      {
        key: 'vlsm', label: 'VLSM plan',
        hint: 'Variable-length subnet masking: list what you need, one line each as "name hosts", and each gets the smallest subnet that fits — largest first, packed from the start of the network, so nothing overlaps and little is wasted.',
        fields: [
          { id: 'net', label: 'Network to divide', def: '10.0.0.0/22', placeholder: '10.0.0.0/22' },
          { id: 'reqs', label: 'Requirements — one per line: name hosts', type: 'textarea', rows: 5, wide: true, def: 'Office 200\nGuest Wi-Fi 100\nCameras 25\nPrinters 10\nRouter link 2' },
        ],
        compute(v) {
          const n = parseCidr(v.net);
          const reqs = String(v.reqs || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l, i) => {
            const m = l.match(/^(.*?)[\s,:=]+(\d+)\s*$/) || l.match(/^()(\d+)$/);
            if (!m) bad(`Line ${i + 1} ("${l}") needs a number of hosts at the end.`);
            return { name: m[1].trim() || `Subnet ${i + 1}`, hosts: Number(m[2]), order: i };
          });
          if (!reqs.length) bad('Add at least one line, such as "Office 50".');
          const sorted = [...reqs].sort((a, b) => b.hosts - a.hosts || a.order - b.order);
          let cursor = n.net;
          const end = n.bc;
          const rows = [];
          let used = 0;
          for (const r of sorted) {
            const p = fitPrefix(r.hosts);
            if (p === null) bad(`${r.name}: ${fmtInt(r.hosts)} hosts is more than IPv4 has.`);
            const size = 2 ** (32 - p);
            cursor = Math.ceil(cursor / size) * size;
            if (cursor + size - 1 > end) bad(`It does not fit: ${r.name} needs a /${p} (${fmtInt(size)} addresses) but only ${fmtInt(Math.max(0, end - cursor + 1))} are left in ${ip4.str(n.net)}/${n.prefix}. Use a bigger network or smaller requirements.`);
            const sr = subnetRow(0, cursor, p);
            rows.push([r.name, fmtInt(r.hosts), sr[1], sr[2], sr[3], sr[4], fmtInt(ip4.usable(p)), fmtInt(ip4.usable(p) - r.hosts)]);
            used += size; cursor += size;
          }
          return [
            { type: 'table', columns: ['Name', 'Needed', 'Subnet', 'First host', 'Last host', 'Broadcast', 'Usable', 'Spare'], rows },
            { type: 'kv', rows: [
              { k: 'Addresses used', v: `${fmtInt(used)} of ${fmtInt(n.size)}`, note: `${round((used / n.size) * 100, 1)}% of ${ip4.str(n.net)}/${n.prefix}.` },
              { k: 'Free for later', v: cursor <= end ? `${ip4.str(cursor)} – ${ip4.str(end)}` : 'none', note: cursor <= end ? `${fmtInt(end - cursor + 1)} addresses.` : '' },
            ] },
          ];
        },
      },
      {
        key: 'range', label: 'Range → CIDR',
        hint: 'Turn a start and end address into the fewest CIDR blocks that cover exactly that range — what a firewall rule or route list needs when the range does not line up with one subnet.',
        fields: [
          { id: 'a', label: 'First address', def: '192.168.1.10' },
          { id: 'b', label: 'Last address', def: '192.168.1.100' },
        ],
        compute(v) {
          const a = ip4.parse(v.a), b = ip4.parse(v.b);
          if (a === null || b === null) bad('Enter two IPv4 addresses.');
          const [lo, hi] = a <= b ? [a, b] : [b, a];
          const blocks = rangeToCidrs(lo, hi);
          return [
            { type: 'kv', rows: [{ k: 'Range', v: `${ip4.str(lo)} – ${ip4.str(hi)}`, note: `${fmtInt(hi - lo + 1)} addresses${a > b ? ' (swapped so the lower comes first)' : ''}.` }, { k: 'CIDR blocks', v: String(blocks.length), note: blocks.length === 1 ? 'The range is exactly one subnet.' : 'Each block must start on a multiple of its own size, which is why a range usually needs several.' }] },
            { type: 'table', columns: ['CIDR', 'First', 'Last', 'Addresses'], rows: blocks.map(([s, p]) => [`${ip4.str(s)}/${p}`, ip4.str(s), ip4.str(s + 2 ** (32 - p) - 1), fmtInt(2 ** (32 - p))]) },
          ];
        },
      },
      {
        key: 'summary', label: 'Summarize routes',
        hint: 'Combine a list of networks: the exact result merges neighbors that line up into larger blocks, and the single summary is the smallest one network that covers them all — what one route or one firewall rule would need.',
        fields: [{ id: 'nets', label: 'Networks — one per line', type: 'textarea', rows: 5, wide: true, def: '192.168.0.0/24\n192.168.1.0/24\n192.168.2.0/24\n192.168.3.0/24' }],
        compute(v) {
          const nets = String(v.nets || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => parseCidr(l, 32));
          if (!nets.length) bad('Add at least one network.');
          const iv = nets.map((n) => [n.net, n.bc]).sort((x, y) => x[0] - y[0]);
          const merged = [];
          for (const [s, e] of iv) { const m = merged[merged.length - 1]; if (m && s <= m[1] + 1) m[1] = Math.max(m[1], e); else merged.push([s, e]); }
          const exact = merged.flatMap(([s, e]) => rangeToCidrs(s, e));
          const lo = iv[0][0], hi = Math.max(...iv.map((x) => x[1]));
          let p = 32; while (p > 0 && ((lo & ip4.mask(p)) >>> 0) !== ((hi & ip4.mask(p)) >>> 0)) p--;
          const sNet = (lo & ip4.mask(p)) >>> 0, sSize = 2 ** (32 - p);
          const covered = merged.reduce((a, [s, e]) => a + e - s + 1, 0);
          return [
            { type: 'kv', rows: [
              { k: 'Single summary', v: `${ip4.str(sNet)}/${p}`, note: sSize === covered ? 'Covers exactly your networks — nothing extra.' : `Also covers ${fmtInt(sSize - covered)} addresses that are not in your list.`, tone: sSize === covered ? 'ok' : 'warn' },
              { k: 'Exact blocks', v: String(exact.length), note: exact.length < nets.length ? `${nets.length} networks merge into ${exact.length}.` : 'Nothing merges — the networks are not neighbors that line up.' },
            ] },
            { type: 'table', columns: ['Exact block', 'First', 'Last', 'Addresses'], rows: exact.map(([s, q]) => [`${ip4.str(s)}/${q}`, ip4.str(s), ip4.str(s + 2 ** (32 - q) - 1), fmtInt(2 ** (32 - q))]) },
          ];
        },
      },
    ],
  });

  /* ---------- IPv6 ---------- */
  TOOLS.push({
    key: 'ipv6', label: 'IPv6', manual: 'nc-ipv6',
    modes: [{
      key: 'main', label: 'IPv6',
      hint: 'Type an IPv6 address with or without a prefix (/64 is assumed). You get the short and full forms, the network it belongs to, what kind of address it is, and how it breaks down. Optionally list the subnets of a given size inside the prefix.',
      fields: [
        { id: 'addr', label: 'IPv6 address / prefix', def: '2001:db8:abcd:12::1/64', placeholder: '2001:db8::1/64', span2: true },
        { id: 'split', label: 'List subnets of size', def: '', placeholder: 'optional — e.g. /64' },
      ],
      compute(v) {
        let t = String(v.addr || '').trim(), p = 64, assumed = true;
        const m = t.match(/^(.*)\/(\d{1,3})$/);
        if (m) { t = m[1]; p = Number(m[2]); assumed = false; if (p > 128) bad('An IPv6 prefix runs from /0 to /128.'); }
        const n = parse6(t);
        if (n === null) bad(`"${t}" is not an IPv6 address — eight groups of up to four hex digits separated by colons; one run of zero groups may be written as "::".`);
        const mask = mask6(p), net = n & mask, lastA = net | (ALL6 ^ mask);
        const type = v6Type(n);
        const count = 1n << BigInt(128 - p);
        const rows = [
          { k: 'Compressed', v: mixed6(n), note: 'The standard short form (RFC 5952): leading zeros dropped, the longest run of zero groups written as "::", lower case.' },
          { k: 'Expanded', v: expand6(n), note: 'All eight groups of four hex digits.' },
          { k: 'Type', v: type.label, tone: type.prefix === 3 ? 'ok' : '' },
          { k: 'Prefix', v: `/${p}`, note: assumed ? 'None given, so /64 was assumed — the standard size of one IPv6 subnet.' : `${p} network bits, ${128 - p} interface bits.` },
          { k: 'Network', v: `${fmt6(net)}/${p}` },
          { k: 'First address', v: fmt6(net) },
          { k: 'Last address', v: fmt6(lastA), note: 'IPv6 has no broadcast address, so every address in the prefix is usable.' },
          { k: 'Addresses', v: count > 10n ** 15n ? `2^${128 - p}  (${fmtBig(count).slice(0, 15)}…)` : fmtBig(count), note: p < 64 ? `That is ${fmtBig(1n << BigInt(64 - p))} subnets of /64.` : '' },
        ];
        const g = groups6(n);
        if (type.prefix === 8) { const sc = g[0] & 0xf; rows.push({ k: 'Multicast scope', v: MC_SCOPE[sc] || `scope ${sc}` }); }
        if ((n >> 32n) === 0xffffn) rows.push({ k: 'Embedded IPv4', v: ip4.str(Number(n & 0xffffffffn)), note: 'IPv4-mapped form.' });
        else if ((n & mask6(96)) === parse6('64:ff9b::')) rows.push({ k: 'Embedded IPv4', v: ip4.str(Number(n & 0xffffffffn)), note: 'The IPv4 server this NAT64 address reaches.' });
        else if ((n >> 112n) === 0x2002n) rows.push({ k: 'Embedded IPv4', v: ip4.str(Number((n >> 80n) & 0xffffffffn)), note: 'The 6to4 gateway.' });
        const blocks = [{ type: 'kv', rows }];
        if (type.prefix === 3 || type.prefix === 7 || type.prefix === 32) {
          const iid = n & ((1n << 64n) - 1n);
          const b = Array.from({ length: 8 }, (_, i) => Number((iid >> BigInt(56 - i * 8)) & 0xffn));
          const eui = b[3] === 0xff && b[4] === 0xfe;
          const mac = eui ? [b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]].map((x) => x.toString(16).padStart(2, '0')).join(':') : '';
          const vendor = mac && window.NetDeckOui ? window.NetDeckOui.lookup(mac) : '';
          blocks.push({ type: 'kv', title: 'How it breaks down', rows: [
            { k: 'Routing prefix', v: `${g.slice(0, 3).map((x) => x.toString(16)).join(':')}::/48`, note: 'The first 48 bits: typically the block an ISP assigns to one site.' },
            { k: 'Subnet ID', v: g[3].toString(16).padStart(4, '0'), note: 'The next 16 bits: which of the site\'s 65,536 subnets.' },
            { k: 'Interface ID', v: g.slice(4).map((x) => x.toString(16).padStart(4, '0')).join(':'), note: eui ? `Built from the MAC address ${mac}${vendor ? ` (${vendor})` : ''} — EUI-64, which reveals the hardware.` : iid < 0x10000n ? 'The last 64 bits, identifying the device — a small number like this was set by hand or handed out by DHCPv6, as is usual for routers and servers.' : 'The last 64 bits, identifying the device — random here (a privacy or stable-opaque address, RFC 4941 / 7217), not derived from the MAC.' },
          ] });
        }
        blocks.push({ type: 'kv', title: 'Encodings', rows: [{ k: 'Reverse DNS name', v: `${expand6(n).replace(/:/g, '').split('').reverse().join('.')}.ip6.arpa`, note: 'The name a PTR lookup asks for: every hex digit, reversed.' }] });
        if (String(v.split || '').trim()) {
          const q = Number(String(v.split).trim().replace(/^\//, ''));
          if (!Number.isInteger(q) || q < p || q > 128) bad(`Subnet size must be a prefix from /${p} to /128.`);
          const cnt = 1n << BigInt(q - p), step = 1n << BigInt(128 - q);
          const rowsT = [];
          for (let i = 0n; i < cnt && i < 16n; i++) { const s = net + i * step; rowsT.push([String(i + 1n), `${fmt6(s)}/${q}`, fmt6(s + step - 1n)]); }
          blocks.push({ type: 'table', title: `Subnets of /${q} — ${fmtBig(cnt)} in total${cnt > 16n ? ', first 16 shown' : ''}`, columns: ['#', 'Subnet', 'Last address'], rows: rowsT });
        }
        return blocks;
      },
    }],
  });

  /* ---------- MAC ---------- */
  TOOLS.push({
    key: 'mac', label: 'MAC', manual: 'nc-mac',
    modes: [{
      key: 'main', label: 'MAC',
      hint: 'Paste a MAC address in any format — 00:00:5e:00:53:01, 00-00-5E-00-53-01, 0000.5e00.5301 or 00005E005301. It is checked, shown in every common format, and decoded: who made it, and what its two flag bits say.',
      fields: [
        { id: 'mac', label: 'MAC address', def: '00-00-5E-00-53-01', placeholder: 'aa:bb:cc:dd:ee:ff', span2: true },
        { id: 'case', label: 'Letters', type: 'select', def: 'upper', options: [['upper', 'UPPER CASE'], ['lower', 'lower case']] },
      ],
      compute(v) {
        const h = parseMac(v.mac);
        if (!h) bad(`"${String(v.mac || '').trim()}" is not a MAC address — twelve hex digits (0–9, A–F), usually in pairs separated by colons or dashes.`);
        const c = (s) => (v.case === 'lower' ? s.toLowerCase() : s.toUpperCase());
        const pairs = h.match(/../g);
        const b0 = parseInt(pairs[0], 16);
        const group = (b0 & 1) === 1, local = (b0 & 2) === 2;
        const bcast = h === 'ffffffffffff';
        const vendor = window.NetDeckOui ? window.NetDeckOui.lookup(h) : '';
        const eui = [(b0 ^ 2).toString(16).padStart(2, '0'), pairs[1], pairs[2], 'ff', 'fe', pairs[3], pairs[4], pairs[5]];
        const ll = fmt6(parse6(`fe80::${eui[0]}${eui[1]}:${eui[2]}${eui[3]}:${eui[4]}${eui[5]}:${eui[6]}${eui[7]}`));
        let seen = null;
        try { const L = window.NetDeckScanLog && window.NetDeckScanLog.latest ? window.NetDeckScanLog.latest() : null; if (L) seen = L.devices.find((d) => String(d.mac || '').toLowerCase().replace(/[^0-9a-f]/g, '') === h) || null; } catch (e) { /* none */ }
        return [
          { type: 'kv', title: 'Formats', rows: [
            { k: 'Colon (Linux, macOS)', v: c(pairs.join(':')) },
            { k: 'Dash (Windows)', v: c(pairs.join('-')) },
            { k: 'Dot (Cisco)', v: c(h.match(/..../g).join('.')) },
            { k: 'Bare', v: c(h) },
          ] },
          { type: 'kv', title: 'What it says', rows: [
            group
              ? { k: 'Manufacturer', v: bcast ? '— (broadcast)' : h.startsWith('01005e') ? '— (IPv4 multicast group)' : h.startsWith('3333') ? '— (IPv6 multicast group)' : vendor ? `— (a group address of ${vendor})` : '— (a group address)', note: 'A group address names a destination that many devices listen to, not a piece of hardware, so it has no manufacturer of its own.' }
              : { k: 'Manufacturer', v: vendor || 'not in the registry', note: local ? 'A locally administered address was made up by software, so no manufacturer can be read from it.' : `From the first half (the OUI, ${c(pairs.slice(0, 3).join(':'))}) in the IEEE registry.` },
            { k: 'Unicast / multicast', v: bcast ? 'Broadcast' : group ? 'Multicast (group)' : 'Unicast (one device)', note: 'The lowest bit of the first byte (I/G): 0 = one device, 1 = a group. A network adapter\'s own address is always unicast.' + (bcast ? ' All ones: every device on the network.' : h.startsWith('01005e') ? ' 01:00:5e… carries IPv4 multicast.' : h.startsWith('3333') ? ' 33:33… carries IPv6 multicast.' : '') },
            group
              ? { k: 'Universal / local', v: 'does not apply', note: 'The U/L bit only tells whether a single device\'s address was burned in or made up; a group address is neither.' }
              : { k: 'Universal / local', v: local ? 'Locally administered' : 'Universally administered', tone: local ? 'warn' : '', note: local ? 'The second-lowest bit (U/L) is set: the address was made up by software — typically a phone or laptop hiding its real address on Wi-Fi ("private" or "random" address), or a virtual machine.' : 'Burned in by the manufacturer, unique worldwide.' },
            ...(seen ? [{ k: 'On your network', v: `${seen.ip}${seen.name ? ` — ${seen.name}` : ''}`, note: 'From the last "Scan my network".', tone: 'ok' }] : []),
          ] },
          group
            ? { type: 'msg', text: 'IPv6: no interface ID — only a single device\'s address can become one.' }
            : { type: 'kv', title: 'IPv6', rows: [
              { k: 'EUI-64 interface ID', v: c(eui.join('').match(/..../g).join(':')), note: 'The MAC split in two, ff:fe inserted, and the U/L bit flipped.' },
              { k: 'Link-local address', v: ll, note: 'What an EUI-64 device would use on its link. Windows and phones use random interface IDs instead, for privacy.' },
            ] },
        ];
      },
    }],
  });

  /* ---------- Bandwidth & time ---------- */
  const SIZE_UNITS = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, TiB: 1024 ** 4 };
  const SPEED_UNITS = { 'kbit/s': 1e3, 'Mbit/s': 1e6, 'Gbit/s': 1e9, 'kB/s': 8e3, 'MB/s': 8e6, 'GB/s': 8e9 };
  const ACTIVITIES = [
    ['calls', 'HD video call', 3.8, 3, 1], ['group', 'Group video call', 4, 3, 0], ['uhd', '4K streaming', 25, 0.2, 1], ['hd', 'HD streaming', 5, 0.1, 2],
    ['music', 'Music streaming', 0.3, 0.05, 1], ['web', 'Web and email', 1.5, 0.5, 3], ['gaming', 'Online gaming', 3, 1, 1], ['backup', 'Cloud backup / large uploads', 0, 10, 0],
    ['cams', 'Cloud security camera', 0, 2, 2], ['iot', 'Smart-home device', 0.05, 0.05, 10],
  ];
  TOOLS.push({
    key: 'bandwidth', label: 'Bandwidth & time', manual: 'nc-bandwidth',
    modes: [
      {
        key: 'transfer', label: 'Transfer time',
        hint: 'How long a file takes at a given speed. Efficiency accounts for protocol overhead — headers, acknowledgements, retransmits — which leaves roughly 90% of a line for data on a good connection.',
        fields: [
          { id: 'size', label: 'Size', def: '4.7' }, { id: 'sunit', label: 'Unit', type: 'select', def: 'GB', options: Object.keys(SIZE_UNITS).map((k) => [k, k]) },
          { id: 'speed', label: 'Speed', def: '100' }, { id: 'vunit', label: 'Unit', type: 'select', def: 'Mbit/s', options: Object.keys(SPEED_UNITS).map((k) => [k, k]) },
          { id: 'eff', label: 'Efficiency %', def: '90' },
        ],
        compute(v) {
          const bytes = num(v.size, 'Size', { min: 0 }) * SIZE_UNITS[v.sunit];
          const bps = num(v.speed, 'Speed', { min: 0.000001 }) * SPEED_UNITS[v.vunit];
          const eff = num(v.eff, 'Efficiency', { min: 1, max: 100 }) / 100;
          const t = (bytes * 8) / (bps * eff);
          const speeds = [10e6, 50e6, 100e6, 300e6, 500e6, 1e9, 2.5e9, 10e9];
          return [
            { type: 'kv', rows: [
              { k: 'Transfer time', v: fmtTime(t), tone: 'ok' },
              { k: 'Data', v: `${fmtBytes(bytes)}  ·  ${fmtInt(Math.round(bytes * 8))} bits`, note: v.sunit.includes('i') ? `${v.sunit} is binary (1 ${v.sunit} = ${fmtInt(SIZE_UNITS[v.sunit])} bytes); disks and downloads mix the two.` : 'Decimal units: 1 GB = 1,000,000,000 bytes.' },
              { k: 'Effective rate', v: `${fmtRate(bps * eff)}  ·  ${fmtBytes((bps * eff) / 8)}/s`, note: 'Line speed × efficiency. Divide bits by 8 for the bytes-per-second a download dialog shows.' },
            ] },
            { type: 'table', title: 'The same transfer at common speeds', columns: ['Speed', 'Time'], rows: speeds.map((s) => [fmtRate(s), fmtTime((bytes * 8) / (s * eff))]) },
          ];
        },
      },
      {
        key: 'need', label: 'How much do I need?',
        hint: 'Count what happens at the same time at the busiest moment — two people on calls while one streams 4K, say — not every device you own. Headroom covers peaks, updates and the difference between advertised and real speeds.',
        fields: [...ACTIVITIES.map(([id, label, , , def]) => ({ id, label, def: String(def) })), { id: 'headroom', label: 'Headroom %', def: '30' }],
        compute(v) {
          const hr = num(v.headroom, 'Headroom', { min: 0, max: 500 }) / 100;
          let down = 0, up = 0;
          const rows = [];
          for (const [id, label, d, u] of ACTIVITIES) {
            const n = num(v[id] || 0, label, { min: 0, max: 10000, int: true });
            if (!n) continue;
            down += n * d; up += n * u;
            rows.push([label, String(n), `${d} / ${u}`, `${round(n * d, 1)} / ${round(n * u, 1)}`]);
          }
          const D2 = down * (1 + hr), U2 = up * (1 + hr);
          const tiers = [25, 50, 100, 200, 300, 500, 1000, 2000, 5000];
          const tier = tiers.find((x) => x >= D2) || tiers[tiers.length - 1];
          return [
            { type: 'kv', rows: [
              { k: 'Download needed', v: `${round(D2, 1)} Mbit/s`, tone: 'ok', note: `${round(down, 1)} Mbit/s of activity + ${Math.round(hr * 100)}% headroom.` },
              { k: 'Upload needed', v: `${round(U2, 1)} Mbit/s`, tone: 'ok', note: `${round(up, 1)} Mbit/s + headroom. Upload is where cable and DSL plans are thin — calls, cameras and backups live here.` },
              { k: 'Plan to look for', v: `${fmtInt(tier)} Mbit/s or more`, note: 'The next common plan above your download figure; check its upload separately.' },
            ] },
            { type: 'table', title: 'Per activity (Mbit/s, down / up)', columns: ['Activity', 'At once', 'Each', 'Total'], rows },
          ];
        },
      },
    ],
  });

  /* ---------- Throughput & latency ---------- */
  const MEDIA = { fiber: [204190, 'Fiber (light in glass, ~2/3 c)'], copper: [200000, 'Copper cable (~2/3 c)'], radio: [299792, 'Radio / air / space (c)'] };
  TOOLS.push({
    key: 'throughput', label: 'Throughput & latency', manual: 'nc-throughput',
    modes: [
      {
        key: 'tcp', label: 'TCP throughput',
        hint: 'A single TCP download is limited by three things: the line speed, the receive window divided by the round-trip time, and packet loss. The slowest of the three wins — which is why a fast line can still give a slow download far away or on a lossy link.',
        fields: [
          { id: 'link', label: 'Line speed (Mbit/s)', def: '100' }, { id: 'rtt', label: 'Round-trip time (ms)', def: '40' },
          { id: 'loss', label: 'Packet loss %', def: '0.1' }, { id: 'mss', label: 'Segment size (bytes)', def: '1460' },
          { id: 'win', label: 'TCP window', type: 'select', def: '16384', options: [['64', '64 KB (no window scaling)'], ['256', '256 KB'], ['1024', '1 MB'], ['4096', '4 MB'], ['16384', '16 MB (Windows auto-tuning)']] },
          { id: 'streams', label: 'Parallel streams', def: '1' },
        ],
        compute(v) {
          const link = num(v.link, 'Line speed', { min: 0.001 }) * 1e6, rtt = num(v.rtt, 'Round-trip time', { min: 0.01 }) / 1000;
          const p = num(v.loss, 'Packet loss', { min: 0, max: 100 }) / 100, mss = num(v.mss, 'Segment size', { min: 100, max: 9000 });
          const win = Number(v.win) * 1024, k = num(v.streams, 'Parallel streams', { min: 1, max: 128, int: true });
          const wl = (k * win * 8) / rtt, ll = p > 0 ? k * ((mss * 8) / rtt) * (1.22 / Math.sqrt(p)) : Infinity;
          const eff = Math.min(link, wl, ll);
          const by = eff === link ? 'the line speed' : eff === wl ? 'the TCP window' : 'packet loss';
          const bdp = (link * rtt) / 8;
          return [
            { type: 'kv', rows: [
              { k: 'Expected throughput', v: fmtRate(eff), tone: eff >= link * 0.9 ? 'ok' : 'warn', note: `Limited by ${by}${k > 1 ? `, across ${k} streams` : ''}.` },
              { k: 'Line speed', v: fmtRate(link) },
              { k: 'Window limit', v: fmtRate(wl), note: 'Window ÷ round-trip time: TCP can only have one window of data "in flight" before it must wait for an acknowledgement.' },
              { k: 'Loss limit', v: fmtRate(ll), note: p > 0 ? 'The Mathis formula: (segment ÷ RTT) × 1.22 ÷ √loss. Every lost packet halves TCP\'s sending rate.' : 'No loss entered, so loss sets no limit.' },
              { k: 'Bandwidth-delay product', v: fmtBytes(bdp), note: `The data in flight needed to fill ${fmtRate(link)} at ${round(rtt * 1000, 1)} ms — the window has to be at least this big.` },
            ] },
            { type: 'table', title: 'One stream at this RTT and window, by packet loss', columns: ['Loss', 'Throughput'], rows: [0.01, 0.05, 0.1, 0.5, 1, 2, 5].map((x) => [`${x}%`, fmtRate(Math.min(link, win * 8 / rtt, (mss * 8 / rtt) * (1.22 / Math.sqrt(x / 100))))]) },
          ];
        },
      },
      {
        key: 'latency', label: 'Latency budget',
        hint: 'Where the milliseconds of a round trip come from: the distance at the speed of light in the medium (propagation), the time to put a packet on each link (serialization), each router\'s processing, and time waiting in queues. Presets fill in typical paths.',
        fields: [
          { id: 'dist', label: 'Distance (one way)', def: '5600' }, { id: 'unit', label: 'Unit', type: 'select', def: 'km', options: [['km', 'km'], ['mi', 'miles']] },
          { id: 'medium', label: 'Medium', type: 'select', def: 'fiber', options: Object.entries(MEDIA).map(([k, [, l]]) => [k, l]) },
          { id: 'factor', label: 'Route factor', def: '1.3' }, { id: 'hops', label: 'Router hops', def: '12' }, { id: 'perhop', label: 'Processing per hop (ms)', def: '0.05' },
          { id: 'pkt', label: 'Packet size (bytes)', def: '1500' }, { id: 'link', label: 'Link speed (Mbit/s)', def: '100' }, { id: 'queue', label: 'Queuing (ms)', def: '0' },
        ],
        actions: [
          { label: 'Same city', run: (api) => api.set({ dist: '50', unit: 'km', medium: 'fiber', factor: '1.5', hops: '6' }) },
          { label: 'Across the US', run: (api) => api.set({ dist: '4000', unit: 'km', medium: 'fiber', factor: '1.3', hops: '12' }) },
          { label: 'Transatlantic', run: (api) => api.set({ dist: '5600', unit: 'km', medium: 'fiber', factor: '1.3', hops: '12' }) },
          { label: 'Geostationary satellite', run: (api) => api.set({ dist: '71572', unit: 'km', medium: 'radio', factor: '1', hops: '8' }) },
          { label: 'Low-orbit satellite', run: (api) => api.set({ dist: '1100', unit: 'km', medium: 'radio', factor: '1.3', hops: '8' }) },
        ],
        compute(v) {
          const km = num(v.dist, 'Distance', { min: 0 }) * (v.unit === 'mi' ? 1.609344 : 1);
          const [speed] = MEDIA[v.medium] || MEDIA.fiber;
          const factor = num(v.factor, 'Route factor', { min: 1, max: 5 }), hops = num(v.hops, 'Router hops', { min: 0, max: 64, int: true });
          const per = num(v.perhop, 'Processing per hop', { min: 0 }) / 1000, pkt = num(v.pkt, 'Packet size', { min: 1 }), link = num(v.link, 'Link speed', { min: 0.001 }) * 1e6, q = num(v.queue, 'Queuing', { min: 0 }) / 1000;
          const prop = (km * factor) / speed, ser = ((pkt * 8) / link) * Math.max(1, hops), proc = per * hops;
          const one = prop + ser + proc + q;
          return [
            { type: 'kv', rows: [
              { k: 'Round trip (estimate)', v: fmtTime(one * 2), tone: 'ok', note: 'What ping would show, give or take.' },
              { k: 'One way', v: fmtTime(one) },
              { k: 'Propagation', v: fmtTime(prop), note: `${fmtInt(Math.round(km * factor))} km of cable path at ${fmtInt(speed)} km/s. Cables do not run straight — the route factor allows for that.` },
              { k: 'Serialization', v: fmtTime(ser), note: `${fmtInt(pkt)} bytes clocked onto a ${fmtRate(link)} link, at each of ${Math.max(1, hops)} hops. Matters on slow links, vanishes on fast ones.` },
              { k: 'Router processing', v: fmtTime(proc) },
              { k: 'Queuing', v: fmtTime(q), note: 'Time waiting behind other packets. Near zero on an idle line; hundreds of ms under bufferbloat.' },
            ] },
            { type: 'msg', tone: '', text: `Physics sets the floor: light in fiber covers about 200 km per millisecond, so ${fmtInt(Math.round(km))} km can never take less than ${round((km / speed) * 2000, 1)} ms there and back, however fast the line.` },
          ];
        },
      },
    ],
  });

  /* ---------- Wi-Fi ---------- */
  const BANDS = { '2.4': [2437, '2.4 GHz'], 5: [5500, '5 GHz'], 6: [6500, '6 GHz'] };
  const WALLS = [['drywall', 'Drywall', [3, 4, 5]], ['glass', 'Window glass', [2, 3, 4]], ['door', 'Wooden door', [3, 4, 5]], ['brick', 'Brick wall', [6, 10, 12]], ['concrete', 'Concrete wall', [12, 18, 22]], ['floor', 'Floor / ceiling', [15, 20, 24]]];
  const bandIdx = (b) => (b === '2.4' ? 0 : b === '5' ? 1 : 2);
  function rssiQuality(r) {
    if (r >= -50) return ['Excellent', 'ok'];
    if (r >= -60) return ['Very good', 'ok'];
    if (r >= -67) return ['Good — enough for voice and video', 'ok'];
    if (r >= -70) return ['Fair — browsing is fine, calls may stutter', 'warn'];
    if (r >= -80) return ['Weak — slow and unreliable', 'warn'];
    return ['Unusable', 'err'];
  }
  const PER_AP = { '2.4': { open: 230, typical: 140, dense: 90 }, 5: { open: 185, typical: 110, dense: 70 }, 6: { open: 150, typical: 90, dense: 55 } };
  function parseSurvey(out) {
    const aps = []; let ssid = '', cur = null;
    for (const line of out.split(/\r?\n/)) {
      let m;
      if ((m = line.match(/^SSID \d+\s*:\s*(.*)$/))) { ssid = m[1].trim(); continue; }
      if ((m = line.match(/^\s+BSSID \d+\s*:\s*(\S+)/))) { cur = { ssid, signal: 0, channel: 0, band: '' }; aps.push(cur); continue; }
      if (!cur) continue;
      if ((m = line.match(/^\s+Signal\s*:\s*(\d+)%/))) cur.signal = Number(m[1]);
      else if ((m = line.match(/^\s+Channel\s*:\s*(\d+)/))) cur.channel = Number(m[1]);
      else if ((m = line.match(/^\s+Band\s*:\s*([\d.]+)/))) cur.band = m[1];
    }
    return aps;
  }
  TOOLS.push({
    key: 'wifi', label: 'Wi-Fi', manual: 'nc-wifi',
    modes: [
      {
        key: 'signal', label: 'Signal strength',
        hint: 'Estimate the signal at a distance from an access point: transmit power and antenna gains, minus the free-space loss for that distance and band, minus what each wall and floor absorbs, minus a margin for furniture and people. A best-case estimate — measure to be sure.',
        fields: [
          { id: 'band', label: 'Band', type: 'select', def: '5', options: Object.entries(BANDS).map(([k, [, l]]) => [k, l]) },
          { id: 'tx', label: 'AP transmit power (dBm)', def: '20' }, { id: 'gap', label: 'AP antenna gain (dBi)', def: '4' }, { id: 'gcl', label: 'Device antenna gain (dBi)', def: '0' },
          { id: 'dist', label: 'Distance', def: '10' }, { id: 'unit', label: 'Unit', type: 'select', def: 'm', options: [['m', 'meters'], ['ft', 'feet']] },
          ...WALLS.map(([id, label]) => ({ id, label: `${label}s`, def: id === 'drywall' ? '2' : id === 'door' ? '1' : '0' })),
          { id: 'margin', label: 'Extra margin (dB)', def: '5' },
        ],
        compute(v) {
          const [f] = BANDS[v.band] || BANDS[5]; const bi = bandIdx(v.band);
          const tx = num(v.tx, 'Transmit power', { min: -10, max: 36 }), g1 = num(v.gap, 'AP antenna gain', { min: -5, max: 30 }), g2 = num(v.gcl, 'Device antenna gain', { min: -10, max: 20 });
          const d = Math.max(1, num(v.dist, 'Distance', { min: 0 }) * (v.unit === 'ft' ? 0.3048 : 1));
          let walls = 0; const wallParts = [];
          for (const [id, label, loss] of WALLS) { const n = num(v[id] || 0, label, { min: 0, max: 50, int: true }); if (n) { walls += n * loss[bi]; wallParts.push(`${n} × ${label.toLowerCase()} (${loss[bi]} dB)`); } }
          const margin = num(v.margin, 'Margin', { min: 0, max: 60 });
          const fspl = (dm) => 20 * Math.log10(dm) + 20 * Math.log10(f) - 27.55;
          const rssi = tx + g1 + g2 - fspl(d) - walls - margin;
          const [q, tone] = rssiQuality(rssi);
          const snr = rssi + 95;
          const pct = Math.max(0, Math.min(100, Math.round(2 * (rssi + 100))));
          const reach = 10 ** ((tx + g1 + g2 - walls - margin + 67 - 20 * Math.log10(f) + 27.55) / 20);
          const dists = [1, 3, 5, 10, 15, 20, 30, 50];
          const unit = v.unit === 'ft' ? 'ft' : 'm', k = v.unit === 'ft' ? 3.28084 : 1;
          return [
            { type: 'kv', rows: [
              { k: 'Signal at the device', v: `${round(rssi, 1)} dBm`, tone, note: q },
              { k: 'Windows shows about', v: `${pct}%`, note: 'Windows turns dBm into a percentage: roughly 2 × (dBm + 100).' },
              { k: 'Signal-to-noise', v: `${round(snr, 1)} dB`, note: 'Against a typical noise floor of −95 dBm. 25 dB or more is good; below 15 dB is poor.' },
              { k: 'Free-space loss', v: `${round(fspl(d), 1)} dB`, note: `${round(d * k, 1)} ${unit} at ${f} MHz: 20·log(distance) + 20·log(frequency) − 27.55.` },
              { k: 'Walls and floors', v: `${walls} dB`, note: wallParts.join(', ') || 'none' },
              { k: `Distance for −67 dBm`, v: `${round(reach * k, 1)} ${unit}`, note: 'How far the same walls allow before calls start to suffer.' },
            ] },
            { type: 'table', title: 'The same setup at other distances', columns: ['Distance', 'Signal', 'Quality'], rows: dists.map((x) => { const r = tx + g1 + g2 - fspl(x / k) - walls - margin; return [`${x} ${unit}`, `${round(r, 1)} dBm`, rssiQuality(r)[0]]; }) },
          ];
        },
      },
      {
        key: 'coverage', label: 'Coverage planner',
        hint: 'How many access points a space needs. Coverage uses planning figures per AP for the band and how many walls there are; capacity uses how many active devices one AP serves well. The bigger of the two is the answer.',
        fields: [
          { id: 'area', label: 'Floor area (per floor)', def: '200' }, { id: 'unit', label: 'Unit', type: 'select', def: 'm2', options: [['m2', 'm²'], ['ft2', 'ft²']] },
          { id: 'floors', label: 'Floors', def: '2' },
          { id: 'band', label: 'Main band', type: 'select', def: '5', options: Object.entries(BANDS).map(([k, [, l]]) => [k, l]) },
          { id: 'env', label: 'Building', type: 'select', def: 'typical', options: [['open', 'Open plan, few walls'], ['typical', 'Typical home or office'], ['dense', 'Many walls, brick or concrete']] },
          { id: 'users', label: 'Devices in use at once', def: '20' },
          { id: 'use', label: 'Main use', type: 'select', def: 'general', options: [['general', 'Browsing, email, streaming'], ['voice', 'Calls and video meetings'], ['dense', 'Many devices in one room']] },
        ],
        compute(v) {
          const k = v.unit === 'ft2' ? 0.09290304 : 1;
          const area = num(v.area, 'Floor area', { min: 1 }) * k, floors = num(v.floors, 'Floors', { min: 1, max: 100, int: true }), users = num(v.users, 'Devices', { min: 0, int: true });
          const per = (PER_AP[v.band] || PER_AP[5])[v.env] || 110;
          const perClient = { general: 30, voice: 20, dense: 15 }[v.use] || 30;
          const perFloor = Math.max(1, Math.ceil(area / per));
          const cov = perFloor * floors, cap = Math.max(1, Math.ceil(users / perClient));
          const n = Math.max(cov, cap);
          const spacing = Math.sqrt(per);
          const u = v.unit === 'ft2' ? 'ft' : 'm', f = v.unit === 'ft2' ? 3.28084 : 1;
          return [
            { type: 'kv', rows: [
              { k: 'Access points', v: String(n), tone: 'ok', note: n === cov ? 'Set by coverage.' : 'Set by capacity — more devices than the coverage count can serve well.' },
              { k: 'For coverage', v: `${cov} (${perFloor} per floor)`, note: `About ${fmtInt(Math.round(per * (v.unit === 'ft2' ? 10.7639 : 1)))} ${v.unit === 'ft2' ? 'ft²' : 'm²'} per AP on ${BANDS[v.band][1]} in this kind of building.` },
              { k: 'For capacity', v: String(cap), note: `About ${perClient} active devices per AP for this use.` },
              { k: 'Spacing', v: `about ${round(spacing * f, 0)} ${u} apart`, note: 'In a grid, with 15–20% overlap so devices can hand over between them.' },
            ] },
            { type: 'msg', tone: '', text: 'Placement: mount APs high and central, in the open (not in a cupboard or behind a TV), stagger them between floors rather than stacking them, and connect them by cable where you can — mesh backhaul over Wi-Fi halves the speed at each hop.' },
          ];
        },
      },
      {
        key: 'channel', label: 'Channel planner',
        hint: 'Pick the quietest channel. List the networks you can see as "channel signal%" per line — or read them from this PC — and each candidate channel is scored by how many neighbors overlap it and how strong they are.',
        fields: [
          { id: 'band', label: 'Band', type: 'select', def: '2.4', options: Object.entries(BANDS).map(([k, [, l]]) => [k, l]) },
          { id: 'dfs', label: 'Include DFS channels (5 GHz)', type: 'checkbox', def: false },
          { id: 'list', label: 'Neighboring networks — one per line: channel signal%', type: 'textarea', rows: 5, wide: true, def: '1 80\n6 45\n6 30\n11 70\n3 20' },
        ],
        actions: [{
          label: 'Read nearby networks', live: true, win: true, title: 'Fill the list from netsh wlan show networks mode=bssid',
          async run(api, v) {
            const out = await runCmd('netsh', {}, 'wlan-networks');
            if (/location permission|requires elevation/i.test(out)) bad('Windows is withholding the list of nearby networks: turn on Location services and "Let desktop apps access your location" (Settings › Privacy & security › Location).');
            const aps = parseSurvey(out);
            if (!aps.length) bad('No nearby networks were listed.');
            const inBand = aps.filter((a) => (v.band === '6' ? a.band.startsWith('6') : v.band === '5' ? a.channel >= 32 && !a.band.startsWith('6') : a.channel <= 14 && !a.band.startsWith('6')));
            api.set({ list: inBand.map((a) => `${a.channel} ${a.signal}   ${a.ssid || '(hidden)'}`).join('\n') || '' });
          },
        }],
        compute(v) {
          const nb = String(v.list || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l, i) => {
            const m = l.match(/^(\d+)[\s,;]+(\d+)/);
            if (!m) bad(`Line ${i + 1} ("${l}") should be "channel signal%", such as "6 45".`);
            return { ch: Number(m[1]), sig: Math.min(100, Number(m[2])) };
          });
          let cands, overlap;
          if (v.band === '2.4') { cands = [1, 6, 11]; overlap = (c, n) => (Math.abs(c - n) < 5 ? 1 - Math.abs(c - n) / 5 : 0); }
          else if (v.band === '5') {
            cands = [36, 40, 44, 48, ...(v.dfs ? [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144] : []), 149, 153, 157, 161, 165];
            const block = (c) => (c >= 149 ? Math.floor((c - 149) / 16) + 100 : Math.floor((c - 36) / 16));
            overlap = (c, n) => (c === n ? 1 : block(c) === block(n) ? 0.5 : 0);
          } else { cands = [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229]; overlap = (c, n) => (c === n ? 1 : Math.abs(c - n) < 16 ? 0.5 : 0); }
          const scored = cands.map((c) => { let s = 0, cnt = 0; for (const x of nb) { const o = overlap(c, x.ch); if (o > 0) { cnt++; s += o * (x.sig / 100); } } return { c, s, cnt }; });
          const best = [...scored].sort((a, b) => a.s - b.s || a.c - b.c)[0];
          const width = v.band === '2.4' ? '20 MHz — always, on 2.4 GHz; 40 MHz there overlaps everyone' : best.s < 0.3 ? `80 MHz${v.band === '6' ? ' or 160 MHz' : ''} — the block is quiet` : '40 MHz, or 20 MHz if it stays busy';
          return [
            { type: 'kv', rows: [
              { k: 'Best channel', v: String(best.c), tone: 'ok', note: `${best.cnt} overlapping network${best.cnt === 1 ? '' : 's'}, interference score ${round(best.s, 2)}.${v.band === '2.4' ? ' Only 1, 6 and 11 do not overlap each other on 2.4 GHz — never pick one in between.' : ''}` },
              { k: 'Channel width', v: width },
              ...(v.band === '6' ? [{ k: 'Note', v: 'Preferred scanning channels', note: 'On 6 GHz, devices look for networks on these channels first (PSC), so stay on one of them.' }] : []),
            ] },
            { type: 'table', title: 'Candidates, quietest first', columns: ['Channel', 'Overlapping networks', 'Score'], rows: [...scored].sort((a, b) => a.s - b.s || a.c - b.c).map((x) => [String(x.c), String(x.cnt), String(round(x.s, 2))]) },
          ];
        },
      },
    ],
  });

  /* ---------- Security ---------- */
  TOOLS.push({
    key: 'security', label: 'Security', manual: 'nc-security',
    modes: [
      {
        key: 'cert', label: 'Certificate expiry',
        hint: 'How long a TLS certificate has left and when to renew it. Enter the dates from the certificate, or a host name and "Check live" to read them from the site. Renew when a third of the lifetime remains, as automated tools do.',
        fields: [
          { id: 'host', label: 'Host (for Check live)', def: 'example.com' },
          { id: 'from', label: 'Valid from', type: 'date', def: () => isoDate(addDays(today(), -45)) },
          { id: 'to', label: 'Valid until', type: 'date', def: () => isoDate(addDays(today(), 45)) },
        ],
        actions: [{
          label: 'Check live', live: true, title: 'Connect to the host on port 443 and read its certificate',
          async run(api, v) {
            const host = String(v.host || '').trim();
            if (!/^[A-Za-z0-9.-]+$/.test(host)) bad('Enter a host name such as example.com.');
            const out = await runCmd('tls-cert', { host });
            const get = (k) => ((out.match(new RegExp(`^\\s*${k}\\s*:\\s*(.+)$`, 'm')) || [])[1] || '').trim();
            if (!get('ValidTo')) bad(`Could not read a certificate from ${host}: ${(out.match(/Exception calling[^\r\n]*/) || ['no answer on port 443'])[0].slice(0, 140)}`);
            api.note = `${get('Subject')} — issued by ${get('Issuer')}`;
            api.set({ from: get('ValidFrom'), to: get('ValidTo') });
          },
        }],
        compute(v, api) {
          const from = new Date(`${v.from}T00:00:00`), to = new Date(`${v.to}T00:00:00`);
          if (isNaN(from) || isNaN(to)) bad('Enter both dates.');
          if (to <= from) bad('"Valid until" must be after "Valid from".');
          const day = 86400000, now = today();
          const life = Math.round((to - from) / day), left = Math.round((to - now) / day), used = Math.min(100, Math.max(0, ((now - from) / (to - from)) * 100));
          const renew = addDays(to, -Math.round(life / 3));
          const limit = from >= new Date('2029-03-15') ? 47 : from >= new Date('2027-03-15') ? 100 : from >= new Date('2026-03-15') ? 200 : 398;
          const tone = left < 0 ? 'err' : now >= renew ? 'warn' : 'ok';
          const rows = [
            { k: 'Days left', v: left < 0 ? `expired ${-left} days ago` : `${left} days`, tone, note: left < 0 ? 'Browsers refuse the site until it is renewed.' : now >= renew ? 'Inside the renewal window — renew now.' : 'Fine for now.' },
            { k: 'Renew by', v: isoDate(renew), note: 'When a third of the lifetime remains — what automated renewal (ACME, Let\'s Encrypt) does, leaving time to retry.' },
            { k: 'Lifetime', v: `${life} days`, note: life > limit ? `Longer than public CAs may issue for a certificate from that date (${limit} days) — probably a private or internal CA.` : `Public CAs may issue at most ${limit} days for a certificate from that date.` },
            { k: 'Lifetime used', v: `${round(used, 0)}%` },
          ];
          if (api.note) rows.unshift({ k: 'Certificate', v: api.note });
          return [{ type: 'kv', rows }, { type: 'msg', tone: '', text: 'Public certificate lifetimes are shrinking by industry rule (CA/Browser Forum): at most 398 days until March 2026, 200 days from 15 March 2026, 100 days from 15 March 2027 and 47 days from 15 March 2029. Automate renewal if you have not already.' }];
        },
      },
      {
        key: 'password', label: 'Password strength',
        hint: 'How long a password would hold out against guessing. It is estimated here in the page, never stored and never sent anywhere — but prefer to test a password shaped like yours rather than the real one.',
        fields: [
          { id: 'pw', label: 'Password', type: 'password', def: '', persist: false, secret: true, span2: true, placeholder: 'type or paste' },
          { id: 'show', label: 'Show it', type: 'checkbox', def: false, persist: false },
        ],
        compute(v) {
          if (!v.pw) return [{ type: 'msg', tone: '', text: 'Type a password to see an estimate. Nothing you type here leaves this page or is kept.' }];
          const { bits, pool, notes } = passwordBits(v.pw);
          const rates = [['Online, rate-limited (10 guesses a second)', 10], ['Offline, slow hash such as bcrypt (10,000 a second)', 1e4], ['Offline, fast hash such as NTLM or MD5 (100 billion a second)', 1e11]];
          const rating = bits < 28 ? ['Very weak', 'err'] : bits < 36 ? ['Weak', 'err'] : bits < 60 ? ['Reasonable', 'warn'] : bits < 128 ? ['Strong', 'ok'] : ['Very strong', 'ok'];
          return [
            { type: 'kv', rows: [
              { k: 'Rating', v: rating[0], tone: rating[1] },
              { k: 'Estimated entropy', v: `${round(bits, 0)} bits`, note: `Each bit doubles the guesses needed. ${v.pw.length} characters from a pool of about ${pool}${notes.length ? `, reduced because ${notes.join(', ')}` : ''}.` },
            ] },
            { type: 'table', title: 'Average time to guess it', columns: ['Attacker', 'Time'], rows: rates.map(([l, r]) => [l, fmtTime(2 ** (bits - 1) / r)]) },
            { type: 'msg', tone: '', text: 'Length beats cleverness: four or five random words make a password that is both strong and easy to type. Use a password manager so every site gets a different one, and turn on two-factor sign-in wherever it is offered.' },
          ];
        },
      },
      {
        key: 'hash', label: 'Hash & checksum',
        hint: 'Compute the checksums a download page lists, from text or a file, and compare them with the published value. The file is read here in the page; it is not uploaded.',
        fields: [
          { id: 'text', label: 'Text (or pick a file below)', type: 'textarea', rows: 3, wide: true, def: '', persist: false, secret: true },
          { id: 'file', label: 'File', type: 'file', span2: true },
          { id: 'cmp', label: 'Expected value', def: '', persist: false, span2: true, placeholder: 'optional — paste the published hash' },
        ],
        async compute(v) {
          const f = files[`security/hash/file`];
          let bytes, what;
          if (f) { if (f.size > 1024 ** 3) bad('That file is larger than 1 GB — too big to hash inside the page.'); bytes = new Uint8Array(await f.arrayBuffer()); what = `${f.name} (${fmtBytes(f.size)})`; }
          else { bytes = new TextEncoder().encode(String(v.text || '')); what = `text, ${fmtInt(bytes.length)} bytes (UTF-8)`; }
          const rows = [{ k: 'Input', v: what }];
          const add = (name, value, note) => rows.push({ k: name, v: value, note });
          add('MD5', md5(bytes), 'Broken for security — fine only for spotting accidental corruption.');
          add('CRC32', crc32(bytes), 'A checksum, not a hash: catches transmission errors, not tampering.');
          if (window.crypto && crypto.subtle) {
            for (const [alg, note] of [['SHA-1', 'Deprecated for security (collisions found in 2017).'], ['SHA-256', 'The usual choice for verifying downloads.'], ['SHA-384', ''], ['SHA-512', '']]) add(alg, toHex(new Uint8Array(await crypto.subtle.digest(alg, bytes))), note);
          } else rows.push({ k: 'SHA', v: 'needs a secure page (https or localhost)', tone: 'warn' });
          const want = String(v.cmp || '').trim().toLowerCase().replace(/[^0-9a-f]/g, '');
          if (want) {
            const hit = rows.find((r) => r.v === want);
            rows.forEach((r) => { if (r === hit) r.tone = 'ok'; });
            rows.push({ k: 'Match', v: hit ? `Yes — matches ${hit.k}` : 'No — matches none of these', tone: hit ? 'ok' : 'err', note: hit ? 'The data is identical to what was published.' : 'The file differs from the published one, or the expected value is for a different algorithm.' });
          }
          return [{ type: 'kv', rows }];
        },
      },
    ],
  });

  /* ---------- Planning ---------- */
  TOOLS.push({
    key: 'planning', label: 'Planning', manual: 'nc-planning',
    modes: [
      {
        key: 'rack', label: 'Rack & power',
        hint: 'Size a rack and its power: list the equipment one per line as "name, height in U, watts, quantity". You get the rack space used, the current drawn, the heat to remove and the UPS to buy.',
        fields: [
          { id: 'rack', label: 'Rack size', type: 'select', def: '12', options: ['6', '9', '12', '15', '18', '22', '24', '27', '32', '42', '45', '48'].map((u) => [u, `${u}U`]) },
          { id: 'volts', label: 'Voltage', type: 'select', def: '120', options: [['120', '120 V'], ['208', '208 V'], ['230', '230 V']] },
          { id: 'amps', label: 'Circuit', type: 'select', def: '15', options: [['10', '10 A'], ['15', '15 A'], ['16', '16 A'], ['20', '20 A'], ['30', '30 A'], ['32', '32 A']] },
          { id: 'pf', label: 'Power factor', def: '0.9' }, { id: 'headroom', label: 'UPS headroom %', def: '25' }, { id: 'wh', label: 'UPS battery (Wh)', def: '', placeholder: 'optional' },
          { id: 'devs', label: 'Equipment — name, U, watts, quantity', type: 'textarea', rows: 5, wide: true, def: 'Firewall, 1, 40, 1\nSwitch 24-port PoE, 1, 370, 1\nPatch panel, 1, 0, 2\nNAS, 2, 60, 1\nUPS, 2, 30, 1' },
        ],
        compute(v) {
          const devs = String(v.devs || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l, i) => {
            const p = l.split(/\s*[,;\t]\s*/);
            if (p.length < 3) bad(`Line ${i + 1} ("${l}") should be "name, U, watts" (and optionally a quantity).`);
            return { name: p[0], u: num(p[1], `Line ${i + 1} height`, { min: 0, max: 60 }), w: num(p[2], `Line ${i + 1} watts`, { min: 0 }), q: p[3] ? num(p[3], `Line ${i + 1} quantity`, { min: 1, int: true }) : 1 };
          });
          const U = devs.reduce((a, d) => a + d.u * d.q, 0), W = devs.reduce((a, d) => a + d.w * d.q, 0);
          const rack = Number(v.rack), V = Number(v.volts), A = Number(v.amps);
          const pf = num(v.pf, 'Power factor', { min: 0.5, max: 1 }), hr = num(v.headroom, 'Headroom', { min: 0, max: 200 }) / 100;
          const amps = W / V, load = (amps / A) * 100;
          const va = (W / pf) * (1 + hr);
          const vaStd = [500, 750, 1000, 1500, 2200, 3000, 5000, 6000, 8000, 10000].find((x) => x >= va);
          const wh = String(v.wh || '').trim() ? num(v.wh, 'Battery', { min: 1 }) : null;
          return [
            { type: 'kv', rows: [
              { k: 'Rack space', v: `${U}U of ${rack}U`, tone: U > rack ? 'err' : U > rack * 0.8 ? 'warn' : 'ok', note: U > rack ? `${U - rack}U short — a bigger rack is needed.` : `${rack - U}U free${U > rack * 0.8 ? ' — leave room for growth and airflow' : ''}. 1U = 1.75 in (44.45 mm).` },
              { k: 'Power', v: `${fmtInt(W)} W`, note: 'Sum of the watts you entered — use the typical draw, not the nameplate maximum, for sizing batteries.' },
              { k: 'Current', v: `${round(amps, 2)} A at ${V} V`, tone: load > 80 ? 'err' : load > 60 ? 'warn' : 'ok', note: `${round(load, 0)}% of a ${A} A circuit. Keep continuous load at or below 80% (${round(A * 0.8, 1)} A).` },
              { k: 'Heat', v: `${fmtInt(Math.round(W * 3.412))} BTU/h`, note: 'Nearly every watt ends up as heat: watts × 3.412. A closet needs ventilation beyond a few hundred watts.' },
              { k: 'UPS size', v: vaStd ? `${fmtInt(vaStd)} VA or larger` : `${fmtInt(Math.ceil(va))} VA`, note: `${fmtInt(W)} W ÷ power factor ${pf} + ${Math.round(hr * 100)}% headroom = ${fmtInt(Math.ceil(va))} VA.` },
              ...(wh ? [{ k: 'Battery runtime', v: fmtTime((wh * 0.9 / Math.max(W, 1)) * 3600), note: `${fmtInt(wh)} Wh × 90% inverter efficiency ÷ ${fmtInt(W)} W. Batteries give less at high load and as they age.` }] : []),
            ] },
            { type: 'table', title: 'Equipment', columns: ['Item', 'Qty', 'U', 'Watts'], rows: devs.map((d) => [d.name, String(d.q), String(d.u * d.q), fmtInt(d.w * d.q)]) },
          ];
        },
      },
      {
        key: 'api', label: 'API rate limit',
        hint: 'Plan calls against an API that allows a number of requests per time window: the safe pace, the gap to leave between requests, and how long a batch will take. The margin keeps you clear of the limit when clocks and counters disagree.',
        fields: [
          { id: 'limit', label: 'Requests allowed', def: '100' }, { id: 'per', label: 'Per', def: '1' },
          { id: 'unit', label: 'Window', type: 'select', def: '60', options: [['1', 'second(s)'], ['60', 'minute(s)'], ['3600', 'hour(s)'], ['86400', 'day(s)']] },
          { id: 'total', label: 'Requests to make', def: '5000' }, { id: 'margin', label: 'Safety margin %', def: '10' },
        ],
        compute(v) {
          const limit = num(v.limit, 'Requests allowed', { min: 1 }), win = num(v.per, 'Per', { min: 0.001 }) * Number(v.unit);
          const total = num(v.total, 'Requests to make', { min: 1, int: true }), m = num(v.margin, 'Margin', { min: 0, max: 90 }) / 100;
          const rate = limit / win, safe = rate * (1 - m);
          const t = total / safe;
          return [
            { type: 'kv', rows: [
              { k: 'Allowed rate', v: `${round(rate, rate < 1 ? 3 : 1)} per second`, note: `${fmtInt(Math.floor(rate * 60))} a minute · ${fmtInt(Math.floor(rate * 3600))} an hour · ${fmtInt(Math.floor(rate * 86400))} a day.` },
              { k: 'Safe pace', v: `${round(safe, safe < 1 ? 3 : 1)} per second`, tone: 'ok', note: `${Math.round(m * 100)}% below the limit.` },
              { k: 'Gap between requests', v: fmtTime(1 / safe), note: 'Space requests this far apart and you never hit the limit.' },
              { k: 'Time for the batch', v: fmtTime(t), note: total <= limit ? `The batch fits in one window, so it can also be sent in a burst of ${fmtInt(total)} — if the API counts a fixed window rather than a rolling one.` : `${fmtInt(Math.ceil(total / limit))} windows' worth of requests.` },
            ] },
            { type: 'msg', tone: '', text: 'When an API answers 429 Too Many Requests, wait for the time in its Retry-After header before trying again, and back off exponentially if it keeps happening.' },
          ];
        },
      },
      {
        key: 'wan', label: 'WAN optimization',
        hint: 'Estimate what a WAN optimizer would save between two sites: data reduction (compression plus deduplication) shrinks the bytes sent, and protocol acceleration removes most of the round trips a chatty protocol such as SMB makes over a long link.',
        fields: [
          { id: 'link', label: 'Link speed (Mbit/s)', def: '50' }, { id: 'rtt', label: 'Round-trip time (ms)', def: '60' },
          { id: 'size', label: 'Data per transfer (MB)', def: '20' }, { id: 'perday', label: 'Transfers per day', def: '200' },
          { id: 'reduce', label: 'Data reduction %', def: '50' }, { id: 'trips', label: 'Round trips per transfer', def: '40' }, { id: 'accel', label: 'Round trips removed %', def: '80' },
        ],
        compute(v) {
          const link = num(v.link, 'Link speed', { min: 0.01 }) * 1e6, rtt = num(v.rtt, 'Round-trip time', { min: 0 }) / 1000, mb = num(v.size, 'Data per transfer', { min: 0 }) * 1e6;
          const per = num(v.perday, 'Transfers per day', { min: 0 }), red = num(v.reduce, 'Data reduction', { min: 0, max: 99 }) / 100, trips = num(v.trips, 'Round trips', { min: 0 }), acc = num(v.accel, 'Round trips removed', { min: 0, max: 100 }) / 100;
          const before = trips * rtt + (mb * 8) / link, after = trips * (1 - acc) * rtt + (mb * (1 - red) * 8) / link;
          return [
            { type: 'kv', rows: [
              { k: 'Time per transfer', v: `${fmtTime(before)} → ${fmtTime(after)}`, tone: 'ok', note: `${round(before / Math.max(after, 1e-9), 1)}× faster.` },
              { k: 'Of which waiting on round trips', v: `${fmtTime(trips * rtt)} → ${fmtTime(trips * (1 - acc) * rtt)}`, note: 'Latency cost does not shrink with a faster link — only with fewer round trips.' },
              { k: 'Data per day', v: `${fmtBytes(mb * per)} → ${fmtBytes(mb * per * (1 - red))}`, note: `${fmtBytes(mb * per * red)} a day not sent.` },
              { k: 'Link time per day', v: `${fmtTime(before * per)} → ${fmtTime(after * per)}` },
            ] },
            { type: 'msg', tone: '', text: 'Real reduction depends on the data: repeated office files and backups deduplicate well, already-compressed media and encrypted traffic barely at all.' },
          ];
        },
      },
    ],
  });

  /* ================= engine: build, read, compute, render ================= */
  const toolOf = (k) => TOOLS.find((t) => t.key === k) || TOOLS[0];
  const modeOf = (t) => t.modes.find((m) => m.key === state.modes[t.key]) || t.modes[0];
  const vkey = (t, m) => `${t.key}/${m.key}`;
  const defOf = (f) => (typeof f.def === 'function' ? f.def() : f.def ?? '');

  function init(deps) {
    D = deps;
    els = { modal: D.$('calc-modal'), tabs: D.$('calc-tabs'), modes: D.$('calc-modes'), hint: D.$('calc-hint'), fields: D.$('calc-fields'), actions: D.$('calc-actions'), out: D.$('calc-out'), book: D.$('calc-manual') };
    if (!els.modal) return;
    els.tabs.innerHTML = TOOLS.map((t) => `<button type="button" class="vtab" role="tab" data-tool="${t.key}">${esc(t.label)}</button>`).join('');
    els.tabs.addEventListener('click', (e) => { const b = e.target.closest('[data-tool]'); if (b) { state.tool = b.dataset.tool; save(); render(); } });
    els.modes.addEventListener('click', (e) => { const b = e.target.closest('[data-mode]'); if (b) { state.modes[state.tool] = b.dataset.mode; save(); render(); } });
    // only the ✕ closes it — clicking outside, pressing Esc or switching windows leaves it open with its inputs
    D.$('calc-close').addEventListener('click', close);
    D.$('calc-copy').addEventListener('click', copyResults);
    D.$('calc-save').addEventListener('click', saveReport);
    els.explain = D.$('calc-explain');
    els.explain.addEventListener('click', () => { state.explain = !state.explain; save(); showExplain(); });
    showExplain();
    els.book.innerHTML = D.bookSvg || '';
    els.book.addEventListener('click', () => { const t = toolOf(state.tool); if (D.openDoc) D.openDoc('manual.html', t.manual); });
  }

  function open(tool, mode, values) {
    if (!els || !els.modal) return;
    if (tool && TOOLS.some((t) => t.key === tool)) state.tool = tool;
    if (mode) state.modes[state.tool] = mode;
    if (values) { const t = toolOf(state.tool), m = modeOf(t); state.vals[vkey(t, m)] = { ...(state.vals[vkey(t, m)] || {}), ...values }; }
    save();
    els.modal.hidden = false;
    render();
    const first = els.fields.querySelector('input:not([type=checkbox]):not([type=file]), textarea, select');
    if (first) first.focus();
  }
  function close() { if (els && els.modal) els.modal.hidden = true; }
  const isOpen = () => Boolean(els && els.modal && !els.modal.hidden);

  function render() {
    const t = toolOf(state.tool), m = modeOf(t);
    els.tabs.querySelectorAll('[data-tool]').forEach((b) => { const on = b.dataset.tool === t.key; b.classList.toggle('is-active', on); b.setAttribute('aria-selected', String(on)); });
    els.modes.hidden = t.modes.length < 2;
    els.modes.innerHTML = t.modes.map((x) => `<button type="button" class="chip${x.key === m.key ? ' is-active' : ''}" data-mode="${x.key}">${esc(x.label)}</button>`).join('');
    els.hint.textContent = m.hint || '';
    els.book.title = `Open the manual at ${t.label}`;
    const saved = state.vals[vkey(t, m)] || {};
    els.fields.innerHTML = '';
    for (const f of m.fields) {
      const wrap = document.createElement('label');
      wrap.className = `calc-field${f.wide ? ' wide' : ''}${f.span2 ? ' span2' : ''}${f.type === 'checkbox' ? ' check' : ''}`;
      const val = f.persist !== false && f.id in saved ? saved[f.id] : defOf(f);
      let input;
      if (f.type === 'select') { input = document.createElement('select'); input.innerHTML = f.options.map(([ov, ol]) => `<option value="${esc(ov)}">${esc(ol)}</option>`).join(''); input.value = String(val); }
      else if (f.type === 'textarea') { input = document.createElement('textarea'); input.rows = f.rows || 4; input.value = val; input.spellcheck = false; }
      else if (f.type === 'checkbox') { input = document.createElement('input'); input.type = 'checkbox'; input.checked = Boolean(val); }
      else if (f.type === 'file') { input = document.createElement('input'); input.type = 'file'; }
      else {
        input = document.createElement('input');
        input.type = f.type === 'password' ? 'password' : f.type === 'date' ? 'date' : 'text';
        input.value = val; input.spellcheck = false; input.autocomplete = 'off';
        if (f.placeholder) input.placeholder = f.placeholder;
        if (f.list) { const id = `calc-list-${t.key}-${f.id}`; const dl = document.createElement('datalist'); dl.id = id; dl.innerHTML = f.list().map(([ov, ol]) => `<option value="${esc(ov)}">${esc(ol)}</option>`).join(''); wrap.appendChild(dl); input.setAttribute('list', id); }
      }
      input.dataset.field = f.id;
      const span = document.createElement('span'); span.textContent = f.label;
      if (f.type === 'checkbox') { wrap.append(input, span); } else { wrap.append(span, input); }
      if (f.type === 'file') {
        const key = `${t.key}/${m.key}/${f.id}`;
        const clear = document.createElement('button'); clear.type = 'button'; clear.className = 'tbtn tbtn-sm'; clear.textContent = 'Clear file'; clear.hidden = !files[key];
        input.addEventListener('change', () => { files[key] = input.files && input.files[0] ? input.files[0] : null; clear.hidden = !files[key]; recompute(); });
        clear.addEventListener('click', (e) => { e.preventDefault(); files[key] = null; input.value = ''; clear.hidden = true; recompute(); });
        wrap.appendChild(clear);
      } else {
        const ev = f.type === 'select' || f.type === 'checkbox' || f.type === 'date' ? 'change' : 'input';
        input.addEventListener(ev, () => { if (f.id === 'show' && m.key === 'password') { const pw = els.fields.querySelector('[data-field="pw"]'); if (pw) pw.type = input.checked ? 'text' : 'password'; } schedule(); });
      }
      els.fields.appendChild(wrap);
    }
    els.actions.innerHTML = '';
    const acts = (m.actions || []).filter((a) => (!a.live || live()) && (!a.win || !D.isWin || D.isWin()));
    els.actions.hidden = !acts.length;
    for (const a of acts) {
      const b = document.createElement('button'); b.type = 'button'; b.className = a.live ? 'run-btn' : 'tbtn'; b.textContent = a.label; if (a.title) b.title = a.title;
      b.addEventListener('click', async () => {
        b.disabled = true; const txt = b.textContent; b.textContent = a.live ? 'Reading…' : txt;
        try {
          m._note = '';
          await a.run({ set: (vals) => setFields(vals), get note() { return m._note; }, set note(x) { m._note = x; } }, readFields(m));
        } catch (e) { showOut([{ type: 'msg', tone: 'err', text: e.message || String(e) }]); }
        b.disabled = false; b.textContent = txt;
      });
      els.actions.appendChild(b);
    }
    // with only short inputs, the buttons take the next cell of the input grid instead of a row of their own
    const inline = acts.length > 0 && !m.fields.some((f) => f.wide || f.type === 'textarea');
    if (inline) els.fields.appendChild(els.actions); else els.fields.after(els.actions);
    els.actions.classList.toggle('inline', inline);
    m._note = '';
    recompute();
  }

  function readFields(m) {
    const v = {};
    els.fields.querySelectorAll('[data-field]').forEach((el) => { v[el.dataset.field] = el.type === 'checkbox' ? el.checked : el.type === 'file' ? '' : el.value; });
    return v;
  }
  function setFields(vals) {
    for (const [k, val] of Object.entries(vals)) { const el = els.fields.querySelector(`[data-field="${k}"]`); if (!el) continue; if (el.type === 'checkbox') el.checked = Boolean(val); else el.value = val; }
    recompute();
  }
  let timer = null;
  function schedule() { clearTimeout(timer); timer = setTimeout(recompute, 120); }

  async function recompute() {
    const t = toolOf(state.tool), m = modeOf(t);
    const v = readFields(m);
    const keep = {};
    for (const f of m.fields) if (f.persist !== false && f.type !== 'file') keep[f.id] = v[f.id];
    state.vals[vkey(t, m)] = keep; save();
    const my = ++seq;
    let out;
    try { out = await m.compute(v, { note: m._note || '' }); }
    catch (e) { out = [{ type: 'msg', tone: 'err', text: e instanceof Bad ? e.message : `Something went wrong: ${e.message || e}` }]; }
    if (my !== seq) return;
    last = { tool: t, mode: m, v, out };
    showOut(out);
  }

  function showExplain() {
    els.out.classList.toggle('explain', !!state.explain);
    els.explain.setAttribute('aria-pressed', String(!!state.explain));
    els.explain.textContent = state.explain ? 'Hide explanations' : 'Show explanations';
  }

  function showOut(out) {
    // groups of values, and tables narrow enough for half the width, share two columns; one with no neighbor to
    // share with spans the width instead (a group of values then splits its own rows over the two columns)
    const narrow = (b) => b.type === 'table' && b.columns.reduce((w, c, i) => w + 26 + 7.6 * Math.max(String(c).length, ...b.rows.map((r) => String(r[i] ?? '').length)), 0) <= 430;
    const col = (b) => !!b && ((b.type === 'kv' && !b.span) || narrow(b));
    out.forEach((b, i) => { b.alone = col(b) && !col(out[i - 1]) && !col(out[i + 1]); });
    els.out.innerHTML = out.map((b) => {
      const title = b.title ? `<h3 class="calc-sub">${esc(b.title)}</h3>` : '';
      if (b.type === 'msg') return `<p class="calc-msg calc-block span" data-tone="${esc(b.tone || '')}">${esc(b.text)}</p>`;
      if (b.type === 'kv') return `<section class="calc-block${b.span || b.alone ? ' span' : ''}">${title}<div class="calc-kv">${b.rows.map((r) => { const tip = r.note ? ` title="${esc(r.note)}"` : ''; return `<div class="calc-row"><div class="calc-k"${tip}>${esc(r.k)}</div><div class="calc-v"${r.tone ? ` data-tone="${esc(r.tone)}"` : ''}${tip}>${r.html || esc(r.v)}</div>${r.note ? `<div class="calc-note">${esc(r.note)}</div>` : ''}</div>`; }).join('')}</div></section>`;
      if (b.type === 'table') return `<section class="calc-block${narrow(b) && !b.alone ? '' : ' span'}">${title}<div class="calc-tablewrap"><table class="data-table calc-table"><thead><tr>${b.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div></section>`;
      return '';
    }).join('');
  }

  /* ================= copy and report ================= */
  function inputsText(t, m, v) {
    return m.fields.filter((f) => !f.secret && f.type !== 'file' && f.id !== 'show').map((f) => {
      let val = v[f.id];
      if (f.type === 'select') { const o = f.options.find(([ov]) => String(ov) === String(val)); val = o ? o[1] : val; }
      if (f.type === 'checkbox') val = val ? 'yes' : 'no';
      return [f.label, String(val ?? '')];
    }).filter(([, val]) => val !== '');
  }
  function asText() {
    if (!last) return '';
    const { tool, mode, v, out } = last;
    const lines = [`NetDeck network calculator — ${tool.label}${tool.modes.length > 1 ? ` · ${mode.label}` : ''}`, ''];
    for (const [k, val] of inputsText(tool, mode, v)) lines.push(`${k}: ${val.replace(/\n/g, ' | ')}`);
    lines.push('');
    for (const b of out) {
      if (b.title) lines.push(`== ${b.title} ==`);
      if (b.type === 'msg') lines.push(b.text);
      if (b.type === 'kv') for (const r of b.rows) lines.push(`${r.k}: ${r.v}`);
      if (b.type === 'table') { lines.push(b.columns.join('\t')); for (const r of b.rows) lines.push(r.join('\t')); }
      lines.push('');
    }
    return lines.join('\n').trim() + '\n';
  }
  async function copyResults() {
    const btn = D.$('calc-copy');
    try { await navigator.clipboard.writeText(asText()); btn.textContent = 'Copied'; } catch (e) { btn.textContent = 'Copy failed'; }
    setTimeout(() => { btn.textContent = 'Copy results'; }, 1400);
  }
  function saveReport() {
    if (!last) return;
    const { tool, mode, v, out } = last;
    const title = `${tool.label}${tool.modes.length > 1 ? ` · ${mode.label}` : ''}`;
    const body = out.map((b) => {
      const h = b.title ? `<h2>${esc(b.title)}</h2>` : '';
      if (b.type === 'msg') return `<p class="note">${esc(b.text)}</p>`;
      if (b.type === 'kv') return `${h}<table>${b.rows.map((r) => `<tr><th>${esc(r.k)}</th><td class="v">${esc(r.v)}</td><td class="n">${esc(r.note || '')}</td></tr>`).join('')}</table>`;
      if (b.type === 'table') return `${h}<table><tr>${b.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</table>`;
      return '';
    }).join('\n');
    const inputs = inputsText(tool, mode, v).map(([k, val]) => `<tr><th>${esc(k)}</th><td class="v" colspan="2">${esc(val).replace(/\n/g, '<br>')}</td></tr>`).join('');
    const when = new Date();
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)} — NetDeck calculator</title>
<style>body{font:14px/1.5 system-ui,Segoe UI,sans-serif;color:#1e221e;max-width:960px;margin:32px auto;padding:0 20px}h1{font-size:21px;margin:0 0 4px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#666;margin:24px 0 6px}.meta{color:#666;font-size:13px}table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0}th,td{border:1px solid #dfe3df;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f3f5f3;font-weight:600;white-space:nowrap}.v{font-family:ui-monospace,Consolas,monospace}.n{color:#666;font-size:12.5px}.note{background:#f4f6f4;border-left:3px solid #8fb896;padding:8px 12px}.print{float:right;font:13px system-ui;padding:6px 12px;border:1px solid #b6bab6;border-radius:6px;background:#fff;cursor:pointer}@media print{.print{display:none}}</style></head><body>
<button class="print" onclick="window.print()">Print / save as PDF</button>
<h1>${esc(title)}</h1><div class="meta">${esc(when.toLocaleString())} · NetDeck ${esc(window.NETDECK_VERSION || '')} network calculator</div>
<h2>Inputs</h2><table>${inputs}</table>
${body}
</body></html>`;
    D.saveFile(`netdeck-calc-${tool.key}-${mode.key}-${when.toISOString().replace(/[:T]/g, '-').slice(0, 19)}.html`, html, 'text/html');
  }

  return { init, open, close, isOpen, TOOLS, _test: { ip4, parseMask, parse6, fmt6, md5, crc32, rangeToCidrs, passwordBits, fitPrefix } };
})();
