/* NetDeck playbooks: ordered diagnostic sequences with per-step checks and a verdict.

   STEP fields
     id         name used to look the result up in the verdict / in `when` (R.id)
     cmd        command id from commands.json          preset   variant key of that command (optional)
     params     values for the command; templates may use playbook inputs {host}, context
                {gateway} {dns0} {dns1} {ip} {adapter} {hostname}, or values captured by earlier steps
     check      name of a CHECK below                  table    offer a Table view of this step's output
     when       (R, params, ctx) => boolean — run only if true (otherwise shown as "not needed")
     skipIf     (params) => boolean — older form of `when`
     stopOnFail a failure here ends the run; later steps are marked "not run"
     warnMs     latency threshold for the ping check

   CHECK signature: (output, params, ctx, meta) => { status, summary, data?, capture? }
     status  pass | warn | fail | info (worth reading, not a fault)
     meta    { durationMs, exitCode, step }
     capture values made available to later steps' params as {name}

   VERDICT signature: (results[], params, ctx, R) => { tone, text, actions? }
     actions [{ label, playbook }] run another playbook · [{ label, copy }] copy text · [{ label, command, params }] jump to a card */
window.NetDeckPlaybooks = (() => {
  const P = window.NetDeckParsers;
  const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  const IP_ANY = /(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*)/gi;

  const secs = (ms) => (ms == null ? '' : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
  const ok = (r) => r && (r.status === 'pass' || r.status === 'warn' || r.status === 'info');
  const failed = (r) => r && r.status === 'fail';
  const warned = (r) => r && r.status === 'warn';

  function classifyIp(ip) {
    if (!IPV4.test(ip)) return 'public';
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)) return 'private';
    if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
    if (a === 169 && b === 254) return 'apipa';
    return 'public';
  }

  /* Shared nslookup reader (Windows and Unix formats). */
  function readNslookup(out) {
    const server = (out.match(/Address:\s+(\S+)/) || [])[1]?.replace(/#\d+$/, '');
    const block = out.split(/^\s*Name:/m).slice(1).join('\n');
    const answers = [...new Set((block.match(IP_ANY) || []).filter((a) => a.length > 3))];
    return {
      server,
      answers,
      nxdomain: /Non-existent domain|NXDOMAIN/i.test(out),
      timedOut: /timed out|no response from server|no servers could be reached/i.test(out),
      refused: /query refused|REFUSED/i.test(out),
    };
  }

  const CHECKS = {
    /* Looks at YOUR adapter (from the detected context), not the first address found anywhere:
       virtual adapters (Hyper-V, Docker, VPN) otherwise mask a dead real one. */
    ipconfig(out, params, ctx) {
      if (ctx?.platform && ctx.platform !== 'win32') {
        const inets = (out.match(/inet (?:addr:)?(\d{1,3}(?:\.\d{1,3}){3})/g) || []).map((m) => m.match(/(\d{1,3}(?:\.\d{1,3}){3})/)[1]);
        const real = inets.filter((ip) => !ip.startsWith('127.') && !ip.startsWith('169.254.'));
        if (!real.length) return { status: 'fail', summary: 'No routable IPv4 address on any interface' };
        if (!ctx.gateway) return { status: 'fail', summary: `IPv4 ${ctx.ip || real[0]} but no default route` };
        return { status: 'pass', summary: `${ctx.adapter || 'interface'}: ${ctx.ip || real[0]} via gateway ${ctx.gateway}`, data: { ip: ctx.ip || real[0], gateway: ctx.gateway } };
      }
      const t = P.ipconfig(out);
      if (!t) return { status: 'fail', summary: 'Could not read adapter configuration' };
      const adapters = new Map();
      const entry = (name) => {
        if (!adapters.has(name)) adapters.set(name, { name: name.replace(/^.*adapter\s+/i, ''), ipv4: [], apipa: [], gateways: [], dhcp: null, disconnected: false });
        return adapters.get(name);
      };
      for (const [adapter, key, value] of t.rows) {
        const a = entry(adapter);
        const v = value.replace(/\(.*\)$/, '').trim();
        if (key === 'IPv4 Address' && IPV4.test(v)) (v.startsWith('169.254.') ? a.apipa : a.ipv4).push(v);
        else if (key === 'Autoconfiguration IPv4 Address' && IPV4.test(v)) a.apipa.push(v);
        else if (key === 'Default Gateway' && IPV4.test(v)) a.gateways.push(v);
        else if (key === 'DHCP Enabled') a.dhcp = /yes/i.test(v);
        else if (key === 'Media State') a.disconnected = /disconnected/i.test(v);
      }
      const list = [...adapters.values()];
      const primary = (ctx?.adapter && list.find((a) => a.name === ctx.adapter)) || list.find((a) => a.ipv4.length && a.gateways.length);
      const deadRoutes = list.filter((a) => a !== primary && a.gateways.length && !a.ipv4.length);
      if (!primary) {
        const ap = list.find((a) => a.apipa.length);
        if (ap) return { status: 'fail', summary: `${ap.name} only has a self-assigned address (${ap.apipa[0]}) — DHCP didn't hand out a lease` };
        return { status: 'fail', summary: 'No adapter has both an IPv4 address and a default gateway' };
      }
      if (!primary.ipv4.length) {
        return { status: 'fail', summary: primary.apipa.length ? `${primary.name} only has a self-assigned address (${primary.apipa[0]}) — DHCP didn't hand out a lease` : `${primary.name} has no IPv4 address` };
      }
      if (!primary.gateways.length) return { status: 'fail', summary: `${primary.name}: ${primary.ipv4[0]} but no default gateway` };
      const base = `${primary.name}: ${primary.ipv4[0]} via gateway ${primary.gateways[0]}${primary.dhcp === false ? ' (static)' : ''}`;
      const data = { adapter: primary.name, ip: primary.ipv4[0], gateway: primary.gateways[0], dhcp: primary.dhcp, deadRoutes: deadRoutes.map((a) => a.name) };
      if (deadRoutes.length) {
        return { status: 'warn', summary: `${base} — but ${deadRoutes.map((a) => `${a.name} also has a default gateway (${a.gateways[0]}) with no valid address`).join('; ')}`, data };
      }
      return { status: 'pass', summary: base, data };
    },

    ping(out, params, ctx, meta) {
      if (/could not find host|Ping request could not find|Name or service not known|cannot resolve/i.test(out)) return { status: 'fail', summary: 'Name could not be resolved' };
      let sent, recv, loss, avg;
      const win = out.match(/Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)/);
      const nix = out.match(/(\d+) packets transmitted, (\d+) (?:packets )?received,.*?([\d.]+)% packet loss/);
      if (win) { [sent, recv, , loss] = win.slice(1).map(Number); avg = Number((out.match(/Average = (\d+)ms/) || [])[1]); }
      else if (nix) { sent = +nix[1]; recv = +nix[2]; loss = Math.round(+nix[3]); avg = Number((out.match(/= [\d.]+\/([\d.]+)\//) || [])[1]); }
      else return { status: 'fail', summary: 'No ping statistics — host unreachable' };
      // "Destination host unreachable" replies count as received on Windows; they are not echoes.
      const unreachable = (out.match(/Destination host unreachable/gi) || []).length;
      if (unreachable) recv = Math.max(0, recv - unreachable);
      if (recv === 0) return { status: 'fail', summary: unreachable ? `Destination host unreachable (${sent} attempts)` : `0 of ${sent} replies (100% loss)`, data: { sent, recv, loss: 100 } };
      const times = [...out.matchAll(/time[=<]\s?([\d.]+)\s?ms/gi)].map((m) => Number(m[1]));
      const max = times.length ? Math.max(...times) : avg;
      const jitter = times.length > 1 ? times.slice(1).reduce((s, t, i) => s + Math.abs(t - times[i]), 0) / (times.length - 1) : 0;
      const data = { sent, recv, loss, avg, max, jitter: Math.round(jitter * 10) / 10 };
      const limit = meta?.step?.warnMs;
      let summary = `${recv}/${sent} replies${Number.isFinite(avg) ? `, avg ${avg} ms` : ''}${times.length > 1 ? `, worst ${max} ms` : ''}`;
      if (loss > 0 || recv < sent) return { status: 'warn', summary: `${summary} — ${Math.round(((sent - recv) / sent) * 100)}% loss`, data };
      if (limit && avg > limit) return { status: 'warn', summary: `${summary} — slow (over ${limit} ms)`, data };
      return { status: 'pass', summary, data };
    },

    nslookup(out, params, ctx, meta) {
      const r = readNslookup(out);
      const via = r.server ? ` via ${r.server}` : '';
      const took = meta?.durationMs ? ` · ${secs(meta.durationMs)}` : '';
      if (r.answers.length) {
        const more = r.answers.length > 1 ? ` (+${r.answers.length - 1} more)` : '';
        const data = { answers: r.answers, server: r.server, durationMs: meta?.durationMs };
        // Windows nslookup prints "timed out" for a first attempt and then succeeds — slow, not broken.
        if (r.timedOut) return { status: 'warn', summary: `${r.answers[0]}${more}${via} — but the first attempt timed out${took}`, data };
        if (meta?.durationMs > 2500) return { status: 'warn', summary: `${r.answers[0]}${more}${via} — slow answer${took}`, data };
        return { status: 'pass', summary: `${r.answers[0]}${more}${via}${took}`, data };
      }
      if (r.nxdomain) return { status: 'fail', summary: `The name does not exist (NXDOMAIN)${via}`, data: { nxdomain: true, server: r.server } };
      if (r.refused) return { status: 'fail', summary: `The server refused the query${via}`, data: { server: r.server } };
      if (r.timedOut) return { status: 'fail', summary: `No answer${via} (timed out)`, data: { timedOut: true, server: r.server } };
      return { status: 'fail', summary: `Lookup failed${via}`, data: { server: r.server } };
    },

    /* Asks for a name under .invalid, which can never exist. An address coming back means
       answers are being rewritten (ISP search page, captive portal, filtering product). */
    nxdomain(out) {
      const r = readNslookup(out);
      if (r.answers.length) return { status: 'warn', summary: `Got ${r.answers[0]} for a name that cannot exist — DNS answers are being rewritten`, data: { hijacked: true } };
      if (r.nxdomain) return { status: 'pass', summary: 'Correctly reports that the name does not exist' };
      return { status: 'info', summary: 'Could not test (no answer)' };
    },

    tnc(out, params, ctx, meta) {
      if (ctx?.platform && ctx.platform !== 'win32') {
        if (/succeeded|open/i.test(out)) return { status: 'pass', summary: `TCP ${params.port} open`, data: { open: true } };
        if (/refused/i.test(out)) return { status: 'fail', summary: `TCP ${params.port} refused — host is up, nothing is listening`, data: { kind: 'refused' } };
        if (/could not resolve|nodename nor servname|Name or service/i.test(out)) return { status: 'fail', summary: 'Name resolution failed', data: { kind: 'dns' } };
        return { status: 'fail', summary: `TCP ${params.port} no response — filtered or host down`, data: { kind: 'filtered' } };
      }
      if (/Name resolution of .* failed/i.test(out)) return { status: 'fail', summary: 'Name resolution failed', data: { kind: 'dns' } };
      const tcp = out.match(/TcpTestSucceeded\s*:\s*(True|False)/i);
      const ping = out.match(/PingSucceeded\s*:\s*(True|False)/i);
      const rtt = out.match(/PingReplyDetails \(RTT\)\s*:\s*(\d+) ms/i);
      if (!tcp) return { status: 'fail', summary: 'No result from Test-NetConnection' };
      if (tcp[1].toLowerCase() === 'true') return { status: 'pass', summary: `TCP ${params.port} open${rtt ? `, ping ${rtt[1]} ms` : ''}`, data: { open: true } };
      // A refusal (RST) comes back in a few seconds; a dropped SYN waits out the full ~21 s timeout.
      const ms = meta?.durationMs;
      const kind = ms == null ? 'closed' : ms < 12000 ? 'refused' : ms > 18000 ? 'filtered' : 'closed';
      const pingOk = ping ? ping[1].toLowerCase() === 'true' : null;
      const text = {
        refused: `TCP ${params.port} refused in ${secs(ms)} — host is up, nothing is listening`,
        filtered: `TCP ${params.port} no response after ${secs(ms)} — filtered by a firewall, or host down`,
        closed: `TCP ${params.port} closed or filtered`,
      }[kind];
      return { status: 'fail', summary: `${text}${pingOk === true ? ' · answers ping' : pingOk === false ? ' · no ping reply' : ''}`, data: { kind, pingOk } };
    },

    /* Microsoft's connectivity probe: 200 with a 22-byte body on an open connection; a redirect or
       anything else means something is answering in its place. */
    captive(out) {
      const curlErr = out.match(/curl: \((\d+)\)\s*(.*)/);
      if (curlErr) return { status: 'fail', summary: `HTTP probe failed: ${curlErr[2] || `curl error ${curlErr[1]}`}` };
      const status = Number((out.match(/^HTTP\/\S+\s+(\d{3})/m) || [])[1]);
      const location = (out.match(/^Location:\s*(\S+)/im) || [])[1];
      const length = Number((out.match(/^Content-Length:\s*(\d+)/im) || [])[1]);
      if (status === 200 && length === 22) return { status: 'pass', summary: 'Open connection — no sign-in page in the way' };
      if (status >= 300 && status < 400) {
        let host = location || '';
        try { host = new URL(location).host; } catch { /* keep raw */ }
        return { status: 'warn', summary: `Redirected to ${host || 'a sign-in page'} — this network has a captive portal; open a browser and sign in`, data: { portal: true } };
      }
      if (status === 200) return { status: 'warn', summary: 'Something answered in place of the probe page — likely a captive portal or filtering proxy', data: { portal: true } };
      return { status: 'info', summary: status ? `Probe returned HTTP ${status}` : 'Probe gave no HTTP status' };
    },

    arp(out, params, ctx) {
      const t = P.parse('arp-a', out, ctx?.platform || 'win32');
      if (!t) return { status: 'warn', summary: 'ARP cache is empty', data: { devices: 0 } };
      const ipCol = t.columns.indexOf('IP address'), macCol = t.columns.indexOf('MAC address'), typeCol = t.columns.indexOf('Type');
      const real = t.rows.filter((r) => {
        const ip = r[ipCol] || '', mac = (r[macCol] || '').toLowerCase();
        const a = Number(ip.split('.')[0]);
        if (a >= 224 || ip.endsWith('.255') || /^ff[-:]ff/.test(mac) || !mac) return false;
        return /dynamic/i.test(r[typeCol] || 'dynamic');
      });
      const mine = ctx?.ip ? real.filter((r) => r[0] === ctx.ip || !IPV4.test(r[0])) : real;
      const devices = (mine.length ? mine : real).length;
      return { status: devices ? 'pass' : 'warn', summary: devices ? `${devices} device${devices === 1 ? '' : 's'} seen recently on your network (${t.rows.length} cache entries in total)` : 'No neighbours in the ARP cache yet', data: { devices, total: t.rows.length } };
    },

    netview(out) {
      if (/6118/.test(out)) return { status: 'info', summary: 'Windows network browsing is switched off here — normal on Windows 10/11, not a fault' };
      const hosts = (out.match(/^\\\\\S+/gm) || []).length;
      const err = out.match(/System error (\d+)/i);
      if (err) return { status: 'info', summary: `Share browsing unavailable (system error ${err[1]})` };
      return { status: 'info', summary: hosts ? `${hosts} computer${hosts === 1 ? '' : 's'} advertising shares` : 'No computers advertising shares', data: { hosts } };
    },

    tracert(out) {
      const hops = [];
      for (const line of out.split(/\r?\n/)) {
        const m = line.match(/^\s*(\d+)\s+(.*)$/);
        if (!m) continue;
        const rest = m[2].trim();
        const addr = (rest.match(/(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{4,})\]?\s*$/i) || [])[1] || null;
        const times = [...rest.matchAll(/(<?\d+)\s*ms/g)].map((t) => Number(t[1].replace('<', '')));
        hops.push({ n: Number(m[1]), addr, ms: times.length ? Math.min(...times) : null });
      }
      if (!hops.length) return { status: 'info', summary: 'No hops recorded' };
      const answered = hops.filter((h) => h.addr);
      const last = answered[answered.length - 1];
      const complete = /Trace complete/i.test(out) && hops[hops.length - 1].addr;
      if (complete) return { status: 'pass', summary: `Reached the destination in ${hops.length} hops`, data: { hops, reached: true } };
      if (!last) return { status: 'info', summary: 'No router on the path answered', data: { hops, reached: false } };
      const where = { private: 'inside your own network', cgnat: "in your provider's access network", public: "in your provider's network or beyond", apipa: 'on a self-assigned address' }[classifyIp(last.addr)];
      return { status: 'info', summary: `Path stops after hop ${last.n} (${last.addr}) — ${where}`, data: { hops, reached: false, lastHop: last, where } };
    },
  };

  /* ================= checks for the second set of playbooks ================= */

  /* Every adapter that has an address or a gateway, with its DNS servers (Windows ipconfig /all). */
  function readAdapters(out) {
    const t = P.ipconfig(out);
    if (!t) return [];
    const map = new Map();
    for (const [adapter, key, value] of t.rows) {
      if (!map.has(adapter)) map.set(adapter, { name: adapter.replace(/^.*adapter\s+/i, ''), description: '', ipv4: [], apipa: [], gateways: [], dns: [] });
      const a = map.get(adapter);
      const v = value.replace(/\(.*\)$/, '').trim();
      if ((key === 'IPv4 Address' || key === 'Autoconfiguration IPv4 Address') && IPV4.test(v)) (v.startsWith('169.254.') ? a.apipa : a.ipv4).push(v);
      else if (key === 'Default Gateway' && IPV4.test(v)) a.gateways.push(v);
      else if (key === 'DNS Servers' && IPV4.test(v)) a.dns.push(v);
      else if (key === 'Description') a.description = v;
    }
    return [...map.values()].filter((a) => a.ipv4.length || a.apipa.length || a.gateways.length);
  }

  const ipconfigBase = CHECKS.ipconfig;
  CHECKS.ipconfig = (out, params, ctx, meta) => {
    const res = ipconfigBase(out, params, ctx, meta);
    if (!ctx?.platform || ctx.platform === 'win32') res.data = { ...(res.data || {}), adapters: readAdapters(out) };
    return res;
  };

  /* Hops of a tracert / traceroute, plus the destination address from its header line. */
  function readTracert(out) {
    const hops = [];
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(/^\s*(\d+)\s+(.*)$/);
      if (!m) continue;
      const rest = m[2];
      const addr = (rest.match(/\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]+/i) || [])[0] || null;
      const times = [...rest.matchAll(/<?([\d.]+)\s*ms/g)].map((t) => Number(t[1]));
      if (!addr && !times.length && !rest.includes('*')) continue;
      hops.push({ n: Number(m[1]), addr, ms: times.length ? Math.min(...times) : null });
    }
    const target = (out.match(/(?:Tracing route to|traceroute to)\s+\S+\s+[[(]([0-9a-f:.]+)[\])]/i) || out.match(/Tracing route to\s+([0-9a-f:.]+)\s/i) || [])[1] || null;
    return { hops, target };
  }

  const WHERE = { private: 'inside your own network', cgnat: "in your provider's access network", public: 'out on the internet', apipa: 'on a self-assigned address', loopback: 'on this machine' };
  const CURL_ERRORS = {
    6: 'the name could not be resolved', 7: 'the connection was refused or failed', 28: 'it timed out',
    35: 'the TLS handshake failed', 51: "the certificate doesn't match the site name", 52: 'the server sent nothing back',
    56: 'the connection was reset', 60: "the site's certificate is not trusted",
  };
  const NOTABLE_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 135: 'RPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB file sharing',
    1433: 'SQL Server', 2375: 'Docker API', 3306: 'MySQL', 3389: 'Remote Desktop', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM',
    6379: 'Redis', 8080: 'HTTP-alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
  };
  const RISKY_PORTS = new Set([21, 23, 1433, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017]);

  Object.assign(CHECKS, {
    http(out) {
      const err = out.match(/curl: \((\d+)\)\s*([^\r\n]*)/);
      if (err) {
        const code = Number(err[1]);
        return { status: 'fail', summary: `No HTTP response: ${CURL_ERRORS[code] || err[2] || `curl error ${code}`}`, data: { curl: code, tls: [35, 51, 60].includes(code) } };
      }
      const statuses = [...out.matchAll(/^HTTP\/\S+\s+(\d{3})\s*([^\r\n]*)/gm)];
      if (!statuses.length) return { status: 'fail', summary: 'No HTTP response' };
      const last = statuses[statuses.length - 1];
      const status = Number(last[1]);
      const reason = last[2] ? ` ${last[2].trim()}` : '';
      const location = (out.match(/^Location:\s*(\S+)/im) || [])[1];
      const server = ((out.match(/^Server:\s*([^\r\n]+)/im) || [])[1] || '').trim();
      const data = { status, location, server };
      if (status >= 500) return { status: 'fail', summary: `HTTP ${status}${reason} — the site's own server is failing`, data };
      if (status === 401 || status === 403) return { status: 'warn', summary: `HTTP ${status}${reason} — the site answered but refuses access`, data };
      if (status === 404) return { status: 'warn', summary: 'HTTP 404 — the site works; that page does not exist', data };
      if (status >= 400) return { status: 'warn', summary: `HTTP ${status}${reason}`, data };
      if (status >= 300) return { status: 'pass', summary: `HTTP ${status} — redirects to ${location || 'another address'}`, data };
      return { status: 'pass', summary: `HTTP ${status}${reason}${server ? ` · served by ${server}` : ''}`, data };
    },

    curlTiming(out) {
      const m = out.match(/dns ([\d.]+)s\s+connect ([\d.]+)s\s+tls ([\d.]+)s\s+first byte ([\d.]+)s\s+total ([\d.]+)s\s+status (\d+)/);
      if (!m) {
        const err = out.match(/curl: \((\d+)\)\s*([^\r\n]*)/);
        return err ? { status: 'fail', summary: `Request failed: ${CURL_ERRORS[Number(err[1])] || err[2]}` } : { status: 'info', summary: 'No timing data returned' };
      }
      const [dns, connect, tls, first, total] = m.slice(1, 6).map(Number);
      const ms = (s) => Math.round(s * 1000);
      const phases = {
        DNS: ms(dns), connect: ms(Math.max(0, connect - dns)), TLS: tls ? ms(Math.max(0, tls - connect)) : 0,
        server: ms(Math.max(0, first - (tls || connect))), transfer: ms(Math.max(0, total - first)),
      };
      const slowest = Object.entries(phases).sort((a, b) => b[1] - a[1])[0][0];
      const summary = `total ${total.toFixed(2)} s — DNS ${phases.DNS} ms · connect ${phases.connect} ms · TLS ${phases.TLS} ms · server ${phases.server} ms · transfer ${phases.transfer} ms`;
      const slow = total > 3 || phases.server > 1500 || phases.DNS > 1000 || phases.connect > 800;
      return { status: slow ? 'warn' : 'pass', summary, data: { total, phases, slowest, status: Number(m[6]) } };
    },

    wlan(out) {
      if (/no wireless interface|is not running/i.test(out)) return { status: 'info', summary: 'No Wi-Fi adapter in use', data: { wifi: false } };
      // Windows 11 withholds Wi-Fi details from non-elevated programs unless Location services are on.
      if (/location permission|requires elevation/i.test(out)) return { status: 'info', summary: 'Windows is withholding Wi-Fi details: turn on Location services (Settings → Privacy & security → Location), or run NetDeck as administrator', data: { wifi: false, blocked: true } };
      const get = (label) => ((out.match(new RegExp(`^\\s*${label}\\s*:\\s*(.+)$`, 'im')) || [])[1] || '').trim();
      const state = get('State');
      if (!/^connected/i.test(state)) return { status: 'info', summary: `Wi-Fi is not connected${state ? ` (${state})` : ''}`, data: { wifi: false } };
      const signal = parseInt(get('Signal'), 10);
      const channel = parseInt(get('Channel'), 10);
      const radio = get('Radio type');
      const rx = parseFloat(get('Receive rate \\(Mbps\\)'));
      const tx = parseFloat(get('Transmit rate \\(Mbps\\)'));
      const band = get('Band') || (channel ? (channel <= 14 ? '2.4 GHz' : '5 GHz') : '');
      const problems = [];
      if (signal < 55) problems.push(`weak signal (${signal}%) — move closer or add an access point`);
      if (/^2\.4/.test(band)) problems.push('on the crowded 2.4 GHz band — use 5 GHz if your router offers it');
      if (/802\.11(n|g|b|a)\b/i.test(radio)) problems.push(`old radio mode (${radio})`);
      if (Math.min(rx || Infinity, tx || Infinity) < 50) problems.push(`low link rate (${rx}/${tx} Mbps)`);
      const summary = `${get('SSID') || 'Wi-Fi'}: signal ${signal}%, ${band}${channel ? ` ch ${channel}` : ''}, ${radio}, ${rx}/${tx} Mbps`;
      return { status: problems.length ? 'warn' : 'pass', summary: problems.length ? `${summary} — ${problems.join('; ')}` : summary, data: { wifi: true, signal, channel, band, radio, rx, tx, problems, bssid: get('(?:AP )?BSSID').toLowerCase() } };
    },

    processes(out) {
      const map = P.processMap(out);
      return { status: 'info', summary: `${map.size} running processes indexed`, data: { map: Object.fromEntries(map) } };
    },

    listening(out, params, ctx, meta) {
      const t = P.fixedWidth(out);
      if (!t) return { status: 'info', summary: 'Could not read the list of listening ports' };
      const la = t.columns.indexOf('LocalAddress'), lp = t.columns.indexOf('LocalPort'), op = t.columns.indexOf('OwningProcess');
      const names = meta?.R?.procs?.data?.map || {};
      const seen = new Map();
      for (const row of t.rows) {
        const port = Number(row[lp]);
        const scope = /^(127\.|::1$)/.test(row[la]) ? 'local' : 'network';
        const key = `${port}/${scope}`;
        if (!port || seen.has(key)) continue;
        seen.set(key, { port, scope, addr: row[la], proc: names[row[op]] || `PID ${row[op]}` });
      }
      const all = [...seen.values()].sort((a, b) => a.port - b.port);
      const exposed = all.filter((e) => e.scope === 'network');
      const local = all.filter((e) => e.scope === 'local');
      const risky = exposed.filter((e) => RISKY_PORTS.has(e.port));
      const label = (e) => `${e.port}${NOTABLE_PORTS[e.port] ? ` ${NOTABLE_PORTS[e.port]}` : ''} (${e.proc})`;
      const summary = `${exposed.length} ports reachable from the network, ${local.length} local-only${risky.length ? ` — remote-access or database services exposed: ${risky.map(label).join(', ')}` : ''}`;
      return { status: risky.length ? 'warn' : 'info', summary, data: { exposed, local, risky, label: undefined, lines: exposed.map(label) } };
    },

    firewall(out) {
      const profiles = [...out.matchAll(/^(Domain|Private|Public) Profile Settings:[\s\S]*?^State\s+(ON|OFF)/gim)].map((m) => ({ name: m[1], on: m[2].toUpperCase() === 'ON' }));
      if (!profiles.length) return { status: 'info', summary: 'Could not read the firewall state' };
      const off = profiles.filter((p) => !p.on).map((p) => p.name);
      if (off.length) return { status: 'warn', summary: `Windows Firewall is OFF for: ${off.join(', ')}`, data: { profiles, off } };
      return { status: 'pass', summary: 'Windows Firewall is on for the Domain, Private and Public profiles', data: { profiles, off } };
    },

    routes(out, params, ctx) {
      const platform = ctx?.platform || 'win32';
      const t = P.parse('route-print', out, platform);
      if (!t) return { status: 'fail', summary: 'Could not read the routing table' };
      let defaults;
      if (platform === 'win32') defaults = t.rows.filter((r) => r[0] === '0.0.0.0' && r[1] === '0.0.0.0').map((r) => ({ gateway: r[2], iface: r[3], metric: Number(r[4]) }));
      else if (platform === 'darwin') defaults = t.rows.filter((r) => r[0] === 'default').map((r) => ({ gateway: r[1], iface: r[3], metric: 0 }));
      else defaults = t.rows.filter((r) => r[0] === 'default').map((r) => ({ gateway: r[1], iface: r[2], metric: Number(r[4]) || 0 }));
      defaults.sort((a, b) => a.metric - b.metric);
      const show = (d) => `via ${d.gateway} on ${d.iface} (metric ${d.metric})`;
      if (!defaults.length) return { status: 'fail', summary: 'No default route — nothing beyond your own network is reachable', data: { defaults } };
      if (defaults.length === 1) return { status: 'pass', summary: `One default route: ${show(defaults[0])}`, data: { defaults } };
      return { status: 'warn', summary: `${defaults.length} default routes; the lowest metric wins: ${defaults.map(show).join(' · ')}`, data: { defaults } };
    },

    tracertPath(out) {
      const { hops, target } = readTracert(out);
      if (!hops.length) return { status: 'info', summary: 'No hops recorded' };
      const answered = hops.filter((h) => h.addr && h.ms != null);
      const last = answered[answered.length - 1];
      if (!last) return { status: 'fail', summary: 'No router on the path answered — not even your own', data: { hops, reached: false } };
      const reached = target ? last.addr === target : /Trace complete/i.test(out) && Boolean(hops[hops.length - 1].addr);
      // The largest latency step that the later hops sustain (one slow router replying late is not a slow path).
      let jump = null;
      for (let i = 1; i < answered.length; i++) {
        const delta = answered[i].ms - answered[i - 1].ms;
        if (delta < 40) continue;
        const later = answered.slice(i).map((h) => h.ms).sort((a, b) => a - b);
        const median = later[Math.floor(later.length / 2)];
        if (median >= answered[i - 1].ms + delta * 0.6 && (!jump || delta > jump.delta)) jump = { at: answered[i], from: answered[i - 1], delta: Math.round(delta) };
      }
      const silent = hops.filter((h) => !h.addr).length;
      const data = { hops, target, reached, last, jump, where: WHERE[P.classifyIp(last.addr)], silent };
      if (!reached) return { status: 'fail', summary: `Path stops after hop ${last.n} (${last.addr}) — ${data.where}`, data };
      if (jump) return { status: 'warn', summary: `Reached in ${last.n} hops (${last.ms} ms) — latency jumps +${jump.delta} ms at hop ${jump.at.n} (${jump.at.addr})`, data };
      return { status: 'pass', summary: `Reached in ${last.n} hops, ${last.ms} ms end to end${silent ? ` · ${silent} silent hop${silent === 1 ? '' : 's'} (normal)` : ''}`, data };
    },

    nsRecords(out, params) {
      const names = [...new Set([...out.matchAll(/nameserver\s*=\s*(\S+)/gi)].map((m) => m[1].replace(/\.$/, '').toLowerCase()))];
      if (names.length) {
        return { status: 'pass', summary: `${names.length} authoritative nameserver${names.length === 1 ? '' : 's'}: ${names.slice(0, 4).join(', ')}${names.length > 4 ? '…' : ''}`, data: { found: true, names }, capture: { ns0: names[0], ns1: names[1] || names[0] } };
      }
      const parent = String(params.host || '').split('.').slice(1).join('.');
      if (parent.includes('.')) return { status: 'info', summary: `No NS records at this name — it lives inside a parent zone; trying ${parent}`, data: { found: false }, capture: { parent } };
      return { status: 'fail', summary: 'No authoritative nameservers found — is the domain registered?', data: { found: false } };
    },
  });

  const PLAYBOOKS = [
    {
      id: 'internet',
      name: "Can't reach the internet?",
      description: 'Walks the chain from your adapter to the web — IP lease, router, raw connectivity (ping, then TCP if ping is blocked), DNS, sign-in portals, HTTPS — and names the broken link.',
      params: [],
      steps: [
        { id: 'ip', cmd: 'ipconfig-all', label: 'Check your adapter', check: 'ipconfig', table: true, stopOnFail: true },
        { id: 'gw', cmd: 'ping', label: 'Ping the router', params: { host: '{gateway}' }, check: 'ping', warnMs: 50 },
        { id: 'net', cmd: 'ping', label: 'Ping the internet (1.1.1.1)', params: { host: '1.1.1.1' }, check: 'ping', warnMs: 150 },
        { id: 'tcp', cmd: 'test-netconnection', label: 'TCP to 1.1.1.1 in case ping is blocked', params: { host: '1.1.1.1', port: '443' }, check: 'tnc', when: (R) => failed(R.net) },
        { id: 'dns', cmd: 'nslookup', label: 'Resolve example.com', params: { host: 'example.com' }, check: 'nslookup', when: (R) => ok(R.net) || ok(R.tcp) },
        { id: 'portal', cmd: 'curl', label: 'Look for a sign-in (captive) portal', params: { url: 'http://www.msftconnecttest.com/connecttest.txt' }, check: 'captive', when: (R) => ok(R.net) || ok(R.tcp) },
        { id: 'https', cmd: 'test-netconnection', label: 'HTTPS to example.com', params: { host: 'example.com', port: '443' }, check: 'tnc', when: (R) => ok(R.dns) },
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.ip)) return { tone: 'fail', text: 'Your adapter has no usable IP address. Check the cable or Wi-Fi association, then renew the DHCP lease from a terminal.', actions: [{ label: 'Copy: ipconfig /renew', copy: 'ipconfig /renew' }] };
        const reachable = ok(R.net) || ok(R.tcp);
        if (!reachable) {
          if (ok(R.gw)) return { tone: 'fail', text: "Your router answers, but nothing beyond it does — by ping or by TCP. The internet link itself (modem / provider) is down; check the router's WAN status or restart the modem." };
          if (failed(R.gw)) return { tone: 'fail', text: 'Neither the router nor the internet answers. This is a local problem — Wi-Fi signal, a bad cable, or the router itself.' };
          return { tone: 'fail', text: 'Nothing on the internet answers by ping or TCP, and no router was detected to test. Check the adapter and cabling.' };
        }
        if (failed(R.dns)) return { tone: 'fail', text: 'The connection works but names do not resolve — this is a DNS problem. Flush the cache, and run the DNS playbook to find which server is failing.', actions: [{ label: 'Run "Is DNS healthy?"', playbook: 'dns' }, { label: 'Copy: ipconfig /flushdns', copy: 'ipconfig /flushdns' }] };
        if (R.portal?.data?.portal) return { tone: 'warn', text: 'You are connected, but a sign-in page is intercepting web traffic (hotel, café or guest Wi-Fi). Open a browser, sign in, then try again.' };
        if (failed(R.https)) return { tone: 'fail', text: 'Names resolve and pings work, but HTTPS is blocked. Look at a firewall, a proxy setting, or security software.' };
        const notes = [];
        if (warned(R.ip)) notes.push(`Another adapter (${R.ip.data.deadRoutes.join(', ')}) has a default route but no valid address — it can capture traffic; disable it or fix its settings.`);
        if (failed(R.net) && ok(R.tcp)) notes.push('Ping to the internet is blocked on this network, but TCP works — that is a policy, not a fault.');
        if (failed(R.gw)) notes.push('Your router does not answer ping (some are set that way); everything beyond it works.');
        if (warned(R.gw)) notes.push(`The link to your router is unhealthy (${R.gw.summary}) — on Wi-Fi this means weak signal or interference.`);
        if (warned(R.net)) notes.push(`The internet path is degraded (${R.net.summary}).`);
        if (warned(R.dns)) notes.push(`DNS answered slowly (${R.dns.summary}).`);
        if (notes.length) return { tone: 'warn', text: `You are online, with caveats. ${notes.join(' ')}` };
        return { tone: 'pass', text: 'Every link in the chain checks out. If one particular site fails, the problem is at their end or in the browser.' };
      },
    },
    {
      id: 'port',
      name: 'Is a port open on a host?',
      description: 'Resolves the name, checks the host answers, tests the exact TCP port — telling "refused" (nothing listening) from "filtered" (firewall) by how fast it fails — and traces the path if nothing answers at all.',
      params: [
        { key: 'host', placeholder: 'e.g. github.com', type: 'host' },
        { key: 'port', placeholder: '443', type: 'port' },
      ],
      steps: [
        { id: 'dns', cmd: 'nslookup', label: 'Resolve the host name', params: { host: '{host}' }, check: 'nslookup', skipIf: (p) => IPV4.test(p.host), stopOnFail: true },
        { id: 'ping', cmd: 'ping', label: 'Ping the host', params: { host: '{host}' }, check: 'ping' },
        { id: 'tcp', cmd: 'test-netconnection', label: 'Test the TCP port', params: { host: '{host}', port: '{port}' }, check: 'tnc' },
        { id: 'path', cmd: 'tracert', preset: 'quick', label: 'Find where the path stops', params: { host: '{host}' }, check: 'tracert', when: (R) => failed(R.tcp) && failed(R.ping) },
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.dns)) return { tone: 'fail', text: `"${p.host}" does not resolve (${R.dns.summary}). Check the spelling, or test the IP address directly.` };
        if (ok(R.tcp)) return { tone: 'pass', text: `Port ${p.port} on ${p.host} is open and accepting connections.` };
        const kind = R.tcp?.data?.kind;
        if (kind === 'refused') return { tone: 'fail', text: `${p.host} is up and actively refused the connection: nothing is listening on port ${p.port}. The service is stopped, or it runs on a different port.` };
        if (ok(R.ping)) return { tone: 'fail', text: `${p.host} answers ping, but port ${p.port} gave no response at all — a firewall (on the host or in between) is silently dropping it.` };
        const stop = R.path?.data?.lastHop;
        if (stop) return { tone: 'fail', text: `${p.host} answers neither ping nor port ${p.port}. The route stops after hop ${stop.n} (${stop.addr}), ${R.path.data.where} — the host is down, or everything past that point is blocked.` };
        return { tone: 'fail', text: `${p.host} answers neither ping nor port ${p.port}. The host may be down, or a firewall drops everything; try a port you know is open to tell the difference.` };
      },
    },
    {
      id: 'dns',
      name: 'Is DNS healthy?',
      description: 'Asks each of your configured DNS servers and two public ones the same question, times the answers, and checks whether non-existent names are being rewritten.',
      params: [],
      steps: [
        { id: 'own', cmd: 'nslookup', label: 'Resolve via your configured DNS', params: { host: 'example.com' }, check: 'nslookup' },
        { id: 'second', cmd: 'nslookup-server', label: 'Resolve via your second DNS server', params: { host: 'example.com', server: '{dns1}' }, check: 'nslookup', when: (R, p, ctx) => Boolean(ctx.dns?.[1]) },
        { id: 'cf', cmd: 'nslookup-server', label: 'Resolve via Cloudflare (1.1.1.1)', params: { host: 'example.com', server: '1.1.1.1' }, check: 'nslookup' },
        { id: 'goog', cmd: 'nslookup-server', label: 'Resolve via Google (8.8.8.8)', params: { host: 'example.com', server: '8.8.8.8' }, check: 'nslookup' },
        { id: 'nx', cmd: 'nslookup', label: 'Ask for a name that cannot exist', params: { host: 'netdeck-check.invalid' }, check: 'nxdomain', when: (R) => ok(R.own) },
      ],
      verdict(r, p, ctx, R) {
        const publicOk = ok(R.cf) || ok(R.goog);
        const flush = { label: 'Copy: ipconfig /flushdns', copy: 'ipconfig /flushdns' };
        // Name the server nslookup really asked — a VPN or virtual adapter can take DNS priority over the one in the context strip.
        const asked = R.own?.data?.server || ctx.dns?.[0];
        if (!ok(R.own) && publicOk) return { tone: 'fail', text: `Your configured DNS server${asked ? ` (${asked})` : ''} is not answering, but public resolvers do. Restart the router, or set your adapter's DNS to 1.1.1.1.`, actions: [flush] };
        if (!ok(R.own) && !publicOk) return { tone: 'fail', text: 'No DNS server answers at all. That is almost always a connectivity problem rather than DNS.', actions: [{ label: 'Run "Can\'t reach the internet?"', playbook: 'internet' }] };
        const notes = [];
        if (!publicOk) notes.push('Public resolvers are blocked here — typical of a corporate network or a router that intercepts DNS.');
        if (failed(R.second)) notes.push(`Your second DNS server (${ctx.dns?.[1]}) is not answering; lookups will stall whenever Windows falls back to it.`);
        if (warned(R.own)) notes.push(`Your resolver is slow or flaky (${R.own.summary}).`);
        if (R.nx?.data?.hijacked) notes.push('Your resolver returns an address for names that do not exist — answers are being rewritten by the provider, a portal or a filter.');
        if (notes.length) return { tone: 'warn', text: `DNS works, with caveats. ${notes.join(' ')}`, actions: [flush] };
        return { tone: 'pass', text: 'DNS is healthy: your resolvers and the public ones answer promptly, and non-existent names are reported honestly.' };
      },
    },
    {
      id: 'lan',
      name: "Who's on my network?",
      description: 'Refreshes and reads the ARP cache — every device this machine has recently exchanged packets with — with a table of their IP and MAC addresses.',
      params: [],
      // `net view` used to be a third step; on Windows 10/11 it spends a minute timing out to report
      // that network browsing is off, so it was dropped. The netview check remains for other playbooks.
      steps: [
        { id: 'wake', cmd: 'ping', label: 'Wake the router entry', params: { host: '{gateway}' }, check: 'ping' },
        { id: 'arp', cmd: 'arp-a', label: 'Read the ARP cache', check: 'arp', table: true },
      ],
      verdict(r, p, ctx, R) {
        const n = R.arp?.data?.devices || 0;
        if (!n) return { tone: 'warn', text: 'The ARP cache is nearly empty — this machine has not exchanged traffic with its neighbours recently. Ping a few local addresses and run again.' };
        return { tone: 'pass', text: `${n} device${n === 1 ? ' has' : 's have'} talked to this machine recently. Press "table" on step 2 for each IP and MAC address; the first three pairs of a MAC identify the manufacturer. The cache only lists devices you have exchanged traffic with, so quiet ones may be missing.` };
      },
    },
  ];

  /* ================= second set of playbooks ================= */
  const isIp = (p) => IPV4.test(p.host || '');
  const v4 = (res) => (ok(res) ? [...(res.data?.answers || [])].filter((a) => IPV4.test(a)).sort() : null);
  const overlap = (a, b) => a.some((x) => b.includes(x));
  const flushAction = { label: 'Copy: ipconfig /flushdns', copy: 'ipconfig /flushdns' };

  PLAYBOOKS.push(
    {
      id: 'website',
      name: "A website won't load",
      description: 'Is it you, DNS, their server, or the secure connection? Resolves the name two ways, connects, asks for the page, times each phase, and checks a known-good site for comparison.',
      params: [{ key: 'host', placeholder: 'e.g. github.com', type: 'host' }],
      steps: [
        { id: 'dns', cmd: 'nslookup', label: 'Resolve it with your DNS', params: { host: '{host}' }, check: 'nslookup', skipIf: isIp },
        { id: 'pub', cmd: 'nslookup-server', label: 'Resolve it with a public DNS (1.1.1.1)', params: { host: '{host}', server: '1.1.1.1' }, check: 'nslookup', skipIf: isIp },
        { id: 'tcp', cmd: 'test-netconnection', label: 'Connect to port 443', params: { host: '{host}', port: '443' }, check: 'tnc', when: (R, p) => isIp(p) || ok(R.dns) },
        { id: 'head', cmd: 'curl', label: 'Ask for the page headers', params: { url: 'https://{host}/' }, check: 'http', when: (R) => ok(R.tcp) },
        { id: 'time', cmd: 'curl', preset: 'timing', label: 'Time each phase of the request', params: { url: 'https://{host}/' }, check: 'curlTiming', when: (R) => ok(R.head) },
        { id: 'control', cmd: 'curl', label: 'Control: does a known-good site load?', params: { url: 'https://example.com/' }, check: 'http', when: (R) => failed(R.tcp) || failed(R.head) || (failed(R.dns) && failed(R.pub)) },
      ],
      verdict(r, p, ctx, R) {
        const runInternet = { label: 'Run "Can\'t reach the internet?"', playbook: 'internet' };
        if (failed(R.dns) && ok(R.pub)) return { tone: 'fail', text: `Your DNS cannot resolve ${p.host}, but a public resolver can (${R.pub.data.answers[0]}). Your resolver is stale, filtering, or blocking this name.`, actions: [{ label: 'Run "Is DNS healthy?"', playbook: 'dns' }, flushAction] };
        if (failed(R.dns) && failed(R.pub)) {
          if (R.pub.data?.nxdomain || R.dns.data?.nxdomain) return { tone: 'fail', text: `"${p.host}" does not exist in DNS. Check the spelling; if it is your domain, the registration or the DNS zone may have lapsed.` };
          return ok(R.control)
            ? { tone: 'fail', text: `No resolver could look up ${p.host}, yet other sites load. The domain's own DNS servers are not answering — that is at their end.` }
            : { tone: 'fail', text: `Nothing resolves and the control site does not load either — the problem is your connection, not ${p.host}.`, actions: [runInternet] };
        }
        const mine = v4(R.dns), pub = v4(R.pub);
        const mismatch = mine && pub && mine.length && pub.length && !overlap(mine, pub);
        if (failed(R.tcp)) {
          if (!ok(R.control)) return { tone: 'fail', text: `${p.host} does not answer, and neither does the control site — the problem is your connection.`, actions: [runInternet] };
          return { tone: 'fail', text: `Your connection is fine (the control site loads), but ${p.host} does not accept connections: ${R.tcp.summary}. The site is down, or it is blocking you.${mismatch ? ` Note that your DNS returns ${mine[0]} while public DNS returns ${pub[0]} — if the site moved recently, flush your DNS cache and try again.` : ''}`, actions: mismatch ? [flushAction] : [] };
        }
        if (failed(R.head)) {
          if (R.head.data?.tls) return { tone: 'fail', text: `The server is reachable but the secure connection fails: ${R.head.summary}. Check this PC's date and time first; then consider security software or a proxy intercepting HTTPS — or the site's certificate has genuinely expired.` };
          if (R.head.data?.status >= 500) return { tone: 'fail', text: `${p.host} is reachable and answering, but with a server error (${R.head.summary}). Nothing on your side can fix that.` };
          return { tone: 'fail', text: `The port is open but no page comes back: ${R.head.summary}.${ok(R.control) ? ' Other sites load, so this is at their end.' : ''}` };
        }
        if (warned(R.head)) return { tone: 'warn', text: `${p.host} is up and reachable: ${R.head.summary}.` };
        if (failed(R.time)) return { tone: 'warn', text: `${p.host} answers a headers-only request (${R.head.summary}), but the full request failed: ${R.time.summary}.` };
        if (warned(R.time)) {
          const why = { DNS: 'looking the name up — a DNS problem on your side', connect: 'reaching the server — distance or a congested path', TLS: 'setting up encryption — often a slow or overloaded server', server: "waiting for the site to build the page — that is their server, not your network", transfer: 'downloading the response — bandwidth' }[R.time.data.slowest];
          return { tone: 'warn', text: `${p.host} loads, slowly: ${R.time.summary}. Most of the time goes on ${why}.` };
        }
        return { tone: 'pass', text: `${p.host} loads normally from this PC (${R.head.summary}; ${R.time?.summary || 'timing skipped'}). If your browser still fails, the cause is in the browser: try a private window to rule out extensions, cache and cookies.` };
      },
    },
    {
      id: 'slow',
      name: 'Why is everything slow?',
      description: 'Twenty pings each to your router and to the internet (average, worst, jitter, loss), a timed DNS lookup and web request, and the Wi-Fi link quality — to say whether it is Wi-Fi, your router, or your provider.',
      params: [],
      steps: [
        { id: 'gw', cmd: 'ping', preset: 'x20', label: '20 pings to your router', params: { host: '{gateway}' }, check: 'ping', warnMs: 30 },
        { id: 'net', cmd: 'ping', preset: 'x20', label: '20 pings to the internet (1.1.1.1)', params: { host: '1.1.1.1' }, check: 'ping', warnMs: 100 },
        { id: 'dns', cmd: 'nslookup', label: 'Time a DNS lookup', params: { host: 'example.com' }, check: 'nslookup' },
        { id: 'web', cmd: 'curl', preset: 'timing', label: 'Time a small web request', params: { url: 'https://example.com/' }, check: 'curlTiming' },
        { id: 'wifi', cmd: 'netsh', label: 'Read the Wi-Fi link', check: 'wlan', when: (R, p, ctx) => /wi-?fi|wireless|wlan/i.test(ctx.adapter || '') },
      ],
      verdict(r, p, ctx, R) {
        const gw = R.gw?.data || {}, net = R.net?.data || {};
        const stats = (d) => `avg ${d.avg} ms, worst ${d.max} ms, jitter ${d.jitter} ms${d.loss ? `, ${d.loss}% loss` : ''}`;
        const wifi = R.wifi?.data?.wifi ? ` Wi-Fi link: ${R.wifi.summary}.` : '';
        if (failed(R.gw) && failed(R.net)) return { tone: 'fail', text: 'Nothing answers at all — this is an outage rather than slowness.', actions: [{ label: 'Run "Can\'t reach the internet?"', playbook: 'internet' }] };
        const gwBad = warned(R.gw) || failed(R.gw) || gw.jitter > 15;
        const netBad = warned(R.net) || failed(R.net) || net.jitter > 25;
        if (gwBad && ok(R.gw)) return { tone: 'warn', text: `The slowness starts between this PC and your router (${stats(gw)}); a healthy link is 1–5 ms with almost no jitter.${wifi || ' On a cable, try another cable or switch port.'}${R.wifi?.data?.problems?.length ? '' : wifi ? ' The radio numbers look fine, so suspect interference or a busy access point.' : ''}` };
        if (netBad) return { tone: 'warn', text: `Your local link is clean (${stats(gw)}) but the path to the internet is not (${R.net.summary}; jitter ${net.jitter} ms). That points at your provider, or at the connection being saturated — a large upload, backup or stream on the network.`, actions: [{ label: 'Trace the path to 1.1.1.1', playbook: 'path', params: { host: '1.1.1.1' } }] };
        if (warned(R.dns)) return { tone: 'warn', text: `Latency is fine, but DNS is slow (${R.dns.summary}). Every new site waits on that lookup, which feels like "everything is slow".`, actions: [{ label: 'Run "Is DNS healthy?"', playbook: 'dns' }] };
        if (warned(R.web)) return { tone: 'warn', text: `The network itself measures well, but the test request was slow: ${R.web.summary}.` };
        if (R.wifi?.data?.blocked) return { tone: 'pass', text: `The network measures healthy right now — router ${stats(gw)}; internet ${stats(net)}; ${R.web?.summary || ''}. The Wi-Fi signal could not be read because Windows withholds it without Location permission; if slowness comes and goes as you move around, that is the first thing to check.` };
        return { tone: warned(R.wifi) ? 'warn' : 'pass', text: `The network measures healthy right now — router ${stats(gw)}; internet ${stats(net)}; ${R.web?.summary || ''}.${wifi} If things still feel slow, look at the PC itself (memory and CPU in tasklist) or at the one service that is slow.` };
      },
    },
    {
      id: 'path',
      name: 'Where does the path break?',
      description: 'Traces the route hop by hop and reads it for you: whether the destination is reached, where replies stop, and where latency jumps — in your network, your provider, or beyond.',
      params: [{ key: 'host', placeholder: 'e.g. 1.1.1.1 or a site', type: 'host' }],
      steps: [
        { id: 'dns', cmd: 'nslookup', label: 'Resolve the name', params: { host: '{host}' }, check: 'nslookup', skipIf: isIp, stopOnFail: true },
        { id: 'trace', cmd: 'tracert', preset: 'path', label: 'Trace the route (up to 20 hops)', params: { host: '{host}' }, check: 'tracertPath', table: true },
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.dns)) return { tone: 'fail', text: `"${p.host}" does not resolve, so there is no route to trace (${R.dns.summary}).` };
        const d = R.trace?.data;
        if (!d || !d.last) return { tone: 'fail', text: 'No router answered, not even your own. Check that you are connected at all.', actions: [{ label: 'Run "Can\'t reach the internet?"', playbook: 'internet' }] };
        const place = (hop) => (hop.n === 1 ? 'your own router' : hop.n <= 3 && P.classifyIp(hop.addr) !== 'private' ? "your provider's first routers" : WHERE[P.classifyIp(hop.addr)]);
        if (!d.reached) return { tone: 'fail', text: `The route to ${p.host} goes quiet after hop ${d.last.n} (${d.last.addr}) — ${place(d.last)}. Everything up to there works. Either the destination is down, or something past that hop drops traffic. (Some hosts never answer traces: if the site works in a browser, that is all this is.) Press "table" for the hop list.` };
        if (d.jump) return { tone: 'warn', text: `${p.host} is reached in ${d.last.n} hops, but latency steps up by ${d.jump.delta} ms at hop ${d.jump.at.n} (${d.jump.at.addr}) — ${place(d.jump.at)} — and stays high from there. ${d.jump.at.n <= 1 ? 'That is your local link: Wi-Fi or the router.' : d.jump.at.n <= 3 ? 'That is the link to your provider: a saturated or poor-quality connection.' : 'That is a long-distance or congested segment outside your control.'}` };
        return { tone: 'pass', text: `The path to ${p.host} is clean: ${d.last.n} hops, ${d.last.ms} ms end to end, no sustained latency jump.${d.silent ? ` ${d.silent} hop${d.silent === 1 ? '' : 's'} did not reply to the trace, which is normal.` : ''}` };
      },
    },
    {
      id: 'exposure',
      name: 'What is this PC exposing?',
      description: 'Lists every TCP port this machine is listening on, names the program behind each, separates "reachable from the network" from "local only", flags remote-access and database services, and checks the firewall.',
      params: [],
      steps: [
        { id: 'procs', cmd: 'tasklist-csv', label: 'Index running programs', check: 'processes' },
        { id: 'listen', cmd: 'get-nettcpconnection', preset: 'state-listen', label: 'List listening TCP ports', check: 'listening', table: true },
        { id: 'fw', cmd: 'netsh', preset: 'advfirewall-show-allprofiles', label: 'Check the Windows firewall', check: 'firewall' },
      ],
      verdict(r, p, ctx, R) {
        const d = R.listen?.data;
        if (!d) return { tone: 'warn', text: 'The listening-port list could not be read on this system.' };
        // Windows hands out ports from 49152 up for its own RPC services; listing each one is noise.
        const label = (e) => `${e.port}${NOTABLE_PORTS[e.port] ? ` ${NOTABLE_PORTS[e.port]}` : ''} (${e.proc})`;
        const named = d.exposed.filter((e) => e.port < 49152);
        const dynamic = d.exposed.filter((e) => e.port >= 49152);
        const rows = named.map((e) => `  • ${label(e)}`);
        if (dynamic.length) rows.push(`  • + ${dynamic.length} dynamic Windows service port${dynamic.length === 1 ? '' : 's'} (${dynamic[0].port}–${dynamic[dynamic.length - 1].port}: ${[...new Set(dynamic.map((e) => e.proc))].join(', ')})`);
        const list = rows.length ? `\nReachable from the network:\n${rows.join('\n')}` : '';
        const fwOff = R.fw?.data?.off?.length ? ` Windows Firewall is OFF for the ${R.fw.data.off.join(' and ')} profile${R.fw.data.off.length === 1 ? '' : 's'} — nothing is filtering these ports there.` : '';
        const fwOn = ok(R.fw) && !fwOff ? ' The firewall is on for every profile, so most of these are filtered unless a rule allows them.' : '';
        if (d.risky.length) return { tone: 'warn', text: `${d.exposed.length} ports are open to the network, including services you should be sure about: ${d.risky.map((e) => `${NOTABLE_PORTS[e.port]} on ${e.port} (${e.proc})`).join(', ')}.${fwOff}${fwOn}${list}` };
        if (fwOff) return { tone: 'warn', text: `${d.exposed.length} ports are open to the network and none are remote-access or database services.${fwOff}${list}` };
        return { tone: 'pass', text: `${d.exposed.length} ports are open to the network — none are remote-access or database services — and ${d.local.length} more are local-only.${fwOn} Ports 135, 139 and 445 are standard Windows services.${list}` };
      },
    },
    {
      id: 'routing',
      name: 'Routing & adapter sanity',
      description: 'Finds competing default routes and adapters that hold a route without a valid address — the cause of "it works on Wi-Fi until I plug the cable in" and half-connected VPNs — and shows which DNS servers each adapter uses.',
      params: [],
      steps: [
        { id: 'routes', cmd: 'route-print', label: 'Read the routing table', check: 'routes', table: true },
        { id: 'ip', cmd: 'ipconfig-all', label: 'Read every adapter', check: 'ipconfig', table: true },
      ],
      verdict(r, p, ctx, R) {
        const defaults = R.routes?.data?.defaults || [];
        const adapters = R.ip?.data?.adapters || [];
        if (!defaults.length) return { tone: 'fail', text: 'There is no default route, so nothing beyond your own network is reachable. The adapter has no gateway: check DHCP or the static settings.', actions: [{ label: 'Copy: ipconfig /renew', copy: 'ipconfig /renew' }] };
        const owner = (d) => adapters.find((a) => a.ipv4.includes(d.iface) || a.apipa.includes(d.iface) || a.name === d.iface);
        const lines = defaults.map((d, i) => { const a = owner(d); return `  ${i === 0 ? '▶' : '•'} ${a ? a.name : d.iface}: via ${d.gateway}, metric ${d.metric}${a && !a.ipv4.length ? ' — NO VALID ADDRESS' : ''}`; });
        const dns = adapters.filter((a) => a.dns.length).map((a) => `  • ${a.name}: ${a.dns.join(', ')}`);
        const detail = `\nDefault routes (▶ wins):\n${lines.join('\n')}${dns.length ? `\nDNS servers per adapter:\n${dns.join('\n')}` : ''}`;
        const winner = owner(defaults[0]);
        if (winner && !winner.ipv4.length) return { tone: 'fail', text: `The winning default route belongs to "${winner.name}", which has no valid IP address — traffic is being sent into a dead adapter. Disable that adapter (or fix its cable / DHCP), and the next route takes over.${detail}` };
        const dead = defaults.slice(1).map(owner).filter((a) => a && !a.ipv4.length);
        if (dead.length) return { tone: 'warn', text: `"${dead.map((a) => a.name).join('", "')}" holds a default route but has no valid address. It is not winning right now, but it will the moment metrics change. Disable it or fix its connection.${detail}` };
        if (defaults.length > 1) return { tone: 'warn', text: `${defaults.length} adapters each have a working default route. Windows uses the lowest metric; the others are idle backups. With a VPN this is how "split" traffic happens, and each adapter may use different DNS servers.${detail}` };
        return { tone: 'pass', text: `One default route and it belongs to a healthy adapter — routing is unambiguous.${detail}` };
      },
    },
    {
      id: 'propagation',
      name: 'Did my DNS change propagate?',
      description: "Finds the domain's authoritative nameservers, asks them and four resolvers (yours, Cloudflare, Google, Quad9) for the same record, and shows who still serves an old answer.",
      params: [{ key: 'host', placeholder: 'e.g. www.example.com', type: 'host' }],
      steps: [
        { id: 'ns', cmd: 'nslookup', preset: 'type-ns', label: 'Find the authoritative nameservers', params: { host: '{host}' }, check: 'nsRecords' },
        { id: 'nsParent', cmd: 'nslookup', preset: 'type-ns', label: 'Look in the parent zone', params: { host: '{parent}' }, check: 'nsRecords', when: (R) => Boolean(R.ns) && !R.ns.data?.found },
        { id: 'own', cmd: 'nslookup', label: 'Ask your resolver', params: { host: '{host}' }, check: 'nslookup' },
        { id: 'cf', cmd: 'nslookup-server', label: 'Ask Cloudflare (1.1.1.1)', params: { host: '{host}', server: '1.1.1.1' }, check: 'nslookup' },
        { id: 'goog', cmd: 'nslookup-server', label: 'Ask Google (8.8.8.8)', params: { host: '{host}', server: '8.8.8.8' }, check: 'nslookup' },
        { id: 'quad9', cmd: 'nslookup-server', label: 'Ask Quad9 (9.9.9.9)', params: { host: '{host}', server: '9.9.9.9' }, check: 'nslookup' },
        { id: 'auth0', cmd: 'nslookup-server', label: 'Ask the first authoritative server', params: { host: '{host}', server: '{ns0}' }, check: 'nslookup', when: (R) => Boolean(R.ns?.data?.found || R.nsParent?.data?.found) },
        { id: 'auth1', cmd: 'nslookup-server', label: 'Ask the second authoritative server', params: { host: '{host}', server: '{ns1}' }, check: 'nslookup', when: (R) => ((R.ns?.data?.names || R.nsParent?.data?.names || []).length > 1) },
        // Big sites rotate or geo-balance their addresses. Asking the same server twice reveals that,
        // so differing answers are not mistaken for an unfinished change.
        { id: 'again', cmd: 'nslookup-server', label: 'Ask the first one again (rotation check)', params: { host: '{host}', server: '{ns0}' }, check: 'nslookup', when: (R) => ok(R.auth0) },
      ],
      verdict(r, p, ctx, R) {
        const fmt = (a) => (a === null ? 'no answer' : a.length ? a.join(', ') : 'IPv6 only');
        const resolvers = [['Your resolver', R.own], ['Cloudflare 1.1.1.1', R.cf], ['Google 8.8.8.8', R.goog], ['Quad9 9.9.9.9', R.quad9]];
        const names = R.ns?.data?.names || R.nsParent?.data?.names || [];
        const auth = [[names[0], R.auth0], [names[1], R.auth1]].filter(([, res]) => res);
        const table = `\n${[...auth.map(([n, res]) => `  ★ ${n} (authoritative): ${fmt(v4(res))}`), ...resolvers.map(([n, res]) => `  • ${n}: ${fmt(v4(res))}`)].join('\n')}`;
        const truth = auth.map(([, res]) => v4(res)).filter((a) => a && a.length);
        if (!truth.length) {
          const answers = resolvers.map(([, res]) => v4(res)).filter((a) => a && a.length);
          if (!answers.length) return { tone: 'fail', text: `Nobody returns an address for ${p.host}.${table}` };
          const agree = answers.every((a) => overlap(a, answers[0]));
          return { tone: agree ? 'warn' : 'fail', text: `The authoritative servers could not be asked directly, so this only compares public resolvers: they ${agree ? 'agree' : 'disagree'}.${table}` };
        }
        const first = v4(R.auth0), second = v4(R.again);
        const rotating = Boolean(first?.length && second?.length && !overlap(first, second));
        if (rotating) {
          // Exact addresses are meaningless for a rotating pool; compare network ranges (/16) instead.
          const net16 = (ip) => ip.split('.').slice(0, 2).join('.');
          const pool = new Set([...truth.flat(), ...second].map(net16));
          const outside = resolvers.filter(([, res]) => { const a = v4(res); return a && a.length && !a.some((ip) => pool.has(net16(ip))); }).map(([n]) => n);
          const ranges = [...pool].map((n) => `${n}.x.x`).join(', ');
          if (!outside.length) return { tone: 'pass', text: `${p.host} is served from a rotating or geo-balanced pool — the same authoritative server gave different addresses a moment apart — so resolvers are expected to differ. Every answer falls inside the published range (${ranges}), which is what "propagated" means for a name like this.${table}` };
          return { tone: 'warn', text: `${p.host} uses rotating addresses, so exact matches are not expected — but ${outside.join(', ')} answer${outside.length === 1 ? 's' : ''} from outside the range the authoritative servers publish (${ranges}). That is an old cached record; it clears when its TTL runs out.${table}`, actions: outside.includes('Your resolver') ? [flushAction] : [] };
        }
        if (truth.length > 1 && !overlap(truth[0], truth[1])) return { tone: 'fail', text: `The domain's own nameservers disagree with each other — the zone has not synchronised between them, so resolvers get either answer at random. Fix this at your DNS host first.${table}` };
        const behind = resolvers.filter(([, res]) => { const a = v4(res); return a && a.length && !overlap(a, truth[0]); }).map(([n]) => n);
        if (!behind.length) return { tone: 'pass', text: `Fully propagated: every resolver returns what the authoritative servers publish (${truth[0].join(', ')}).${table}` };
        return { tone: 'warn', text: `Not everywhere yet: ${behind.join(', ')} still return${behind.length === 1 ? 's' : ''} a different answer from the authoritative servers. Those are cached copies that update when the old record's TTL runs out — nothing to fix, just wait. (Sites on a CDN or geo-DNS legitimately give different answers per resolver.)${table}`, actions: behind.includes('Your resolver') ? [flushAction] : [] };
      },
    },
  );

  /* ================= third set: checks ================= */
  const num = (s) => Number(String(s ?? '').replace(',', '.'));
  const listValue = (out, label) => ((out.match(new RegExp(`^\\s*${label}\\s*:[ \\t]*(.*)$`, 'im')) || [])[1] || '').trim();
  const isWindows = (ctx) => !ctx?.platform || ctx.platform === 'win32';
  const PUBLIC_CA = /DigiCert|Let's Encrypt|ISRG|Google Trust|\bGTS\b|Sectigo|USERTrust|GlobalSign|Amazon|Cloudflare|GoDaddy|Starfield|Entrust|Microsoft|SSL\.com|Buypass|IdenTrust|Certum|Actalis|ZeroSSL|HARICA|SwissSign|QuoVadis|\bWE\d\b|\bWR\d\b|\bE\d{1,2}\b|\bR\d{1,2}\b/i;
  const INTERCEPTOR = /Zscaler|Fortinet|FortiGate|Palo Alto|Sophos|Blue ?Coat|Symantec Web|Netskope|Umbrella|Cisco|Kaspersky|ESET|Avast|AVG|Bitdefender|McAfee|Forcepoint|Barracuda|WatchGuard|SonicWall|Check Point|Squid|mitmproxy|Fiddler|Charles Proxy/i;

  Object.assign(CHECKS, {
    wlanNetworks(out, params, ctx, meta) {
      if (/location permission|requires elevation/i.test(out)) return { status: 'info', summary: 'Windows is withholding the list of nearby networks (needs Location permission or an administrator shell)', data: { blocked: true } };
      const aps = [];
      let ssid = '', cur = null;
      for (const line of out.split(/\r?\n/)) {
        let m;
        if ((m = line.match(/^SSID \d+\s*:\s*(.*)$/))) { ssid = m[1].trim(); continue; }
        if ((m = line.match(/^\s+BSSID \d+\s*:\s*(\S+)/))) { cur = { ssid, bssid: m[1].toLowerCase(), signal: 0, channel: 0 }; aps.push(cur); continue; }
        if (!cur) continue;
        if ((m = line.match(/^\s+Signal\s*:\s*(\d+)%/))) cur.signal = Number(m[1]);
        else if ((m = line.match(/^\s+Channel\s*:\s*(\d+)/))) cur.channel = Number(m[1]);
      }
      if (!aps.length) return { status: 'info', summary: 'No nearby networks were listed', data: { total: 0 } };
      const link = meta?.R?.link?.data || {};
      const is24 = (ch) => ch >= 1 && ch <= 14;
      const audible = aps.filter((a) => a.signal >= 35 && a.bssid !== link.bssid);
      const clash = link.channel ? audible.filter((a) => (is24(link.channel) ? is24(a.channel) && Math.abs(a.channel - link.channel) <= 4 : a.channel === link.channel)) : [];
      let suggestion = null;
      if (link.channel && is24(link.channel)) {
        const load = [1, 6, 11].map((ch) => ({ ch, n: audible.filter((a) => is24(a.channel) && Math.abs(a.channel - ch) <= 4).length })).sort((a, b) => a.n - b.n);
        if (load[0].ch !== link.channel && load[0].n < clash.length) suggestion = load[0].ch;
      }
      const summary = `${aps.length} access points in range${link.channel ? `; ${clash.length} strong one${clash.length === 1 ? '' : 's'} share or overlap your channel ${link.channel}` : ''}`;
      return { status: clash.length >= 3 ? 'warn' : 'pass', summary, data: { total: aps.length, clash: clash.length, suggestion } };
    },

    mtu(out, params, ctx, meta) {
      const size = meta?.step?.size;
      if (/needs to be fragmented|Message too long|frag(mentation)? needed/i.test(out)) return { status: 'info', summary: `${size}-byte packets are too big for this path`, data: { fits: false, size } };
      if (/Reply from [^\r\n]*(bytes=|TTL=)/i.test(out) || /bytes from/i.test(out)) return { status: 'pass', summary: `${size}-byte packets get through unfragmented — path MTU is at least ${size + 28}`, data: { fits: true, size } };
      return { status: 'info', summary: `No reply to ${size}-byte packets (filtered, or lost)`, data: { fits: null, size } };
    },

    mxRecords(out) {
      const found = [
        ...[...out.matchAll(/MX preference = (\d+), mail exchanger = (\S+)/gi)].map((m) => ({ pref: Number(m[1]), host: m[2] })),
        ...[...out.matchAll(/mail exchanger = (\d+)\s+(\S+)/gi)].map((m) => ({ pref: Number(m[1]), host: m[2] })),
      ].map((r) => ({ pref: r.pref, host: r.host.replace(/\.$/, '').toLowerCase() })).sort((a, b) => a.pref - b.pref);
      if (!found.length) {
        if (/Non-existent domain|NXDOMAIN/i.test(out)) return { status: 'fail', summary: 'The domain does not exist in DNS', data: { nxdomain: true } };
        return { status: 'fail', summary: 'No MX records — this domain is not set up to receive email', data: { none: true } };
      }
      if (!found[0].host) return { status: 'fail', summary: 'The domain publishes a "null MX": it declares that it accepts no email', data: { nullMx: true } };
      return { status: 'pass', summary: `${found.length} mail server${found.length === 1 ? '' : 's'}: ${found.slice(0, 3).map((r) => `${r.host} (priority ${r.pref})`).join(', ')}`, data: { records: found }, capture: { mx0: found[0].host } };
    },

    txtFind(out, params, ctx, meta) {
      const what = meta?.step?.what || 'TXT';
      const joined = out.replace(/"\s*\r?\n?\s*"/g, '');
      const m = joined.match(new RegExp(`${meta?.step?.find}[^"\\r\\n]*`, 'i'));
      if (!m) return { status: 'warn', summary: `No ${what} record is published`, data: { found: false } };
      const policy = (m[0].match(/\bp=(\w+)/i) || [])[1];
      return { status: 'pass', summary: `${what}: ${m[0].trim().slice(0, 150)}`, data: { found: true, record: m[0].trim(), policy } };
    },

    osHealth(out, params, ctx) {
      if (!isWindows(ctx)) return { status: 'info', summary: out.split(/\r?\n/).find((l) => l.trim())?.trim().slice(0, 140) || 'uptime read' };
      const uptime = num(listValue(out, 'UptimeDays')), total = num(listValue(out, 'MemoryTotalGB')), free = num(listValue(out, 'MemoryFreeGB'));
      if (!Number.isFinite(uptime) || !total) return { status: 'info', summary: 'Could not read uptime and memory' };
      const usedPct = Math.round(((total - free) / total) * 100);
      const data = { os: listValue(out, 'OS'), version: listValue(out, 'Version'), uptime, total, free, usedPct };
      const problems = [];
      if (uptime > 14) problems.push(`up ${uptime} days without a restart`);
      if (usedPct > 90) problems.push(`memory ${usedPct}% used`);
      const summary = `${data.os} ${data.version} · up ${uptime} days · memory ${usedPct}% used (${free} of ${total} GB free)`;
      return { status: problems.length ? 'warn' : 'pass', summary, data: { ...data, problems } };
    },

    disks(out, params, ctx) {
      if (!isWindows(ctx)) return { status: 'info', summary: 'See the output for file-system usage' };
      const t = P.fixedWidth(out);
      if (!t) return { status: 'info', summary: 'Could not read disk space' };
      const c = (n) => t.columns.indexOf(n);
      const drives = t.rows.map((r) => ({ drive: r[c('Drive')], size: num(r[c('SizeGB')]), free: num(r[c('FreeGB')]), pct: num(r[c('FreePct')]) })).filter((d) => d.drive);
      const low = drives.filter((d) => d.pct < 10);
      const summary = drives.map((d) => `${d.drive} ${d.pct}% free (${d.free} of ${d.size} GB)`).join(' · ');
      return { status: low.some((d) => d.pct < 5) ? 'fail' : low.length ? 'warn' : 'pass', summary, data: { drives, low } };
    },

    hung(out) {
      if (/No tasks are running/i.test(out)) return { status: 'pass', summary: 'No programs are hung', data: { hung: [] } };
      const t = P.fixedWidth(out);
      const names = t ? [...new Set(t.rows.map((r) => r[0]))] : [];
      if (!names.length) return { status: 'pass', summary: 'No programs are hung', data: { hung: [] } };
      return { status: 'warn', summary: `Not responding: ${names.join(', ')}`, data: { hung: names } };
    },

    topMemory(out) {
      const t = P.fixedWidth(out);
      if (!t) return { status: 'info', summary: 'Could not read the process list' };
      const nameCol = t.columns.indexOf('Image Name'), memCol = t.columns.indexOf('Mem Usage');
      const totals = new Map();
      for (const r of t.rows) {
        const kb = Number(String(r[memCol] || '').replace(/[^\d]/g, ''));
        const e = totals.get(r[nameCol]) || { name: r[nameCol], kb: 0, n: 0 };
        e.kb += kb; e.n += 1;
        totals.set(r[nameCol], e);
      }
      const top = [...totals.values()].sort((a, b) => b.kb - a.kb).slice(0, 5);
      const gb = (kb) => (kb > 1048576 ? `${(kb / 1048576).toFixed(1)} GB` : `${Math.round(kb / 1024)} MB`);
      return { status: 'info', summary: `Biggest memory users: ${top.map((e) => `${e.name} ${gb(e.kb)}${e.n > 1 ? ` (${e.n} processes)` : ''}`).join(' · ')}`, data: { top } };
    },

    hotfix(out) {
      const t = P.fixedWidth(out);
      if (!t || !t.rows.length) return { status: 'info', summary: 'No dated updates were listed' };
      const days = num(t.rows[0][t.columns.indexOf('DaysAgo')]);
      const id = t.rows[0][t.columns.indexOf('HotFixID')];
      const summary = `Latest update ${id}, ${days} day${days === 1 ? '' : 's'} ago`;
      return { status: days > 60 ? 'warn' : 'pass', summary: days > 60 ? `${summary} — Windows Update may be stuck or paused` : summary, data: { days, id } };
    },

    timeOffset(out, params, ctx) {
      if (!isWindows(ctx)) return { status: 'info', summary: 'See the output for the clock status' };
      const offsets = [...out.matchAll(/([+-]\d+\.\d+)s/g)].map((m) => Number(m[1]));
      if (!offsets.length) return { status: 'info', summary: 'The time server did not answer (NTP uses UDP 123, which some networks block)', data: { reachable: false } };
      const worst = offsets.reduce((a, b) => (Math.abs(b) > Math.abs(a) ? b : a), 0);
      const abs = Math.abs(worst);
      const text = abs < 1 ? `${Math.round(abs * 1000)} ms` : abs < 120 ? `${abs.toFixed(1)} seconds` : `${Math.round(abs / 60)} minutes`;
      const dir = worst > 0 ? 'behind' : 'ahead of';
      const data = { offset: worst, reachable: true };
      if (abs < 1) return { status: 'pass', summary: `Clock is within ${text} of internet time`, data };
      if (abs < 60) return { status: 'warn', summary: `Clock is ${text} ${dir} internet time`, data };
      return { status: 'fail', summary: `Clock is ${text} ${dir} internet time`, data };
    },

    w32status(out) {
      if (/Access is denied|0x80070005/i.test(out)) return { status: 'info', summary: 'Sync details need an administrator shell — the measurement above is what matters' };
      // On a PC that is not joined to a domain the service is trigger-started on a schedule, so "stopped" is its normal state.
      if (/has not been started/i.test(out)) return { status: 'info', summary: 'The Windows Time service is idle right now — normal on a home PC, where Windows starts it on a schedule to sync', data: { idle: true } };
      const source = listValue(out, 'Source'), last = listValue(out, 'Last Successful Sync Time');
      if (!source) return { status: 'info', summary: 'No sync status available' };
      if (/Local CMOS|Free-running/i.test(source)) return { status: 'warn', summary: `Not syncing with any server (source: ${source})`, data: { source, unsynced: true } };
      return { status: 'pass', summary: `Syncs with ${source}${last ? ` · last sync ${last}` : ''}`, data: { source, last } };
    },

    established(out, params, ctx, meta) {
      const t = P.fixedWidth(out);
      if (!t) return { status: 'info', summary: 'Could not read the connection list' };
      const ra = t.columns.indexOf('RemoteAddress'), rp = t.columns.indexOf('RemotePort'), op = t.columns.indexOf('OwningProcess');
      const names = meta?.R?.procs?.data?.map || {};
      const by = new Map();
      let total = 0;
      const hosts = new Set();
      for (const r of t.rows) {
        const addr = r[ra];
        if (!addr || /^(127\.|::1$|0\.0\.0\.0$|::$)/.test(addr)) continue;
        total += 1;
        hosts.add(addr);
        const name = names[r[op]] || `PID ${r[op]}`;
        const e = by.get(name) || { name, n: 0, ports: new Set(), lan: 0 };
        e.n += 1; e.ports.add(Number(r[rp]));
        if (P.classifyIp(addr) === 'private') e.lan += 1;
        by.set(name, e);
      }
      const programs = [...by.values()].sort((a, b) => b.n - a.n).map((e) => ({ ...e, ports: [...e.ports].sort((a, b) => a - b) }));
      const unusual = programs.filter((e) => e.ports.some((p) => ![80, 443].includes(p)));
      return { status: 'info', summary: `${total} live connections from ${programs.length} programs to ${hosts.size} addresses${programs[0] ? ` — busiest: ${programs[0].name} (${programs[0].n})` : ''}`, data: { total, programs, unusual } };
    },

    dhcpLease(out, params, ctx) {
      if (!isWindows(ctx)) return { status: 'info', summary: 'Lease details are only read on Windows' };
      const t = P.ipconfig(out);
      if (!t) return { status: 'fail', summary: 'Could not read adapter configuration' };
      const groups = new Map();
      for (const [adapter, key, value] of t.rows) {
        const name = adapter.replace(/^.*adapter\s+/i, '');
        if (!groups.has(name)) groups.set(name, {});
        const g = groups.get(name);
        if (!(key in g)) g[key] = value.replace(/\(.*\)$/, '').trim();
      }
      const name = (ctx?.adapter && groups.has(ctx.adapter)) ? ctx.adapter : [...groups.keys()].find((n) => groups.get(n)['IPv4 Address']);
      const g = name && groups.get(name);
      if (!g) return { status: 'fail', summary: 'No adapter has an IPv4 address' };
      const ip = g['IPv4 Address'] || g['Autoconfiguration IPv4 Address'] || '';
      if (!ip || ip.startsWith('169.254.')) return { status: 'fail', summary: `${name} has ${ip ? `only a self-assigned address (${ip})` : 'no address'} — no DHCP server answered` };
      if (!/yes/i.test(g['DHCP Enabled'] || '')) return { status: 'info', summary: `${name} uses a static address (${ip}) — there is no lease to expire`, data: { static: true, ip } };
      const parse = (s) => Date.parse(String(s || '').replace(/^[A-Za-z]+,\s*/, ''));
      const expires = parse(g['Lease Expires']), obtained = parse(g['Lease Obtained']);
      const server = g['DHCP Server'];
      const data = { adapter: name, ip, server, expires, obtained };
      const capture = IPV4.test(server || '') ? { dhcpServer: server } : {};
      if (Number.isFinite(expires)) {
        const hours = (expires - Date.now()) / 3600000;
        if (hours < 0) return { status: 'fail', summary: `${name}: the lease on ${ip} expired ${Math.round(-hours)} h ago and was not renewed`, data, capture };
        const left = hours > 48 ? `${Math.round(hours / 24)} days` : `${Math.round(hours)} h`;
        return { status: 'pass', summary: `${name}: ${ip} leased from ${server || 'an unknown server'}, ${left} left`, data, capture };
      }
      return { status: 'pass', summary: `${name}: ${ip} leased from ${server || 'an unknown server'} (expires ${g['Lease Expires'] || 'unknown'})`, data, capture };
    },

    conflicts(out) {
      if (/No address-conflict events/i.test(out)) return { status: 'pass', summary: 'No address-conflict events in the System log', data: { count: 0 } };
      const whens = [...out.matchAll(/^When\s*:\s*(.+)$/gim)].map((m) => m[1].trim());
      if (!whens.length) return { status: 'info', summary: 'The System log could not be read' };
      // An old event is history, not a current fault.
      const ageDays = Math.floor((Date.now() - Date.parse(whens[0].replace(' ', 'T'))) / 86400000);
      const data = { count: whens.length, latest: whens[0], ageDays };
      if (Number.isFinite(ageDays) && ageDays > 30) return { status: 'info', summary: `Last address conflict was logged ${ageDays} days ago (${whens[0]}) — nothing recent`, data };
      return { status: 'warn', summary: `${whens.length} address-conflict event${whens.length === 1 ? '' : 's'} logged — most recent ${whens[0]}`, data };
    },

    winhttp(out) {
      if (/Direct access/i.test(out)) return { status: 'pass', summary: 'No system-wide (WinHTTP) proxy', data: { proxy: null } };
      const server = listValue(out, 'Proxy Server\\(s\\)');
      return { status: 'info', summary: `System-wide proxy: ${server || 'configured'}`, data: { proxy: server || true } };
    },

    userProxy(out) {
      const enabled = listValue(out, 'ProxyEnable') === '1';
      const server = listValue(out, 'ProxyServer'), pac = listValue(out, 'AutoConfigURL');
      if (enabled && server) return { status: 'info', summary: `Your account sends web traffic through the proxy ${server}`, data: { proxy: server, pac } };
      if (pac) return { status: 'info', summary: `Your account uses a proxy auto-config script: ${pac}`, data: { proxy: null, pac } };
      return { status: 'pass', summary: 'No proxy configured for your account', data: { proxy: null, pac: null } };
    },

    certIssuer(out) {
      const issuer = listValue(out, 'Issuer'), subject = listValue(out, 'Subject');
      if (!issuer) return { status: 'fail', summary: `Could not complete a TLS connection: ${(out.match(/Exception calling[^\r\n]*|error[^\r\n]*/i) || ['no certificate returned'])[0].slice(0, 140)}` };
      const days = num(listValue(out, 'DaysLeft'));
      const trusted = /true/i.test(listValue(out, 'TrustedByWindows'));
      const org = (issuer.match(/O=("[^"]+"|[^,]+)/) || [])[1]?.replace(/"/g, '') || (issuer.match(/CN=([^,]+)/) || [])[1] || issuer;
      const data = { issuer, subject, org, days, trusted };
      if (INTERCEPTOR.test(issuer)) return { status: 'warn', summary: `Issued by ${org} — that is a security product re-signing your HTTPS traffic, not the site's real certificate`, data: { ...data, intercepted: true } };
      if (!trusted) return { status: 'fail', summary: `Issued by ${org}, which Windows does not trust`, data };
      if (PUBLIC_CA.test(issuer)) return { status: days < 14 ? 'warn' : 'pass', summary: `Issued by ${org} (a public certificate authority) · ${days} days left`, data };
      return { status: 'info', summary: `Issued by ${org} — trusted by this PC but not a public authority I recognise; on a company PC that usually means HTTPS inspection`, data: { ...data, unusual: true } };
    },

    /* Quick TCP port test: the command states the outcome itself, within 5 seconds. */
    tcpProbe(out, params, ctx) {
      if (!isWindows(ctx)) return CHECKS.tnc(out, params, ctx, {});
      const result = listValue(out, 'Result').toLowerCase();
      const ms = num(listValue(out, 'Millis'));
      if (result === 'open') return { status: 'pass', summary: `TCP ${params.port} open (${ms} ms)`, data: { open: true, ms } };
      if (result === 'refused') return { status: 'fail', summary: `TCP ${params.port} refused — host is up, nothing is listening`, data: { kind: 'refused', ms } };
      if (result === 'timeout') return { status: 'fail', summary: `TCP ${params.port} no response within 5 s — filtered by a firewall, or host down`, data: { kind: 'filtered', ms } };
      if (result === 'dns-failure') return { status: 'fail', summary: 'The host name could not be resolved', data: { kind: 'dns' } };
      return { status: 'fail', summary: `TCP ${params.port}: ${result || 'no result'}`.slice(0, 160), data: { kind: 'closed' } };
    },

    /* Local network scan: count what was found and sort it into recognisable groups. */
    lanScan(out) {
      const err = out.match(/SCAN-ERROR:\s*([^\r\n]+)/);
      if (err) return { status: 'fail', summary: err[1] };
      const t = P.parse('lan-scan', out, 'win32');
      if (!t || !t.rows.length) return { status: 'fail', summary: 'The scan returned no devices' };
      const c = (n) => t.columns.indexOf(n);
      const devices = t.rows.map((r) => ({ ip: r[c('IP')], name: r[c('Name')], mac: r[c('MAC')], maker: r[c('Manufacturer')] || '', replied: r[c('Ping')] === 'replied', note: r[c('Note')] }));
      const others = devices.filter((d) => d.note !== 'this PC');
      const silent = others.filter((d) => !d.replied).length;
      const randomised = others.filter((d) => /randomised/.test(d.maker)).length;
      const unknown = others.filter((d) => !d.maker).length;
      const range = (out.match(/Scanned (\S+) on (.+?) in ([\d.,]+) s/) || []);
      const summary = `${others.length} other device${others.length === 1 ? '' : 's'} on ${range[1] || 'your subnet'}${range[3] ? ` in ${range[3]} s` : ''} — ${silent} ignore ping and were found through ARP`;
      return { status: 'pass', summary, data: { devices, others, silent, randomised, unknown, range: range[1], adapter: range[2] } };
    },

    ipv6addr(out, params, ctx) {
      let globals;
      if (isWindows(ctx)) {
        const t = P.ipconfig(out);
        globals = (t ? t.rows : []).filter((r) => /^(Temporary )?IPv6 Address$/.test(r[1])).map((r) => r[2].replace(/\(.*\)$/, '').trim()).filter((a) => !/^fe80/i.test(a));
      } else {
        globals = [...out.matchAll(/inet6 ([0-9a-f:]+)/gi)].map((m) => m[1]).filter((a) => !/^(fe80|::1)/i.test(a));
      }
      // fc00::/7 (addresses starting fc or fd) are "unique local": private, like 192.168.x.x — often from a VPN. Not internet IPv6.
      const local = globals.filter((a) => /^f[cd]/i.test(a));
      globals = globals.filter((a) => !/^f[cd]/i.test(a));
      if (!globals.length && local.length) return { status: 'info', summary: `Only a private IPv6 address (${local[0]}, the kind a VPN assigns) — no IPv6 route to the internet`, data: { has: false, local } };
      if (!globals.length) return { status: 'info', summary: 'No global IPv6 address — this network is IPv4-only (link-local addresses do not count)', data: { has: false } };
      return { status: 'pass', summary: `Global IPv6 address: ${globals[0]}${globals.length > 1 ? ` (+${globals.length - 1} more)` : ''}`, data: { has: true, globals } };
    },
  });

  /* ================= third set of playbooks ================= */
  const MTU_SIZES = [1472, 1464, 1452, 1400, 1372, 1272];
  const SERVICE_PORTS = [[443, 'HTTPS'], [80, 'HTTP'], [22, 'SSH'], [3389, 'Remote Desktop'], [445, 'SMB file sharing'], [1433, 'SQL Server']];
  const hostLooksDead = (R) => failed(R.ping) && R.p443?.data?.kind === 'filtered' && R.p80?.data?.kind === 'filtered';

  PLAYBOOKS.push(
    {
      id: 'wifi',
      name: 'Wi-Fi health',
      description: 'Signal strength, band, radio mode and link rate of your connection, how many neighbouring access points crowd your channel, and how steady the link to your router really is.',
      params: [],
      steps: [
        { id: 'link', cmd: 'netsh', label: 'Read your Wi-Fi link', check: 'wlan' },
        { id: 'nets', cmd: 'netsh', preset: 'wlan-networks', label: 'Survey nearby access points', check: 'wlanNetworks', when: (R) => Boolean(R.link?.data?.wifi) },
        { id: 'gw', cmd: 'ping', preset: 'x20', label: '20 pings to your router', params: { host: '{gateway}' }, check: 'ping', warnMs: 30 },
      ],
      verdict(r, p, ctx, R) {
        const g = R.gw?.data;
        const link = g ? ` The link to your router measures avg ${g.avg} ms, worst ${g.max} ms, jitter ${g.jitter} ms${g.loss ? `, ${g.loss}% loss` : ''} — ${warned(R.gw) || g.jitter > 15 ? 'unsteady; a good Wi-Fi link is under 10 ms with little jitter.' : 'steady.'}` : '';
        if (R.link?.data?.blocked) return { tone: warned(R.gw) ? 'warn' : 'pass', text: `Windows 11 hides Wi-Fi details from programs unless Location services are on (Settings → Privacy & security → Location) or NetDeck runs as administrator, so signal and channel could not be read.${link}` };
        if (!R.link?.data?.wifi) return { tone: 'pass', text: `This PC is not using Wi-Fi right now (${R.link?.summary || 'no wireless link'}).${link}` };
        const d = R.link.data;
        const notes = [...(d.problems || [])];
        if (R.nets?.data?.clash >= 3) notes.push(`${R.nets.data.clash} strong neighbouring access points share or overlap your channel${R.nets.data.suggestion ? ` — channel ${R.nets.data.suggestion} is the quietest of 1 / 6 / 11` : ''}`);
        if (notes.length || warned(R.gw)) return { tone: 'warn', text: `Wi-Fi is connected (${R.link.summary.split(' — ')[0]}), with room to improve: ${notes.join('; ') || 'the link is unsteady'}.${link}` };
        return { tone: 'pass', text: `Wi-Fi looks healthy: ${R.link.summary}.${R.nets?.data?.total ? ` ${R.nets.data.total} access points are in range and your channel is not crowded.` : ''}${link}` };
      },
    },
    {
      id: 'services',
      name: 'Can I reach that service?',
      description: 'Tests the common service ports on one host in a single run — HTTPS, HTTP, SSH, Remote Desktop, SMB file sharing, SQL Server — and says which are open, refused or filtered. Only test hosts you are responsible for.',
      params: [{ key: 'host', placeholder: 'e.g. fileserver or 192.168.1.10', type: 'host' }],
      steps: [
        { id: 'dns', cmd: 'nslookup', label: 'Resolve the host name', params: { host: '{host}' }, check: 'nslookup', skipIf: isIp, stopOnFail: true },
        { id: 'ping', cmd: 'ping', label: 'Ping the host', params: { host: '{host}' }, check: 'ping' },
        ...SERVICE_PORTS.map(([port, name], i) => ({ id: `p${port}`, cmd: 'tcp-probe', label: `${name} (${port})`, params: { host: '{host}', port: String(port) }, check: 'tcpProbe', when: i < 2 ? undefined : (R) => !hostLooksDead(R) })),
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.dns)) return { tone: 'fail', text: `"${p.host}" does not resolve (${R.dns.summary}). On a local network, try the IP address, or check the name with nbtstat.` };
        const rows = SERVICE_PORTS.map(([port, name]) => { const res = R[`p${port}`]; return { port, name, res, state: !res ? 'not tested' : ok(res) ? 'OPEN' : res.data?.kind === 'refused' ? 'refused (nothing listening)' : res.data?.kind === 'filtered' ? 'filtered (no response)' : 'closed' }; });
        const table = `\n${rows.map((x) => `  ${x.state === 'OPEN' ? '✓' : '•'} ${x.name} ${x.port}: ${x.state}`).join('\n')}`;
        const open = rows.filter((x) => x.state === 'OPEN');
        if (hostLooksDead(R)) return { tone: 'fail', text: `${p.host} answers neither ping nor web ports, so the remaining ports were skipped: the host is off, unreachable from here, or drops everything.${table}` };
        if (!open.length) return { tone: 'fail', text: `${p.host} is ${ok(R.ping) ? 'up (it answers ping)' : 'not answering ping'}, but none of the tested services is reachable. "Refused" means nothing is listening; "filtered" means a firewall is dropping the connection.${table}` };
        return { tone: 'pass', text: `${p.host} is reachable on ${open.map((x) => `${x.name} (${x.port})`).join(', ')}.${table}` };
      },
    },
    {
      id: 'mtu',
      name: 'MTU check — "some sites hang"',
      description: "Sends don't-fragment pings of decreasing size to find the largest packet your path carries (its MTU, Maximum Transmission Unit). Explains sites that half-load, stalled uploads and flaky VPNs.",
      params: [],
      steps: [
        { id: 'base', cmd: 'ping', label: 'Ordinary ping first', params: { host: '1.1.1.1' }, check: 'ping', stopOnFail: true },
        ...MTU_SIZES.map((size, i) => ({ id: `m${size}`, cmd: 'ping', preset: `mtu-${size}`, size, label: `${size}-byte packet, don't fragment`, params: { host: '1.1.1.1' }, check: 'mtu', when: i === 0 ? undefined : (R) => !MTU_SIZES.slice(0, i).some((s) => R[`m${s}`]?.data?.fits === true) })),
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.base)) return { tone: 'fail', text: 'Ordinary pings do not get through, so packet size cannot be tested. Start with the internet playbook.', actions: [{ label: 'Run "Can\'t reach the internet?"', playbook: 'internet' }] };
        const fit = MTU_SIZES.map((s) => R[`m${s}`]).find((res) => res?.data?.fits === true);
        if (!fit) {
          const sawFrag = MTU_SIZES.some((s) => R[`m${s}`]?.data?.fits === false);
          return sawFrag
            ? { tone: 'fail', text: 'Even 1272-byte packets are rejected as too big — the path MTU is below 1300, which is unusually small. Look for a misconfigured tunnel or VPN.' }
            : { tone: 'warn', text: 'Large pings get no reply at all (not even a "too big" message), so something on the path filters them and the MTU cannot be measured this way. That same filtering is what makes MTU problems hard to see: connections simply stall.' };
        }
        const mtu = fit.data.size + 28;
        if (mtu >= 1500) return { tone: 'pass', text: 'Full-size 1500-byte packets pass unfragmented: the path MTU is the Ethernet standard and packet size is not your problem.' };
        const why = mtu >= 1492 ? 'typical of a PPPoE (DSL / some fibre) connection' : mtu >= 1440 ? 'typical of a light tunnel or a provider that encapsulates traffic' : 'typical of a VPN or tunnel adding its own headers';
        return { tone: 'warn', text: `The largest packet that crosses unfragmented is ${fit.data.size} bytes, so the path MTU is ${mtu} — ${why}. That is fine as long as "packet too big" messages get back to you; when a firewall blocks them, large transfers stall while small ones work (pages half-load, uploads hang, VPNs feel flaky). If you see those symptoms, set the adapter or VPN MTU to ${mtu}.` };
      },
    },
    {
      id: 'email',
      name: 'Email delivery check',
      description: "Looks up a domain's mail servers, tests whether you can reach them, and checks that SPF and DMARC records exist — the usual causes of mail that bounces or lands in spam.",
      params: [{ key: 'host', placeholder: 'e.g. example.com (the part after @)', type: 'host' }],
      steps: [
        { id: 'mx', cmd: 'nslookup', preset: 'type-mx', label: 'Find the mail servers (MX)', params: { host: '{host}' }, check: 'mxRecords' },
        { id: 'spf', cmd: 'nslookup', preset: 'type-txt', label: 'Look for an SPF record', params: { host: '{host}' }, check: 'txtFind', find: 'v=spf1', what: 'SPF' },
        { id: 'dmarc', cmd: 'nslookup', preset: 'type-txt', label: 'Look for a DMARC record', params: { host: '_dmarc.{host}' }, check: 'txtFind', find: 'v=DMARC1', what: 'DMARC' },
        { id: 'smtp', cmd: 'tcp-probe', label: 'Connect to the first mail server on port 25', params: { host: '{mx0}', port: '25' }, check: 'tcpProbe', when: (R) => ok(R.mx) },
      ],
      verdict(r, p, ctx, R) {
        if (failed(R.mx)) return { tone: 'fail', text: `${p.host} cannot receive email: ${R.mx.summary}. Mail sent to it bounces until MX records are published at the domain's DNS host.` };
        const notes = [];
        if (!R.spf?.data?.found) notes.push('no SPF record — receivers cannot tell which servers may send for this domain, so its mail is more likely to be marked as spam');
        if (!R.dmarc?.data?.found) notes.push('no DMARC record — nothing tells receivers what to do with forged mail, and large providers increasingly require one');
        else if (R.dmarc.data.policy === 'none') notes.push('DMARC is published but set to p=none (monitor only)');
        const smtp = failed(R.smtp) ? ' Port 25 on the mail server is not reachable from this PC — that is normal on home and many office connections, because providers block outbound port 25; mail programs submit on 587 or 465 instead. It only matters if this machine is itself a mail server.' : ok(R.smtp) ? ' The mail server accepts connections on port 25 from here.' : '';
        const mx = R.mx.data.records.slice(0, 3).map((x) => x.host).join(', ');
        if (notes.length) return { tone: 'warn', text: `${p.host} receives mail at ${mx}, but: ${notes.join('; ')}.${smtp}` };
        return { tone: 'pass', text: `${p.host} is set up properly: mail goes to ${mx}, and both SPF and DMARC${R.dmarc.data.policy ? ` (p=${R.dmarc.data.policy})` : ''} are published.${smtp}` };
      },
    },
    {
      id: 'pchealth',
      name: 'PC health snapshot',
      description: 'Uptime, memory pressure, disk space, hung programs, the biggest memory users and how recently Windows was patched — the quick triage for "my computer is slow".',
      params: [],
      steps: [
        { id: 'os', cmd: 'os-health', label: 'Uptime and memory', check: 'osHealth' },
        { id: 'disk', cmd: 'disk-free', label: 'Disk space', check: 'disks', table: true },
        { id: 'hung', cmd: 'tasklist', preset: 'hung', label: 'Programs not responding', check: 'hung' },
        { id: 'mem', cmd: 'tasklist', label: 'Biggest memory users', check: 'topMemory', table: true },
        { id: 'patch', cmd: 'get-hotfix', label: 'Latest Windows updates', check: 'hotfix', table: true },
      ],
      verdict(r, p, ctx, R) {
        const notes = [];
        const os = R.os?.data;
        if (os?.uptime > 14) notes.push(`it has been up ${os.uptime} days — restart it; long uptimes leak memory and hold back updates`);
        if (os?.usedPct > 90) notes.push(`memory is ${os.usedPct}% full${R.mem?.data?.top?.[0] ? ` (largest: ${R.mem.data.top[0].name})` : ''} — close programs or add RAM`);
        (R.disk?.data?.low || []).forEach((d) => notes.push(`drive ${d.drive} has only ${d.pct}% free (${d.free} GB) — Windows slows down and updates fail below about 10%`));
        if (R.hung?.data?.hung?.length) notes.push(`not responding: ${R.hung.data.hung.join(', ')}`);
        const lowerFirst = (s) => (s ? s[0].toLowerCase() + s.slice(1) : '');
        if (warned(R.patch)) notes.push(lowerFirst(R.patch.summary));
        const mem = R.mem?.summary ? `\n${R.mem.summary}.` : '';
        if (notes.length) return { tone: failed(R.disk) ? 'fail' : 'warn', text: `Things to deal with:\n${notes.map((n) => `  • ${n}`).join('\n')}${mem}` };
        return { tone: 'pass', text: `This PC is in good shape: ${R.os?.summary || ''}; ${R.disk?.summary || ''}; nothing hung; ${lowerFirst(R.patch?.summary)}.${mem}` };
      },
    },
    {
      id: 'timesync',
      name: 'Clock & time sync',
      description: "Measures this PC's clock against an internet time server. A clock that is minutes out causes certificate errors on every site and failed logins to work accounts.",
      params: [],
      steps: [
        { id: 'offset', cmd: 'w32tm', label: 'Compare with time.windows.com', check: 'timeOffset' },
        { id: 'status', cmd: 'w32tm', preset: 'status', label: 'Where the clock syncs from', check: 'w32status' },
      ],
      verdict(r, p, ctx, R) {
        const fix = [{ label: 'Copy: w32tm /resync', copy: 'w32tm /resync' }];
        if (failed(R.offset)) return { tone: 'fail', text: `${R.offset.summary}. That is enough to break HTTPS (certificates look expired or not yet valid) and domain logins (Kerberos allows 5 minutes). Set the time in Settings → Time & language → "Sync now", or run the command below in an administrator terminal. If it drifts back, the motherboard battery may be failing.`, actions: fix };
        if (warned(R.offset)) return { tone: 'warn', text: `${R.offset.summary} — not enough to break anything yet, but it should be within a second.${warned(R.status) ? ` ${R.status.summary}.` : ''}`, actions: fix };
        if (R.offset?.data?.reachable === false) return { tone: 'warn', text: `The time server could not be reached, so the clock could not be measured. ${R.status?.summary || ''}` };
        if (warned(R.status)) return { tone: 'warn', text: `The clock is accurate right now, but: ${R.status.summary}. It will drift over time.`, actions: fix };
        return { tone: 'pass', text: `${R.offset?.summary || 'Clock checked'}. ${R.status?.summary || ''}` };
      },
    },
    {
      id: 'outbound',
      name: 'Who is this PC talking to?',
      description: 'Every live outbound connection, grouped by the program that owns it — useful for spotting something unexpected phoning home, or what is using the connection right now.',
      params: [],
      steps: [
        { id: 'procs', cmd: 'tasklist-csv', label: 'Index running programs', check: 'processes' },
        { id: 'conns', cmd: 'get-nettcpconnection', preset: 'state-established', label: 'List established connections', check: 'established', table: true },
      ],
      verdict(r, p, ctx, R) {
        const d = R.conns?.data;
        if (!d) return { tone: 'warn', text: 'The connection list could not be read on this system.' };
        const lines = d.programs.slice(0, 12).map((e) => `  • ${e.name}: ${e.n} connection${e.n === 1 ? '' : 's'} — port${e.ports.length === 1 ? '' : 's'} ${e.ports.slice(0, 6).join(', ')}${e.ports.length > 6 ? '…' : ''}${e.lan === e.n ? ' (local network only)' : ''}`);
        const more = d.programs.length > 12 ? `\n  • …and ${d.programs.length - 12} more programs` : '';
        return { tone: 'pass', text: `${R.conns.summary}. Ports 80 and 443 are ordinary web traffic; anything else is listed so you can recognise it (22 SSH, 993 mail, 5228 Google push, 3478 calls…). Press "table" for every connection with its remote address.\n${lines.join('\n')}${more}` };
      },
    },
    {
      id: 'dhcp',
      name: 'DHCP lease & address conflicts',
      description: 'Whether your address is leased or static, who handed it out and when it expires, whether that DHCP server still answers, and whether Windows has logged another device using your address.',
      params: [],
      steps: [
        { id: 'lease', cmd: 'ipconfig-all', label: 'Read the lease', check: 'dhcpLease', table: true },
        { id: 'server', cmd: 'ping', label: 'Ping the DHCP server', params: { host: '{dhcpServer}' }, check: 'ping', when: (R) => Boolean(R.lease?.data?.server) && IPV4.test(R.lease.data.server) },
        { id: 'conflict', cmd: 'winevent-ipconflict', label: 'Look for address-conflict events', check: 'conflicts' },
      ],
      verdict(r, p, ctx, R) {
        const renew = [{ label: 'Copy: ipconfig /renew', copy: 'ipconfig /renew' }];
        if (failed(R.lease)) return { tone: 'fail', text: `${R.lease.summary}. Check the cable or Wi-Fi connection and that the router's DHCP service is on, then renew.`, actions: renew };
        if (warned(R.conflict)) return { tone: 'warn', text: `Windows has logged that another device used this PC's IP address (${R.conflict.summary}). Two devices sharing an address knock each other offline at random. Usual causes: a device with a hand-typed static address inside the router's DHCP range, or two DHCP servers on one network.${R.lease?.data?.static ? ' This PC is the one with the static address — move it outside the DHCP range or switch it to automatic.' : ''}`, actions: R.lease?.data?.static ? [] : renew };
        if (R.lease?.data?.static) return { tone: 'pass', text: `${R.lease.summary}. No conflicts are logged. Make sure the address sits outside your router's DHCP range so it is never handed to another device.` };
        if (failed(R.server)) return { tone: 'warn', text: `${R.lease.summary}, but that DHCP server no longer answers ping. If it is really gone, this PC keeps working until the lease runs out and then loses its address.` };
        return { tone: 'pass', text: `${R.lease?.summary}. The DHCP server answers, and there are no recent address conflicts${R.conflict?.data?.ageDays ? ` (the last one was ${R.conflict.data.ageDays} days ago)` : ''}.` };
      },
    },
    {
      id: 'proxy',
      name: 'Proxy & HTTPS inspection',
      description: 'Shows any proxy your PC is set to use, and reads the certificate a well-known site presents to you — if a security product or corporate gateway is re-signing your HTTPS traffic, its name appears as the issuer.',
      params: [],
      steps: [
        { id: 'system', cmd: 'netsh', preset: 'winhttp-show-proxy', label: 'System-wide proxy', check: 'winhttp' },
        { id: 'user', cmd: 'proxy-settings', label: 'Proxy for your account', check: 'userProxy' },
        { id: 'cert', cmd: 'tls-cert', label: 'Who signed example.com for you?', params: { host: 'example.com' }, check: 'certIssuer' },
      ],
      verdict(r, p, ctx, R) {
        const proxies = [R.system?.data?.proxy && `system-wide: ${R.system.data.proxy}`, R.user?.data?.proxy && `your account: ${R.user.data.proxy}`, R.user?.data?.pac && `auto-config script: ${R.user.data.pac}`].filter(Boolean);
        const proxyText = proxies.length ? `A proxy is configured (${proxies.join('; ')}).` : 'No proxy is configured.';
        const c = R.cert?.data;
        if (failed(R.cert)) return { tone: 'fail', text: `${proxyText} The certificate check failed: ${R.cert.summary}. If browsers show certificate warnings everywhere, check the PC's clock first.`, actions: [{ label: 'Run "Clock & time sync"', playbook: 'timesync' }] };
        if (c?.intercepted || c?.unusual) return { tone: 'warn', text: `${proxyText} Your HTTPS traffic is being inspected: example.com's certificate reaches you signed by "${c.org}" rather than a public authority. On a work PC this is normally company policy (the inspecting product can read that traffic). On a personal PC it is usually antivirus "web protection" — or something you should find and remove.` };
        if (proxies.length) return { tone: 'warn', text: `${proxyText} Web traffic goes through it, so if the proxy is slow or unreachable, everything is. Certificates are not being re-signed: example.com is signed by ${c?.org}.` };
        return { tone: 'pass', text: `${proxyText} HTTPS is not being intercepted either: example.com is signed by ${c?.org}, a public certificate authority, and Windows trusts it.` };
      },
    },
    {
      id: 'ipv6',
      name: 'IPv6 check',
      description: 'Whether your network offers IPv6 and, if it does, whether it actually works — half-working IPv6 makes sites hesitate for seconds before falling back to IPv4.',
      params: [],
      steps: [
        { id: 'addr', cmd: 'ipconfig-all', label: 'Do you have a global IPv6 address?', check: 'ipv6addr' },
        { id: 'aaaa', cmd: 'nslookup', preset: 'type-aaaa', label: 'Can DNS return IPv6 (AAAA) records?', params: { host: 'ipv6.google.com' }, check: 'nslookup' },
        { id: 'ping6', cmd: 'ping', preset: 'force-ipv6', label: 'Ping over IPv6', params: { host: 'ipv6.google.com' }, check: 'ping', when: (R) => Boolean(R.addr?.data?.has) },
        { id: 'web6', cmd: 'curl', preset: 'ipv6', label: 'Load a page over IPv6', params: { url: 'https://ipv6.google.com/' }, check: 'http', when: (R) => Boolean(R.addr?.data?.has) },
      ],
      verdict(r, p, ctx, R) {
        if (!R.addr?.data?.has && R.addr?.data?.local) return { tone: 'pass', text: `This network has no IPv6 route to the internet. The only IPv6 address is a private one (${R.addr.data.local[0]}), the kind a VPN or mesh network assigns for its own use. Everything reaches the internet over IPv4, and there is no half-working IPv6 to slow things down.` };
        if (!R.addr?.data?.has) return { tone: 'pass', text: 'This network is IPv4-only: your router or provider does not hand out IPv6 addresses. That is fine — everything works over IPv4, and there is no half-working IPv6 to slow things down.' };
        if (ok(R.ping6) || ok(R.web6)) return { tone: warned(R.ping6) ? 'warn' : 'pass', text: `IPv6 works: you have ${R.addr.data.globals[0]}, and an IPv6-only site ${ok(R.web6) ? 'loads' : 'answers ping'} (${R.ping6?.summary || R.web6?.summary}).` };
        return { tone: 'warn', text: `You have an IPv6 address (${R.addr.data.globals[0]}) but nothing is reachable over IPv6. This is the bad combination: programs try IPv6 first, wait for it to fail, then fall back to IPv4 — sites hesitate for a few seconds before loading. Restart the router; if it persists, turn IPv6 off on the router or the adapter until the provider fixes it.` };
      },
    },
  );

  PLAYBOOKS.push({
    id: 'scan',
    name: 'Scan my network',
    description: 'Finds every device on your own network: pings all the addresses in your subnet at once, then reads the ARP table for MAC addresses — which also reveals devices that ignore ping — and adds names and manufacturers where it can. Nothing to type; it only ever scans the private network this PC is on.',
    params: [],
    steps: [
      { id: 'scan', cmd: 'lan-scan', label: 'Sweep the subnet and read the ARP table', check: 'lanScan', table: true },
    ],
    verdict(r, p, ctx, R) {
      if (failed(R.scan)) return { tone: 'fail', text: `${R.scan.summary}` };
      const d = R.scan.data;
      const byMaker = new Map();
      d.others.forEach((x) => { const k = x.maker || 'unrecognised manufacturer'; byMaker.set(k, (byMaker.get(k) || 0) + 1); });
      const makers = [...byMaker.entries()].sort((a, b) => b[1] - a[1]).map(([k, n]) => `  • ${n} × ${k}`).join('\n');
      const router = d.devices.find((x) => x.note === 'router');
      const notes = [];
      if (d.randomised) notes.push(`${d.randomised} use a randomised private address — that is what phones, tablets and recent laptops do on Wi-Fi, so they cannot be matched to a manufacturer`);
      if (d.silent) notes.push(`${d.silent} never answered ping but showed up in the ARP table, which is normal for phones, TVs and smart-home devices`);
      return {
        tone: 'pass',
        text: `${d.others.length} other devices share ${d.range || 'your network'} with this PC${router ? ` (router: ${router.ip}${router.maker ? `, ${router.maker}` : ''})` : ''}. Press "table" for every address, MAC and manufacturer — sort by manufacturer to group them, and compare against what you expect to own.${notes.length ? ` Note: ${notes.join('; ')}.` : ''}\nBy manufacturer:\n${makers}\nAnything you cannot account for is worth tracking down: the router's own client list usually shows a name for each address.`,
      };
    },
  });

  /* ================= groups (order here is the order on the page) ================= */
  const GROUPS = [
    ['Connectivity', ['internet', 'website', 'slow', 'path', 'port', 'services', 'mtu', 'wifi']],
    ['DNS & email', ['dns', 'propagation', 'email']],
    ['Security & exposure', ['exposure', 'outbound', 'proxy']],
    ['This PC & local network', ['scan', 'lan', 'pchealth', 'timesync', 'routing', 'dhcp', 'ipv6']],
  ];
  for (const [group, ids] of GROUPS) ids.forEach((id, i) => { const pb = PLAYBOOKS.find((p) => p.id === id); if (pb) { pb.group = group; pb.order = i; } });
  PLAYBOOKS.forEach((pb) => { if (!pb.group) { pb.group = 'Other'; pb.order = 99; } });

  return {
    groups: () => [...GROUPS.map((g) => g[0]), ...(PLAYBOOKS.some((p) => p.group === 'Other') ? ['Other'] : [])],
    list: () => PLAYBOOKS,
    get: (id) => PLAYBOOKS.find((p) => p.id === id),
    check: (name, out, params, ctx, meta) => (CHECKS[name] ? CHECKS[name](out, params, ctx, meta) : { status: 'pass', summary: 'completed' }),
  };
})();
