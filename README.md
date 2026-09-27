# NetDeck

A searchable reference of network & system CLI commands with live execution, structured output, and guided troubleshooting playbooks. Zero dependencies — just Node.js.

## Run it

```
node server.js
```

Then open http://localhost:4573 (set `PORT` to change).

## Features

- **Search** by name, syntax or purpose (`/` focuses the search box)
- **Filter** by platform (Windows / Linux·macOS / PowerShell) and category
- **Side-by-side equivalents** — Windows command with its Linux/macOS counterparts, copy button on every row
- **Network context strip** — detects your adapter, IP, gateway, DNS servers and whether the shell is elevated; host inputs get one-click *fill* chips (gateway, DNS, 1.1.1.1, localhost, recent hosts)
- **▶ run** executes safe, read-only commands locally and streams output live. Each run opens its own **terminal tab**, so a slow `pathping` can keep going while you fire off quick lookups. Stop kills the process.
- **Table view** — for `netstat`, `arp`, `route print`, `ipconfig`, `tasklist`, `getmac`, `Get-NetTCPConnection`, `Resolve-DnsName` and the DNS cache, the raw text parses into a sortable, filterable table. Anything with a PID column is joined to process names, so `netstat -ano` shows *which program* owns each port.
- **Packet capture (timed)** — 10/30/60 s `pktmon` recording of this PC's own traffic, summarized into protocols, top internet hosts, LAN peers and DNS names looked up; a variant keeps a `.pcapng` on the Desktop for Wireshark. Needs Run as admin.
- **Packet capture (filtered)** — the timed capture with a pktmon filter by variant: DNS only, one host, one port, ARP & broadcast (20 s, admin).
- **Capture viewer** — the last capture as a packet table (time, direction, source, destination, protocol, bytes, decode), with DNS-only and TCP-SYN-only variants; no admin needed.
- **Packet counters (live)** — packets in/out/dropped per second on every adapter for 10/30/60 s, then a per-layer table (adapter, firewall, VPN and other filter drivers) with drop reasons, to locate where packets die. Needs Run as admin.
- **Speed test** — download/upload against Cloudflare's public test server with a line per second, idle latency, and latency under load with a bufferbloat grade. No account, nothing to install.
- **Connection stability monitor** — a ping a second to the router and 1.1.1.1 for 1/3/5/10 minutes, a line every 10 s with a delay bar chart, loss runs called out, and a verdict on whether dropouts are local or beyond the router.
- **Discover announcing devices** — mDNS/Bonjour + SSDP/UPnP discovery: devices answer with their own names, models and services; names feed the scan table for a week.
- **Device port probe** — 26 common device ports on one address in 2.5 s with a plain-English guess at what it is; a "probe" button sits on every scan row.
- **Scan log** — each scan is remembered locally: the table shows when a device was first seen, and the verdict lists what is new, gone or moved since the last scan.
- **Wi-Fi survey** — every access point in range with band/channel/signal/security, channel-load table, and a suggested quieter channel.
- **Adapter throughput (live)** — bytes in/out per second on every adapter for 15 s / 60 s / 3 min, a bar per second, and a verdict (idle vs. busy, % of link speed).
- **Per-process network activity** — connections and remote hosts per program (no admin); the "with traffic" variant attributes a 10 s pktmon capture to programs through their ports for bytes sent/received per program.
- **iperf3** — runnable when installed: client, reverse, 4 parallel streams, or one-shot server.
- **Firewall rule audit** — every enabled inbound allow rule scored by exposure (any address / any port / any program / public profile), most exposed first, with a verdict.
- **Listening ports — who and whether reachable** — program, Windows service, code signer, start time and firewall verdict per listening port.
- **DNS honesty check** — configured resolvers and their operators, real egress address, tampering and port-53 interception tests, VPN leak, DoH status.
- **Router check-up** — management ports (telnet!), admin page and certificate, UPnP on/off and every port it has forwarded from the internet.
- **Hosts file & DNS cache audit** — pinned security/update sites (malware), Docker/local aliases recognized, cache scanned for private answers, look-alike and random names.
- **Notes** — a note per run, kept in History and included in reports.
- **Compare** — line-by-line diff of any two runs of the same command or playbook (open tabs or History).
- **Report** — one self-contained HTML file per run (with Print/PDF), anonymization on by default: computer name, consistent fake addresses, MAC device halves.
- **Schedule** — a playbook every 5 min–3 h while NetDeck is open; unchanged runs replace the previous tab, changed results are kept, flagged and can notify.
- **Dashboard** — the third view: one screen that says how the network is right now. Eight status tiles (router and internet from the live 10 s ping, DNS, HTTPS and Wi-Fi from a three-second set of quick checks, DNS honesty / router check-up / devices from the latest run of those playbooks), then cards for this computer (ipconfig /all, lease, MAC and manufacturer, Wi-Fi link, uptime), the connection (the checks as rows with a one-line verdict), the network (from the scan log: devices, changes since the last scan, a bar per manufacturer), latency & loss over 10 min to 24 h (the health-strip pings, kept for a day, with loss marks and the results of longer monitors), speed tests (every run kept, with download/upload bars and the bufferbloat grade) the route to the internet (the last traceroute as a hop chain, colored by network, with the latency jump marked), traffic (adapter byte counters sampled every 6 s while the view is open, via the hidden `adapter-stats` command: rates, link utilization, totals since boot, a 10-minute chart) and security posture (the live firewall state plus the latest run of each security check, with a verdict line). **Snapshot** saves the whole dashboard as one self-contained HTML page, anonymized like a report. All inline SVG — no chart library. Every tile and row has a button that runs its source command or playbook in the terminal; the snapshot is kept in localStorage (`netdeck.dashboard.v1`; the time series in `netdeck.dashboard.series.v1`, fed from every saved run so the history's 30-entry limit does not lose them). Implemented in [public/dashboard.js](public/dashboard.js), which app.js hands its execute/startRun/runPlaybook functions.
- **Outage log** — a Dashboard card that catches the drops you never see. Once started, the backend itself (so it carries on with the window closed to the tray) pings the router and 1.1.1.1 (8.8.8.8 as a second opinion) every 5 s and records every outage — two or more failed checks in a row — with its start, length and where it failed: past the router (ISP or modem), between the PC and the router (Wi-Fi, cable, router), the PC disconnected, or unclear when the router ignores pings. Time NetDeck was not watching (closed, asleep) is kept as coverage gaps, never as downtime, and the first minute after watching starts is a grace period. The card shows totals, a day-by-day timeline for 24 h / 7 / 30 days, a verdict and the list; **Save report** writes one HTML file for the ISP; the desktop app can notify when the connection comes back. The log (90 days) is `outage-log.json` in the data folder. Implemented in [src-tauri/src/outage.rs](src-tauri/src/outage.rs) and the matching block in server.js (`/api/outage`); `NETDECK_OUTAGE_TEST=<file>` simulates outages for testing.
- **Network calculator** — the calculator icon beside the theme button (or Ctrl+K, "calc") opens a popup with nine tools, all computed in the page: IPv4 subnet (any mask notation, class, binary with colored network/subnet/host bits, same-subnet and hosts-needed checks), split & summarize (equal split, VLSM plan, range → CIDR, route summarization), IPv6 (RFC 5952 compression, type, prefix breakdown, EUI-64 detection, subnet listing), MAC (formats, OUI vendor, I/G and U/L bits, EUI-64), bandwidth & transfer time, TCP throughput (window and Mathis loss limits, BDP) and latency budget, Wi-Fi signal (free-space path loss + walls), coverage and channel planning, certificate expiry (with live check), password strength, hashes (MD5, SHA-1/256/384/512, CRC32; text or file), rack & power, API rate limits and WAN optimization. Copy results or save an HTML report. Implemented in [public/netcalc.js](public/netcalc.js); the manual's "Network calculator" chapter teaches addressing and subnetting as well as documenting each tool.
- **Playbooks** — guided diagnostics that run a sequence of commands, check each result, and give a verdict naming the broken link. Thirty-one of them, shown in four groups (Connectivity · DNS & email · Security & exposure · This PC & local network) with group chips, and filtered by the same search box (name, description and the commands they run):
  - *Can't reach the internet?* — IP lease → gateway → raw connectivity → DNS → HTTPS
  - *Does my connection drop out?* — the 3-minute stability monitor with a verdict: local link vs. beyond the router vs. jitter.
  - *Is my DNS honest?* — DNS honesty check + hosts/cache audit with one verdict (hijack / tampering / interception / leak / honest).
  - *Router check-up* — the router check with a verdict.
  - *Are packets being dropped on this PC?* — pktmon counters on every driver layer for 10 s while pinging the router and 1.1.1.1 and downloading 5 MB; names the layer that drops (firewall/VPN filter vs. adapter) or clears this PC. Needs Run as admin.
  - *Is a port open on a host?* — resolve → ping → TCP test
  - *Is DNS healthy?* — your resolver vs. Cloudflare vs. Google
  - *Scan my network* — the IP scanner: a parallel ping sweep of your own private subnet (≤ 254 addresses, no input, refuses public addresses), enriched from the ARP table so devices that ignore ping still appear; names where available, and a Manufacturer column from the built-in MAC-prefix table in [public/oui.js](public/oui.js), which also detects randomized private MACs Manufacturer names come from the full IEEE registry (~54,000 prefixes; `node tools/build-oui.js` refreshes it).
  - *Who's on my network?* — the passive version: just the ARP cache, with a table of IP and MAC addresses
  - *A website won't load* — your DNS vs public DNS, TCP 443, headers, per-phase timing, and a control site to separate "them" from "you"
  - *Why is everything slow?* — 20-ping latency / jitter / loss to the router and the internet, timed DNS and web request, Wi-Fi link
  - *Where does the path break?* — a route trace read for you: reached or not, where it stops, where latency steps up
  - *What is this PC exposing?* — listening ports with process names, network-reachable vs local-only, risky services, firewall state
  - *Routing & adapter sanity* — competing default routes, adapters holding a route with no valid address, DNS per adapter
  - *Did my DNS change propagate?* — authoritative servers vs four resolvers, with rotation (round-robin / geo-DNS) detection
  - *Wi-Fi health* — signal, band, radio mode, link rate, channel crowding, link steadiness
  - *Can I reach that service?* — HTTPS / HTTP / SSH / RDP / SMB / SQL on one host: open, refused or filtered
  - *MTU check* — don't-fragment pings of decreasing size to find the path MTU
  - *Email delivery check* — MX, SPF, DMARC and port 25
  - *PC health snapshot* — uptime, memory, disk space, hung programs, top memory users, last patch
  - *Clock & time sync* — offset from an internet time server, and the sync source
  - *Who is this PC talking to?* — live outbound connections grouped by program
  - *DHCP lease & address conflicts* — lease, DHCP server, logged IP conflicts (recent vs. historic)
  - *Proxy & HTTPS inspection* — configured proxies, and who really signed the certificate you receive
  - *IPv6 check* — global vs private (ULA) addresses, and whether IPv6 actually works
  - *Can't see the other PC / shared folder* — this PC's profile/services/firewall, the other PC by DNS, LLMNR/NetBIOS and mDNS, ping, port 445
  - *Printer won't print* — spooler, queues, ping, ports 9100/631/515/80, and the scan log to find a printer that changed address
  - *Is my VPN really working?* — full vs split tunnel from the route table, public address, DNS leak, tunnel MTU
  - *Will my video calls be OK?* — jitter and loss both legs, Wi-Fi, NAT type over STUN, upload and bufferbloat
  - *Am I behind double NAT or CGNAT?* — private hops on the way out, the router's WAN address over UPnP, the public address
  - *Can't Remote Desktop to this PC* — edition, switch, service, port, firewall per profile, users, then a real connection
  Steps can name a command **variant** by key, run **conditionally** on earlier results, **stop the run** on a fatal failure, **capture** values for later steps, show a **table** of their own output, and verdicts can offer **action buttons** (run another playbook, copy a fix-it command). Checks receive the step's duration and exit code — that is how "refused" is told from "filtered". The authoring contract is documented at the top of [public/playbooks.js](public/playbooks.js).
- **History** — the last 30 runs (output included) are kept in the browser; reopen or re-run any of them.
- **Variants** — a per-command drop-down of vetted flag combinations (`ping -t`, `tracert -h 15`, `nslookup -type=MX`, `netstat -anob`…). Admin-only variants unlock when the server runs elevated.
- **? help** on every card runs the tool's own help (`/?`, `Get-Help`, `--help`) into a tab.
- **Health strip** — live sparklines of gateway and internet ping, sampled every 10 s.
- **Output tools** — find-in-output with match count, wrap toggle, save as `.txt`, live elapsed timer.
- **Ctrl+K command palette** — jump to any command or playbook by name or purpose.
- **Cross-platform** — on Linux/macOS the run button moves to the L/M (Linux / macOS) row and runs that platform's equivalent (`runUnix` specs in `commands.json`, with `darwin` overrides).
- **Light / dark theme** — toggle in the header; the manual follows.
- **Manual button** — the book icon on every command and playbook card opens the manual at that entry (`manual.html#cmd-<id>` / `#pb-<id>`; every command and playbook has an anchor). In the desktop app the manual and cheat sheet open in a second window, so the main window keeps its tabs.
- **Pinning** — ☆ on any card or playbook keeps it at the top and first in the palette; a "★ pinned" filter shows only those.
- **Deep links** (web editions only — the desktop app's pages live at `tauri.localhost`, which nothing outside the app can open, so it has no link buttons) — the 🔗 button on a card, tab or playbook copies a URL like `#cmd/ping?host=1.1.1.1` that opens NetDeck jumped to that card with the inputs pre-filled (nothing auto-runs).
- **Custom commands** — "+ Add command" creates reference-only cards (copy buttons, never a run button). Stored in `custom-commands.json` next to the app; in the hosted build they live in the browser.
- **Desktop notifications** — the 🔔 button in the terminal bar; when on, a run that finishes while the tab is in the background raises a system notification.
- **Keyboard navigation** — `j`/`k` or arrows move between cards, `Enter` runs (or focuses an empty host box), `c` copies, `p` pins, `h` opens help, `l` copies a link, `Esc` clears.
- **Cheat sheet** — `/cheatsheet.html`: the whole reference as compact cards, one per command, with a print stylesheet (Print → Save as PDF).
- **Linux/macOS table view** — parsers for `ss`, `lsof`, `ip addr`, `ifconfig`, `arp`, `ip route`, `netstat -rn`, `ps aux` and `dig`.
- ★ marks the "most useful on Windows" commands from the source reference

## Hosting the reference on a web server

```
node build-static.js
```

writes a `dist/` folder — plain HTML/CSS/JS plus `commands.json` — that any static host can serve (Netlify, Cloudflare Pages, GitHub Pages, S3, nginx). Preview it locally with `node serve-dist.js` (http://localhost:4580).

A hosted page **cannot run commands on the visitor's machine**; it's the full reference (search, playbook steps, manual, cheat sheet, pinning, links, custom commands in the browser) with execution off. To get live execution from the hosted page, a visitor pairs it with a NetDeck server running on their own computer:

```
set NETDECK_ORIGIN=https://netdeck.example.com   (PowerShell: $env:NETDECK_ORIGIN="https://netdeck.example.com")
node server.js
```

The server prints a **pairing token**; the hosted page's "Connect local NetDeck" dialog takes `http://localhost:4573` and that token. Only that exact origin gets CORS headers, every request must carry the token, and the server still binds to `127.0.0.1` only. Set `NETDECK_TOKEN` to fix the token across restarts. Chrome, Edge and Firefox allow an `https` page to talk to `http://localhost`; Safari does not.

## Desktop app (Tauri)

```
npx @tauri-apps/cli@^2 build
```

builds a native desktop app from `src-tauri/` — a Rust backend that reuses the same `commands.json` whitelist and the same UI files, talking over Tauri IPC instead of HTTP. On Windows it produces `src-tauri/target/release/netdeck.exe` (~6 MB, uses the system WebView2) and an NSIS installer in `src-tauri/target/release/bundle/nsis/`. Prerequisites: Rust (stable, MSVC toolchain on Windows), the Visual Studio C++ build tools, and the WebView2 runtime (present on Windows 10/11). `npx @tauri-apps/cli@^2 dev` runs it unbundled for development.

**Two Windows installers.** `node tools/build-installers.js` builds both for the current version (`--normal-only` skips the second):

| Installer | Size | WebView2 |
|---|---|---|
| `NetDeck_<version>_x64-setup.exe` | ~5 MB | Downloaded from Microsoft during setup, only on a PC that lacks it (Windows 11 and current Windows 10 already have it) |
| `NetDeck_<version>_x64-offline-setup.exe` | ~210 MB | Microsoft's full WebView2 installer is inside, so setup needs no internet at all — for air-gapped machines, lab benches and PCs whose network is the problem |

The offline one is the same app built with `src-tauri/tauri.offline.conf.json` merged in (`webviewInstallMode: offlineInstaller`). Either way WebView2 is Microsoft's self-updating (Evergreen) runtime, and it updates itself once the PC is online.

The desktop app adds a **tray icon** (Open / Quit), **close-to-tray** (closing the window keeps runs going; Quit is in the tray menu), **native notifications** and a **native save dialog**, and is **single-instance** — launching it again just brings the running window to the front. Custom commands are stored in the per-user app-data folder (`%APPDATA%\com.netdeck.desktop\`). Builds are per-OS: run the same command on a Mac or Linux box for those targets.

**Administrator rights.** A few variants (`netstat -anob`) and Windows 11 Wi-Fi details need elevation. The desktop app has a **Run as admin** button beside the STANDARD USER badge: it exits, relaunches itself through the UAC prompt (`Start-Process -Verb RunAs`), and falls back to a normal start if the prompt is declined. The Node editions show a *How to run as admin* dialog with the exact commands for their own folder instead — a page cannot restart its server.

**Installing on Windows.** Run `NetDeck_<version>_x64-setup.exe` — or `NetDeck_<version>_x64-offline-setup.exe` on a PC with no internet. It installs per-user (no admin prompt) to `%LOCALAPPDATA%\NetDeck`, adds **NetDeck** to the Start menu (folder "NetDeck") and a **desktop shortcut**, and registers in *Settings → Apps* for uninstalling (which removes both shortcuts). Re-running a newer installer upgrades in place. `setup.exe /S` installs silently. Because the installer is unsigned, SmartScreen shows "unknown publisher" the first time — choose *More info → Run anyway*.

`public/api.js` is the adapter that lets the one UI run against all three backends (Node server, hosted static page, Tauri).

## Single executable (Node)

```
node build-exe.js
```

produces `build/netdeck.exe` (or `build/netdeck` on Linux/macOS) — Node and the app in one file, using Node's single-executable-application support. It fetches `postject` once via `npx` at build time; the result has no runtime dependencies. Double-clicking `netdeck.exe` starts the server and opens the browser; keep its console window open while you use it (closing the window stops the server). If port 4573 is busy it moves to the next free port and says so. `custom-commands.json` is kept beside the executable. Flags: `--port N`, `--open` (open the browser even when run from a terminal). Windows SmartScreen may warn on first launch because the file is unsigned.

## Safety model

- Only commands whitelisted in [commands.json](commands.json) with `"safe": true` and a `run` spec can execute — the browser only ever sends a command **id**, never a command line.
- State-changing commands (`ipconfig /flushdns`, `route add`, `taskkill`, `arp -d`, …) are copy-only, with a note explaining why.
- User-supplied parameters are validated server-side (hostname/IP charset, port range, http(s) URL) and passed as discrete `spawn` arguments — no shell, no injection surface.
- `/api/run` requires a custom `X-NetDeck` header and a local `Origin`, so other websites open in your browser cannot trigger runs (CSRF).
- The server binds to `127.0.0.1` only, and runs time out after 3 minutes.

## Files

- [server.js](server.js) — static file server, `/api/run` streaming endpoint (chunked HTTP), `/api/context` network detection, `/api/health` ping sampler
- [commands.json](commands.json) — the command dataset (edit this to add commands; `"hidden": true` keeps internal helpers out of the grid). Per command: `run` (Windows spec with `params` and `presets`), `runUnix` (Linux, optional `darwin` override), `help` / `helpUnix`.
- [public/manual.html](public/manual.html) — the user manual (also served at `/manual.html`)
- [public/cheatsheet.html](public/cheatsheet.html) — printable cheat sheet
- [public/manual-img/](public/manual-img/) — the manual's playbook screenshots (WebP, ~1.4 MB in total)
- [tools/capture-manual-shots.js](tools/capture-manual-shots.js) — regenerates those screenshots: start NetDeck (`node server.js`), start a Chromium browser with `--headless=new --remote-debugging-port=9333 about:blank`, then `node tools/capture-manual-shots.js 9333`. It runs every playbook and captures each result pane (plus the Playbooks overview and the Dashboard), replacing the computer name (OFFICE-PC), renumbering local addresses into 192.168.1.x and public ones into 203.0.113.x, and hiding the second half of MAC addresses before each shot; `tools/figure-dims.js` then sizes every figure to its file. The manual text uses the same placeholder ranges and says so. Program names (in the exposure, outbound and PC-health shots) are left as they are — review those before publishing the manual anywhere public.
- [tools/licenses.js](tools/licenses.js) — writes the manual's "About & license" section (MIT text + the desktop app's third-party crates grouped by license, from cargo metadata); re-run after dependency updates.
- [tools/bump.js](tools/bump.js) — the version lives in `package.json`; `node tools/bump.js patch` (or `minor`, `major`, or an exact `x.y.z`) updates `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `public/version.js` and every `<span class="nd-version">` in the manual together, so the header, the installer and every edition agree. Run it before each build; with no argument it reports whether the files agree.
- [build-static.js](build-static.js) / [serve-dist.js](serve-dist.js) — hosted build and its local preview
- [build-exe.js](build-exe.js) — single-executable packaging (Node)
- [src-tauri/](src-tauri/) — the desktop app: `src/lib.rs` (backend), `tauri.conf.json`, `capabilities/`
- [public/api.js](public/api.js) — backend adapter (HTTP vs Tauri IPC)
- [public/app.js](public/app.js) — UI: cards, tabs, table view, history, context
- [public/parsers.js](public/parsers.js) — output parsers for the table view
- [public/playbooks.js](public/playbooks.js) — playbook definitions, step checks and verdicts

## License

MIT — see [LICENSE](LICENSE). Use it, change it, ship it; keep the copyright notice.
