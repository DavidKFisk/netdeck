# Network & System Command Reference

Source data for building a command-reference app. Each command lists its platform, category, syntax and purpose.

## App brief (starting point)

- **Goal:** A searchable reference of network and system CLI commands (like `arp`, `netstat`, `ipconfig`).
- **Core features:**
  - Search by command name or purpose
  - Filter by category and platform (Windows / Linux / macOS / PowerShell)
  - Side-by-side Windows vs Linux/macOS equivalents
  - Copy-to-clipboard for each command
  - Optional: run commands locally and show output (desktop app only; requires a shell backend)
- **Data model (suggested):**

```json
{
  "id": "netstat-ano",
  "name": "netstat",
  "syntax": "netstat -ano",
  "platforms": ["windows"],
  "category": "Connections & Ports",
  "purpose": "Show active connections, listening ports and owning process IDs",
  "equivalents": ["ss -tulpn", "netstat -tulpn"],
  "safe_to_run": true
}
```

`safe_to_run` should be `false` for commands that change system state (release/renew, flush, route add/delete, kill, etc.).

---

## 1. Network Configuration & Interfaces

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `ipconfig /all` | `ip addr` / `ifconfig` | Show IP addresses, MAC addresses and adapters |
| `ipconfig /release` / `ipconfig /renew` | `dhclient -r` / `dhclient` | Release or renew a DHCP lease |
| `ipconfig /flushdns` | `resolvectl flush-caches` | Clear the DNS cache |
| `ipconfig /displaydns` | `resolvectl statistics` | View the DNS cache |
| `netsh` | `nmcli`, `ip`, `iw` | Configure interfaces, Wi-Fi and firewall |
| `getmac` | `ip link` | List MAC addresses |

## 2. Connectivity & Routing

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `ping <host>` | `ping <host>` | Test whether a host is reachable |
| `tracert <host>` | `traceroute <host>` / `tracepath <host>` | Show the path packets take |
| `pathping <host>` | `mtr <host>` | Traceroute plus packet-loss stats |
| `route print` | `ip route` / `route -n` / `netstat -rn` | Show the routing table |
| `route add` / `route delete` | `ip route add` / `ip route del` | Add or remove routes |

## 3. Connections & Ports

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `netstat -ano` | `netstat -tulpn` / `ss -tulpn` | Active connections, listening ports and owning processes |
| `Get-NetTCPConnection` (PowerShell) | `lsof -i` | List open network connections |
| `Test-NetConnection <host> -Port 443` | `nc -zv <host> 443` / `telnet <host> 443` | Test whether a specific port is open |

## 4. Address Resolution (ARP / Neighbors)

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `arp -a` | `arp -a` / `ip neigh` | Show the ARP cache (IP-to-MAC mappings) |
| `arp -d *` | `ip neigh flush all` | Clear the ARP cache |

## 5. DNS Lookups

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `nslookup <domain>` | `nslookup <domain>` | Query DNS records |
| `Resolve-DnsName <domain>` (PowerShell) | `dig <domain>` / `host <domain>` | Detailed DNS queries |

## 6. Windows Networking & Sharing (Windows only)

| Command | Purpose |
|---|---|
| `nbtstat -a <host>` | NetBIOS name info |
| `net use` | Map or unmap network drives |
| `net share` | List or create shares |
| `net view` | List computers and shares on the network |
| `net user` / `net localgroup` | Manage local accounts and groups |
| `hostname` | Show the computer name (also works on Linux/macOS) |

## 7. Scanning, Capture & Transfer (cross-platform)

| Command | Purpose |
|---|---|
| `nmap` | Port and host scanning |
| `tcpdump` (Linux/macOS) / `pktmon` (Windows) | Packet capture |
| `curl` / `wget` | HTTP requests and downloads (`curl` is built into Windows 10/11) |
| `ssh`, `scp`, `sftp` | Remote shell and file copy (built into Windows 10/11) |
| `whois` | Domain registration lookup |
| `iperf3` | Bandwidth testing |

## 8. System & Process Info

| Windows | Linux / macOS | Purpose |
|---|---|---|
| `tasklist` / `taskkill` | `ps aux` / `kill` | List or end processes |
| `systeminfo` | `uname -a`, `lscpu`, `free -h` | System details |
| `sfc /scannow`, `chkdsk` | `fsck` | Check system files and disks |
| `whoami` | `whoami`, `id` | Current user |

---

## Help syntax

- Windows: `<command> /?` (e.g., `netstat /?`)
- PowerShell: `Get-Help <cmdlet>`
- Linux/macOS: `man <command>` or `<command> --help`

## Most useful on Windows

`netstat -ano`, `arp -a`, `ipconfig /all`, `tracert`, `nslookup`, `Test-NetConnection`
