# net-trace

> Traceroute for Windows using scapy.

`net-trace` maps the path packets take to a destination, hop by hop.
It uses scapy for TTL manipulation, so it needs Administrator privileges
and Npcap on Windows — the same requirements as any real traceroute tool.

## Features

- **ICMP and TCP traceroute** (`--protocol icmp|tcp`)
- **Configurable probes per hop** (`-q`), max hops (`-m`), timeout (`-w`)
- **Reverse DNS** on each hop (disable with `--no-resolve`)
- **JSON output** for scripting
- Clean rendering: `*` for timeouts, aligned RTT columns

## Requirements (Windows)

1. **Npcap** installed — https://npcap.com/
   During install, tick *"Install Npcap in WinPcap API-compatible Mode"*.
2. **Administrator privileges** — run PowerShell or Windows Terminal as Administrator.
3. **Python 3.10+**

Without both of these, scapy can't open raw sockets and `net-trace`
will fail with a clear error.

## Install (Windows)

```powershell
git clone https://github.com/YOUR_USERNAME/net-trace.git
cd net-trace
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -e ".[dev]"
```

Or as a global tool (after activating an Admin terminal for use):

```powershell
pipx install .
```

## Usage

```powershell
# Basic ICMP traceroute (run PowerShell as Administrator)
net-trace example.com

# TCP traceroute on a specific port (better through firewalls)
net-trace example.com --protocol tcp -p 443

# Fewer probes per hop = faster
net-trace example.com -q 1

# Shorter per-probe timeout
net-trace example.com -w 1

# Skip reverse DNS
net-trace example.com --no-resolve

# JSON output
net-trace example.com --json
```

## Example output

```
$ net-trace example.com
Tracing route to example.com (93.184.216.34)
over a maximum of 30 hops:

  1    1.234 ms   1.101 ms   1.212 ms   192.168.1.1
  2    8.456 ms   8.301 ms   8.512 ms   10.0.0.1
  3   12.789 ms  12.601 ms  12.899 ms   *
  4   18.234 ms  18.101 ms  18.412 ms   *
  5   22.101 ms  22.234 ms  22.456 ms   93.184.216.34

Trace complete. 5 hops.
```

```json
$ net-trace example.com --json
{
  "target": "example.com",
  "resolved": "93.184.216.34",
  "hops": [
    { "hop": 1, "rtts_ms": [1.234, 1.101, 1.212], "addr": "192.168.1.1" },
    { "hop": 5, "rtts_ms": [22.101, 22.234, 22.456], "addr": "93.184.216.34" }
  ],
  "total_hops": 5
}
```

## ICMP vs TCP

| | ICMP | TCP |
|---|---|---|
| Requires Admin + Npcap | Yes | Yes |
| Works through most firewalls | Sometimes | Sometimes |
| Works to web servers | Often blocked | Often allowed (port 443) |
| Best for | LAN/infra hops | Internet destinations |

**Rule of thumb:** ICMP first. If you get `*` all the way, retry with
`--protocol tcp -p 443`.

## Interpreting output

- `*` in the RTT column means a probe timed out (no reply within `-w`)
- A hop with **some** RTTs but not all is common — routers rate-limit ICMP
- Reaching the destination doesn't require every hop to answer

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | At least one hop replied |
| `1` | No hops replied |
| `2` | Bad arguments or missing deps/privileges |

## Development

```powershell
pytest
ruff check .
mypy src
```

## ⚠️ Legal

Only trace routes to hosts you are authorized to probe. Traceroute sends
packets with deliberately low TTLs; on some networks this is considered
probing and may trip monitoring. Don't point this at infrastructure you
don't own.

## License

MIT — see [LICENSE](LICENSE).