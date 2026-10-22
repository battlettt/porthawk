# porthawk

A fast, concurrent TCP port scanner with service banner grabbing, written in Go
using only the standard library.

porthawk connects to each host/port pair using a bounded pool of workers. It
records which ports accept a connection and how long the handshake took. It
then reads a short banner from each open port and uses that to guess the
service (SSH, HTTP, SMTP, FTP, POP3, IMAP, MySQL, Redis, VNC, ...).

## Why it matters

You can't secure what you can't see. Knowing which services are listening on
your network is basic to security auditing:

- **Attack surface review.** Every open port is something an attacker can
  reach. Finding forgotten services (an old FTP daemon, a Redis instance
  bound to `0.0.0.0`) is often the quickest security win.
- **Firewall verification.** Check that the rules you wrote actually block
  what you meant them to block.
- **Asset inventory.** Banners show software and versions, which you can
  compare against patch levels and vulnerability advisories.
- **Change detection.** Save JSON/CSV output on a schedule and diff the
  results to spot new services.

## Install

Requires Go 1.24 or newer. There are no external dependencies.

```sh
git clone https://github.com/battlettt/porthawk.git
cd porthawk
go build -o porthawk .
```

## Usage

```sh
# Scan the 100 most common ports on your own machine (the default port set)
./porthawk -t 127.0.0.1

# Scan the top 20 ports across your home subnet
./porthawk -t 192.168.1.0/24 -top 20

# Specific ports and a range, against a hostname and an IP range
./porthawk -t myserver.lan,10.0.0.1-10.0.0.20 -p 22,80,443,8000-8100

# Full port sweep of one host with more workers and a tighter timeout
./porthawk -t 192.168.1.10 -p 1-65535 -w 500 -timeout 500ms

# Machine-readable output for later diffing
./porthawk -t 192.168.1.0/24 -top 50 -f json -o scan.json -q

# CSV for a spreadsheet
./porthawk -t 10.0.0.5 -p 1-1024 -f csv -o scan.csv
```

Target specs can be combined with commas: single IPv4/IPv6 addresses,
hostnames (resolved to all of their addresses), CIDR blocks (`10.0.0.0/24`)
and dash ranges (`10.0.0.1-10.0.0.20`). Duplicates are removed. For IPv4
blocks larger than a /31, the network and broadcast addresses are skipped.
To prevent accidents, a single scan is limited to 65,536 hosts.

### Flags

| Flag       | Default   | Description                                              |
|------------|-----------|----------------------------------------------------------|
| `-t`       | required  | Targets: IPs, hostnames, CIDRs, ranges (comma-separated) |
| `-p`       | top 100   | Ports: `80`, `22,80,443`, `1-1024`, or a mix             |
| `-top`     |           | Scan the N most common ports (1-100); excludes `-p`      |
| `-w`       | `100`     | Number of concurrent workers                             |
| `-timeout` | `2s`      | Per-connection dial timeout (e.g. `500ms`, `3s`)         |
| `-f`       | `table`   | Output format: `table`, `json`, `csv`                    |
| `-o`       | stdout    | Write results to a file                                  |
| `-q`       | `false`   | Suppress progress and summary messages on stderr         |

Exit codes: `0` when the scan completes, `1` if the results can't be written,
`2` for usage errors (bad flags, targets or ports) and `130` if the scan is
interrupted with Ctrl-C. If you interrupt a scan, porthawk still prints the
results it found up to that point.

### Sample output

```
$ ./porthawk -t 127.0.0.1,localhost -p 2222,8080,9
porthawk: scanning 2 host(s) x 3 port(s) with 100 workers
HOST       PORT  SERVICE  LATENCY  BANNER
127.0.0.1  2222  ssh      1.07ms   SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
127.0.0.1  8080  http     0.30ms   HTTP/1.0 200 OK
porthawk: 2 open port(s) found in 2ms
```

JSON output is an array of objects:

```json
[
  {
    "host": "127.0.0.1",
    "port": 2222,
    "service": "ssh",
    "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
    "latency_ms": 0.26
  }
]
```

## How it works

- `target.go` parses and expands target specs using `net/netip`.
- `ports.go` / `topports.go` parse port specs and hold the common-ports list.
- `scanner.go` feeds host/port jobs to a fixed pool of workers. Each worker
  dials with a timeout and sends results back over a channel. The scan stops
  when the context is cancelled (SIGINT/SIGTERM).
- `banner.go` sends an HTTP `HEAD` probe to web ports. On other ports it
  waits for the server to speak first, then sends a bare CRLF. It matches the
  reply against a small fingerprint table, and falls back to the port's
  conventional service name.
- `output.go` renders results as an aligned table, JSON or CSV.

## Testing

```sh
go test ./...
```

The tests cover target expansion (CIDR, ranges, dedupe, invalid input), port
parsing (ranges, lists, top-N, invalid input) and service fingerprinting from
sample banners. They don't make any network connections.

## Limitations

- **TCP connect scan only.** There is no SYN/stealth scanning, UDP or OS
  detection. Full connects show up in the target's logs.
- **Open vs. filtered.** Closed and filtered ports are both left out of the
  results. A firewall that silently drops packets makes each probe wait for
  the full timeout.
- **No TLS.** HTTPS and other TLS ports get a plaintext probe, so the banner
  is usually empty or an error page. The service name then comes from the
  port number.
- **Heuristic fingerprints.** Service names are a best guess based on the
  first bytes a server sends. They are not a full protocol handshake.
- **Rate.** Lots of workers on a slow or monitored network can set off
  IDS/IPS alerts or overload fragile devices. Start small.

## Responsible use

**Only scan systems you own or have explicit written permission to test.**
Unauthorized port scanning may violate computer misuse laws (such as the US
CFAA or the UK Computer Misuse Act), your ISP's terms of service, or your
employer's policies. Even where it's legal, it may be treated as hostile
activity. porthawk is meant for learning, auditing your own networks, and
authorized security assessments. You alone are responsible for how you use it.
