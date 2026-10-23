# porthawk

A fast, concurrent TCP port scanner with service banner grabbing, written in Go
using only the standard library.

porthawk connects to each host/port pair using a bounded pool of workers. It
records which ports accept a connection and how long the handshake took. It
then reads a short banner from each open port and uses that to guess the
service (SSH, HTTP, SMTP, FTP, POP3, IMAP, MySQL, Redis, VNC, ...). On TLS
ports (HTTPS, IMAPS, LDAPS, ...) it completes a TLS handshake first, records
the protocol version, cipher and certificate details, and reads the banner
over the encrypted connection.

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
- **Certificate hygiene.** Spot expired or self-signed certificates and
  servers still offering old TLS versions.

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

# Self-contained HTML report to open in a browser or share
./porthawk -t 192.168.1.0/24 -top 100 -f html -o report.html

# Plaintext probes only, no TLS handshakes
./porthawk -t 10.0.0.5 -p 443,993 -notls
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
| `-f`       | `table`   | Output format: `table`, `json`, `csv`, `html`            |
| `-o`       | stdout    | Write results to a file                                  |
| `-q`       | `false`   | Suppress progress and summary messages on stderr         |
| `-notls`   | `false`   | Skip TLS handshakes; probe TLS ports in plaintext        |

Exit codes: `0` when the scan completes, `1` if the results can't be written,
`2` for usage errors (bad flags, targets or ports) and `130` if the scan is
interrupted with Ctrl-C. If you interrupt a scan, porthawk still prints the
results it found up to that point.

### Sample output

```
$ ./porthawk -t 127.0.0.1,localhost -p 2222,8080,8443,9
porthawk: scanning 2 host(s) x 4 port(s) with 100 workers
HOST       PORT  SERVICE  TLS   LATENCY  BANNER
127.0.0.1  2222  ssh      -     1.07ms   SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
127.0.0.1  8080  http     -     0.30ms   HTTP/1.0 200 OK
127.0.0.1  8443  https    1.2!  0.80ms   HTTP/1.1 404 Not Found
porthawk: 3 open port(s) found in 6ms
```

The TLS column shows the negotiated version (`1.3`, `1.2`, ...), with `!`
appended when the certificate has expired, or `-` for plaintext services.

JSON output is an array of objects. Results from a TLS handshake carry a
`tls` object; plaintext results omit it:

```json
[
  {
    "host": "127.0.0.1",
    "port": 2222,
    "service": "ssh",
    "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
    "latency_ms": 0.26
  },
  {
    "host": "127.0.0.1",
    "port": 8443,
    "service": "https",
    "banner": "HTTP/1.1 404 Not Found",
    "latency_ms": 0.80,
    "tls": {
      "version": "TLS 1.2",
      "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "server_name": "127.0.0.1",
      "cert_subject": "dev.example.lan",
      "cert_issuer": "dev.example.lan",
      "cert_sans": ["dev.example.lan"],
      "cert_not_before": "2024-05-01T00:00:00Z",
      "cert_not_after": "2025-05-01T00:00:00Z",
      "cert_expired": true,
      "cert_self_signed": true,
      "cert_sig_alg": "SHA256-RSA",
      "cert_host_mismatch": true
    }
  }
]
```

CSV output has the columns `host, port, service, banner, latency_ms,
tls_version, tls_cipher, tls_cert_subject, tls_cert_expiry`. The TLS columns
are empty for plaintext services.

The HTML report (`-f html`) is a single file with no external assets. It has
a header with the scan targets, ports per host, time taken and open port
count, a per-service summary, and a table of every open port with its TLS
version, cipher, certificate subject and expiry.

## TLS probing

These ports get a TLS handshake before the banner grab: 443, 465, 636, 853,
990, 993, 995, 6697 and 8443. porthawk accepts any certificate (it is a
scanner, not a client that trusts the server) and old versions back to TLS
1.0, and records:

- the negotiated protocol version and cipher suite,
- the server name sent (the scanned IP, so no SNI is sent),
- the leaf certificate's subject and issuer (CommonName, or the first
  Organization), up to 8 DNS subject alternative names, validity dates and
  signature algorithm,
- whether the certificate has expired, is self-signed, or fails hostname
  verification against the scanned address.

On web ports the HTTP `HEAD` probe is then sent over TLS, so you see the real
response instead of a "plain HTTP sent to HTTPS port" error. The service name
becomes the TLS variant of what the banner shows (`http` becomes `https`,
`imap` becomes `imaps`). If the banner matches a different protocol, such as
SSH behind a multiplexer, that match is kept.

If the handshake fails, porthawk reconnects and falls back to the plaintext
probe, so a plain HTTP server on port 443 is still identified. Use `-notls` to
skip handshakes altogether.

## How it works

- `target.go` parses and expands target specs using `net/netip`.
- `ports.go` / `topports.go` parse port specs and hold the common-ports list.
- `scanner.go` feeds host/port jobs to a fixed pool of workers. Each worker
  dials with a timeout and sends results back over a channel. The scan stops
  when the context is cancelled (SIGINT/SIGTERM).
- `tls.go` performs the TLS handshake on TLS ports and extracts version,
  cipher and certificate details.
- `banner.go` sends an HTTP `HEAD` probe to web ports. On other ports it
  waits for the server to speak first, then sends a bare CRLF. It matches the
  reply against a small fingerprint table, and falls back to the port's
  conventional service name.
- `output.go` renders results as an aligned table, JSON or CSV, and
  `html.go` renders the HTML report with `html/template`.

## Testing

```sh
go test ./...
```

The tests cover target expansion (CIDR, ranges, dedupe, invalid input), port
parsing (ranges, lists, top-N, invalid input), service fingerprinting from
sample banners, and every output format. The TLS tests start local
`httptest` servers on the loopback interface, including ones with generated
expired and CA-signed certificates. No other network connections are made.

## Limitations

- **TCP connect scan only.** There is no SYN/stealth scanning, UDP or OS
  detection. Full connects show up in the target's logs.
- **Open vs. filtered.** Closed and filtered ports are both left out of the
  results. A firewall that silently drops packets makes each probe wait for
  the full timeout.
- **TLS on known ports only.** Handshakes are only tried on the ports listed
  under [TLS probing](#tls-probing). TLS on other ports (an HTTPS admin panel
  on 9443, say) gets a plaintext probe, and STARTTLS is not attempted.
- **No SNI.** Targets are scanned by IP address, so servers that pick a
  certificate by SNI return their default one. For the same reason,
  `cert_host_mismatch` is usually true unless the certificate lists the IP.
- **No chain validation.** Certificates are inspected, not verified against
  a trust store. A cert can be unexpired and not self-signed and still be
  untrusted.
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
