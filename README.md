# porthawk

A fast, concurrent TCP port scanner with service banner grabbing, written in Go
using only the standard library.

porthawk connects to each host/port pair using a bounded pool of workers. It
records which ports accept a connection and how long the handshake took. It
then reads a short banner from each open port and uses that to guess the
service (SSH, HTTP, SMTP, FTP, POP3, IMAP, MySQL, Redis, VNC, ...) and, where
the banner says, the server software version. On TLS
ports (HTTPS, IMAPS, LDAPS, ...) it completes a TLS handshake first, records
the protocol version, cipher and certificate details, and reads the banner
over the encrypted connection. Each scan can be compared with an earlier one
to show which ports opened, closed or changed.

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
- **Change detection.** Save JSON output on a schedule and compare each scan
  with the last one (`-diff`) to spot new services, closed ports and version
  changes. See [Change detection](#change-detection).
- **Certificate hygiene.** Spot expired or self-signed certificates and
  servers still offering old TLS versions.

## Install

Requires Go 1.24 or newer. There are no external dependencies.

```sh
git clone https://github.com/battlettt/porthawk.git
cd porthawk
go build -o porthawk .
```

To stamp a release version into the binary (shown by `-version` and in the
HTML report footer), set it with `-ldflags`. Without it the version is `dev`.

```sh
go build -ldflags "-X main.version=1.3.0" -o porthawk .
./porthawk -version
# porthawk v1.3.0
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

# Same sweep, gently: at most 50 connection attempts per second
./porthawk -t 192.168.1.10 -p 1-65535 -rate 50

# Machine-readable output for later diffing
./porthawk -t 192.168.1.0/24 -top 50 -f json -o scan.json -q

# Compare with that scan and save this one as the new baseline
./porthawk -t 192.168.1.0/24 -top 50 -f json -diff scan.json -o scan.json -q

# CSV for a spreadsheet
./porthawk -t 10.0.0.5 -p 1-1024 -f csv -o scan.csv

# Self-contained HTML report to open in a browser or share
./porthawk -t 192.168.1.0/24 -top 100 -f html -o report.html

# Plaintext probes only, no TLS handshakes
./porthawk -t 10.0.0.5 -p 443,993 -notls

# Add reverse DNS names for the hosts with open ports
./porthawk -t 192.168.1.0/24 -top 20 -rdns
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
| `-rate`    | `0`       | Max connection attempts per second (`0` = unlimited)    |
| `-timeout` | `2s`      | Per-connection dial timeout (e.g. `500ms`, `3s`)         |
| `-f`       | `table`   | Output format: `table`, `json`, `csv`, `html`            |
| `-o`       | stdout    | Write results to a file                                  |
| `-q`       | `false`   | Suppress progress and summary messages on stderr         |
| `-notls`   | `false`   | Skip TLS handshakes; probe TLS ports in plaintext        |
| `-diff`    |           | Compare results with a previous JSON scan file           |
| `-rdns`    | `false`   | Reverse DNS (PTR) lookup for hosts with open ports       |
| `-version` |           | Print `porthawk v<version>` and exit                     |

Exit codes: `0` when the scan completes, `1` if the results can't be written
or the `-diff` file can't be read, `2` for usage errors (bad flags, targets or ports) and `130` if the scan is
interrupted with Ctrl-C. If you interrupt a scan, porthawk still prints the
results it found up to that point.

### Sample output

```
$ ./porthawk -t 127.0.0.1,localhost -p 2222,8080,8443,9
porthawk: scanning 2 host(s) x 4 port(s) with 100 workers
HOST       PORT  SERVICE                               TLS   LATENCY  BANNER
127.0.0.1  2222  ssh (OpenSSH_9.6p1 Ubuntu-3ubuntu13)  -     1.07ms   SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
127.0.0.1  8080  http (SimpleHTTP/0.6)                 -     0.30ms   HTTP/1.0 200 OK
127.0.0.1  8443  https                                 1.2!  0.80ms   HTTP/1.1 404 Not Found
porthawk: 3 open port(s) found in 6ms
```

The SERVICE column shows the server software version in parentheses when the
banner carries one (see [Service versions](#service-versions)). The HTTP
version comes from the `Server` response header, which isn't part of the
one-line banner.

The TLS column shows the negotiated version (`1.3`, `1.2`, ...), with `!`
appended when the certificate has expired, or `-` for plaintext services.

With `-rdns`, porthawk looks up the PTR record of each host that has an open
port once the scan has finished: one lookup per distinct host, at most 16 at
a time, each with a 2 second timeout. The name is shown in a HOSTNAME column
after HOST (`-` for hosts without a PTR record). The column is left out when
no host has a name, which is always the case without `-rdns`:

```
$ ./porthawk -t 127.0.0.1 -top 100 -rdns
porthawk: scanning 1 host(s) x 100 port(s) with 100 workers
HOST       HOSTNAME   PORT  SERVICE                 TLS  LATENCY  BANNER
127.0.0.1  localhost  8080  http (SimpleHTTP/0.6)   -    5.43ms   HTTP/1.0 200 OK
127.0.0.1  localhost  8443  https (SimpleHTTP/0.6)  1.3  0.40ms   HTTP/1.0 200 OK
porthawk: 2 open port(s) found in 13ms
```

Lookups are skipped if the scan is interrupted.

JSON output is an array of objects. `version` is omitted when unknown, and
`hostname` (after `host`) is omitted unless `-rdns` found a name.
Results from a TLS handshake carry a `tls` object; plaintext results omit it:

```json
[
  {
    "host": "127.0.0.1",
    "port": 2222,
    "service": "ssh",
    "version": "OpenSSH_9.6p1 Ubuntu-3ubuntu13",
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

With `-diff`, the JSON output becomes an object: the same array under
`results`, plus a `diff` object (see [Change detection](#change-detection)).

CSV output has the columns `host, hostname, port, service, version, banner,
latency_ms, tls_version, tls_cipher, tls_cert_subject, tls_cert_expiry`. The
hostname is empty without `-rdns` or when the lookup finds no name, the
version is empty when unknown, and the TLS columns are empty for plaintext
services.

The HTML report (`-f html`) is a single file with no external assets. It has
a header with the scan targets, ports per host, time taken and open port
count, a per-service summary, and a table of every open port with its
software version (under the service name), reverse DNS name (under the
host, with `-rdns`), TLS version, cipher, certificate subject and expiry. The
footer gives the finish time and the porthawk version that wrote the report.

**Example report:** [docs/example-report.html](docs/example-report.html) is a
sample generated on the author's machine with
`./porthawk -t 127.0.0.1 -top 100 -rdns -f html -o docs/example-report.html`,
against two local Python test servers: `http.server` on port 8080 and the same
server over TLS with a self-signed certificate on 8443. It was built without
`-ldflags`, so the footer says `porthawk vdev`. GitHub shows HTML files as
source; download the file or open it from a local clone to see it rendered.

## Service versions

When a banner announces its software, porthawk records it as the result's
version:

| Service | Banner                                                   | Version                          |
|---------|----------------------------------------------------------|----------------------------------|
| ssh     | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13`                 | `OpenSSH_9.6p1 Ubuntu-3ubuntu13` |
| http    | `Server: nginx/1.24.0`                                   | `nginx/1.24.0`                   |
| http    | `Server: Apache/2.4.57 (Debian)`                         | `Apache/2.4.57 (Debian)`         |
| http    | `Server: Microsoft-IIS/10.0`                             | `Microsoft-IIS/10.0`             |
| ftp     | `220 ProFTPD 1.3.8a Server (Debian)`                     | `ProFTPD 1.3.8a`                 |
| ftp     | `220 (vsFTPd 3.0.3)`                                     | `vsFTPd 3.0.3`                   |
| ftp     | `220 FileZilla Server 1.8.0`                             | `FileZilla Server 1.8.0`         |
| smtp    | `220 mail.example.com ESMTP Postfix 3.7.4`               | `Postfix 3.7.4`                  |
| smtp    | `220 mx.example.com ESMTP Exim 4.96 ...` (also Sendmail) | `Exim 4.96`                      |
| smtp    | `220 mx Microsoft ESMTP MAIL Service, Version: 10.0...`  | `Microsoft ESMTP 10.0...`        |
| mysql   | handshake packet                                         | `8.0.36`, `5.5.5-10.11.6-MariaDB`|

Anything else, including banners without a version number (`Server: nginx`,
`ESMTP Postfix (Ubuntu)`), gets no version. Only the first product in a
`Server` header is kept. The same patterns apply over TLS, so an HTTPS server
shows its `Server` header too.

## Change detection

Save a scan as JSON, then pass that file to `-diff` on a later run. porthawk
reads the old file before scanning, matches results by host and port, and
prints what's different after the results:

- **opened**: open now, not in the previous scan
- **closed**: in the previous scan, not open now
- **changed**: open in both, but the service, version, banner, TLS version,
  cipher or certificate subject differs. Each changed field is listed with its
  old and new value.

Week 1, save a baseline:

```
$ ./porthawk -t 127.0.0.1 -p 2121,2222,6379,8080 -f json -o scan.json
porthawk: scanning 1 host(s) x 4 port(s) with 100 workers
porthawk: 3 open port(s) found in 1ms
```

Week 2: SSH and nginx have been upgraded, the FTP server is gone, and someone
has started Redis. Compare, and save this run as next week's baseline:

```
$ ./porthawk -t 127.0.0.1 -p 2121,2222,6379,8080 -f json -diff scan.json -o scan.json
porthawk: scanning 1 host(s) x 4 port(s) with 100 workers
Changes since scan.json: 1 opened, 1 closed, 2 changed, 0 unchanged
  + opened  127.0.0.1:6379  redis               -NOAUTH Authentication required.
  - closed  127.0.0.1:2121  ftp (vsFTPd 3.0.3)  220 (vsFTPd 3.0.3)
  ~ changed 127.0.0.1:2222  ssh
      version: "OpenSSH_9.6p1 Ubuntu-3ubuntu13" -> "OpenSSH_9.7p1 Ubuntu-7ubuntu4"
      banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" -> "SSH-2.0-OpenSSH_9.7p1 Ubuntu-7ubuntu4"
  ~ changed 127.0.0.1:8080  http
      version: "nginx/1.24.0" -> "nginx/1.26.2"
porthawk: 3 open port(s) found in 1.002s
```

When nothing has changed, the summary is a single line:

```
No changes since scan.json (3 port(s) unchanged).
```

The summary goes to stdout, after the results when they're also on stdout.
The one exception is JSON on stdout: the summary goes to stderr so stdout
stays valid JSON (`-q` suppresses it there). JSON output with `-diff` is an
object holding the results and a machine-readable diff:

```json
{
  "results": [ ... ],
  "diff": {
    "opened_count": 1,
    "closed_count": 1,
    "changed_count": 2,
    "unchanged_count": 0,
    "opened": [ { "host": "127.0.0.1", "port": 6379, "service": "redis", ... } ],
    "closed": [ { "host": "127.0.0.1", "port": 2121, "service": "ftp", ... } ],
    "changed": [
      {
        "host": "127.0.0.1",
        "port": 8080,
        "service": "http",
        "changes": [ { "field": "version", "old": "nginx/1.24.0", "new": "nginx/1.26.2" } ]
      },
      ...
    ]
  }
}
```

`-diff` reads both shapes, the plain array and this object, so you can keep
writing over the same file with `-diff scan.json -o scan.json`. That only
works with `-f json`; porthawk refuses to overwrite the `-diff` file with
table, CSV or HTML output. Unknown fields in the file are ignored. If the
file is missing, isn't porthawk JSON, or has an entry without a valid host
and port, porthawk exits with status 1 before scanning.

Only host/port pairs covered by the current scan are compared. Scanning
`-p 22` after a full sweep won't report every other port as closed. If a scan
is interrupted, ports it never reached show up as closed, and porthawk prints
a warning saying so.

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
- `version.go` pulls software versions out of banners with a short list of
  regular expressions, one or more per service.
- `rdns.go` does the optional reverse DNS lookups after the scan, once per
  distinct host, with its own small worker pool.
- `output.go` renders results as an aligned table, JSON or CSV, and
  `html.go` renders the HTML report with `html/template`.
- `diff.go` loads a previous JSON scan, compares it with the current results
  and prints the change summary.

## Testing

```sh
go test ./...
go test -race ./...
make fuzz   # 30s of fuzzing per parser target
```

Continuous integration runs on every push and pull request to `main`
(see `.github/workflows/ci.yml`): format check, build, vet, tests, tests
with the race detector, and a short fuzz smoke test. `make` wraps the
common tasks: `build`, `version` (stamps `1.3.0` into the binary),
`test`, `vet`, `race`, `fuzz`, `fmt`, `clean`, and `report` (scans
localhost and writes `report.html`).

The tests cover target expansion (CIDR, ranges, dedupe, invalid input), port
parsing (ranges, lists, top-N, invalid input), service fingerprinting and
version extraction from sample banners, and every output format. The diff
tests cover the JSON write/load round trip, opened/closed/changed detection,
and missing or corrupt `-diff` files. The reverse DNS tests use a fake
resolver to check one lookup per host, timeouts and cancellation, plus one
real lookup of `127.0.0.1`. That lookup normally comes from `/etc/hosts`, but
if the address isn't listed there the system resolver may ask a DNS server.
The TLS tests start local
`httptest` servers on the loopback interface, including ones with generated
expired and CA-signed certificates, and the `-diff` end-to-end tests use
plain loopback listeners. No other network connections are made.

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
- **Self-reported versions.** Versions are whatever the banner claims. Admins
  often hide or fake them, and distributions backport security fixes without
  changing the upstream version number. Treat them as a lead, not proof of
  a vulnerability.
- **Rate.** Lots of workers on a slow or monitored network can set off
  IDS/IPS alerts or overload fragile devices. Start small, and use
  `-rate` to cap connection attempts per second (for example `-rate 50`
  on a home router or an old device).

## Responsible use

**Only scan systems you own or have explicit written permission to test.**
Unauthorized port scanning may violate computer misuse laws (such as the US
CFAA or the UK Computer Misuse Act), your ISP's terms of service, or your
employer's policies. Even where it's legal, it may be treated as hostile
activity. porthawk is meant for learning, auditing your own networks, and
authorized security assessments. You alone are responsible for how you use it.
