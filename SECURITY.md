# Security policy

## What porthawk is for

porthawk is a TCP port scanner for auditing systems you own or have explicit
written permission to test: your own machines, your home network, and
authorized security assessments. It is not a stealth or evasion tool — it
makes full TCP connections, which show up in the target's logs — and it must
not be used to probe systems you are not authorized to test. Unauthorized
scanning may violate computer misuse laws, your ISP's terms of service, or
your employer's policies. See "Responsible use" in the README.

## Reporting a vulnerability

If you find a security issue in porthawk itself — for example, a banner that
escapes into terminal output, a parser crash on hostile input, or a flaw in
how results are written — please report it through GitHub's private
vulnerability reporting on this repository, so it can be fixed before the
details are public. Do not open a public issue with exploit details.

Please include:

- which version or commit you tested,
- a minimal input or command that reproduces the issue,
- what you expected versus what happened.

## What is in scope

- Banner handling: banners come from untrusted servers and are treated as
  hostile input. They are stripped of control characters (including the C1
  range U+0080–U+009F) and truncated before display, and HTML reports escape
  them with `html/template`.
- Input parsing: target specs, port specs, and previous-scan JSON files are
  parsed with strict bounds (65,536 hosts per scan, ports 1–65535) and are
  covered by unit and fuzz tests.
- No credentials: porthawk stores no passwords, tokens, or scan targets,
  and it makes no network connections except the probes you ask it to make.

## Out of scope

Misuse of porthawk against systems you are not authorized to test is not a
vulnerability in porthawk. Reports about the existence of open ports on a
third party's system should go to that system's owner.
