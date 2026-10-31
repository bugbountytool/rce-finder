# RCE Finder

A template-driven scanner for confirming remote code execution (RCE)
vulnerability classes in web applications, using **out-of-band (OOB)
callback confirmation** instead of destructive exploitation. Built for
authorized security testing — bug bounty hunting, internal pentests, CI
security gates on your own services.

```
STATUS     SEVERITY  TEMPLATE                  TARGET                    DETAIL
CONFIRMED  critical  jndi-generic-oob          https://api.example.com   OOB dns callback received from 203.0.113.4
NOT_VULNERABLE  high ssti-generic-oob          https://api.example.com   no OOB callback observed within timeout
```

## Why OOB confirmation

Most "is this RCE?" checks either (a) guess from an HTTP status code /
response body, which is unreliable, or (b) fire a real exploit payload
(reverse shell, file write), which is destructive and often against
bug-bounty program rules. RCE Finder instead injects a payload that, if
evaluated server-side, makes the target reach out to a canary domain you
control via DNS or HTTP. A callback arriving is a clean, binary signal:
**confirmed** code evaluation happened. No callback within the timeout:
**not vulnerable** (for that check). Nothing in between, and no destructive
action either way.

## How it works

```
targets.txt ──► scope loader ──► for each (target, template):
                                     issue unique canary  ──►  inject payload, send ONE request
                                     poll OOB server for callback
                                     CONFIRMED | NOT_VULNERABLE | ERROR
```

- **Scope is explicit.** Targets come only from a file you supply. There is
  no crawler and no auto-discovery — see SECURITY.md for why.
- **Checks are YAML templates**, not hardcoded Go, so the detection logic is
  auditable and the project is extensible by contributors who don't need to
  touch the engine. See `templates/` and CONTRIBUTING.md.
- **Confirmation requires an OOB backend you control.** The tool ships with
  a safe local stub that never reports false hits, so it builds and runs
  out of the box — you plug in a real interaction server for real scans.
  See docs/OOB.md.
- **Safe policy defaults.** Loopback/private numeric targets require the
  explicit `-allow-private` opt-in for authorized lab testing. Templates also
  declare their required capability mode; the default scanner runs only safe
  validation templates. See docs/ARCHITECTURE.md.

## Quick start

```bash
go build -o rce-finder ./cmd/rce-finder

echo "https://your-authorized-target.example" > targets.txt

# See what would be sent, without sending anything:
./rce-finder -targets targets.txt -i-am-authorized -dry-run

# Real scan, once you have an OOB server (docs/OOB.md):
./rce-finder -targets targets.txt -i-am-authorized -oob-server https://your-interaction-server.example
```

Full walkthrough: docs/USAGE.md.

## Included starter templates

| Template | Vulnerability class | Reference |
|---|---|---|
| `jndi-generic-oob` | Generic JNDI injection (Log4Shell-style) | CVE-2021-44228 |
| `ssti-generic-oob` | Server-side template injection | OWASP SSTI |
| `el-injection-generic-oob` | OGNL/SpEL expression injection | CVE-2017-5638 |
| `deserialization-generic-oob` | Insecure deserialization (reachability probe) | OWASP Deser |

These are **generic class detectors**, not one-to-one CVE exploits — they
flag that an endpoint evaluates attacker input in a way consistent with the
vulnerability class, which is the point where you move to manual,
authorized, in-scope follow-up.

## What this tool deliberately does not do

- It does not discover or expand scope on its own — see SECURITY.md.
- It does not ship exploit gadget chains or run destructive payloads — see
  CONTRIBUTING.md's template rules.
- It does not run without an explicit `-i-am-authorized` acknowledgement.

## Contributing

New detection templates are the easiest and most valuable contribution —
see CONTRIBUTING.md.

## License

MIT — see LICENSE.

## Responsible use

Read SECURITY.md before running this against anything. In short: only
targets you are explicitly authorized to test, ever.
