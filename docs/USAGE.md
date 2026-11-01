# Usage

## Install / build

```bash
git clone https://github.com/bugbountytool/rce-finder.git
cd rce-finder
go build -o rce-finder ./cmd/rce-finder
```

## 1. Write your target file

One URL per line, scheme required. This file is your scope — every line in
it must be something you are explicitly authorized to test (see
SECURITY.md).

```
# targets.txt
https://staging.example-bugbounty-target.com
https://api.example-bugbounty-target.com
```

## 2. (Optional but recommended) Stand up an OOB server

Without one, every result will be `NOT_VULNERABLE` or `ERROR` — the local
stub client never reports a hit. See docs/OOB.md.

## 3. Dry run first

See exactly what requests would be sent, without sending them:

```bash
./rce-finder -targets targets.txt -i-am-authorized -dry-run
```

## 4. Run for real

```bash
./rce-finder \
  -targets targets.txt \
  -i-am-authorized \
  -oob-server https://your-interaction-server.example \
  -rate 2 \
  -concurrency 5
```

To reduce probes to templates applicable to a known stack, select declared
technology tags explicitly:

```bash
./rce-finder -targets targets.txt -i-am-authorized -technologies java,jvm -dry-run
```

## 5. Read the results

```
STATUS     SEVERITY  TEMPLATE                  TARGET                        DETAIL
CONFIRMED  critical  jndi-generic-oob          https://api.example.com       OOB dns callback received from 203.0.113.4
NOT_VULNERABLE  high  ssti-generic-oob         https://api.example.com       no OOB callback observed within timeout
```

A `CONFIRMED` result means the target made an outbound DNS/HTTP request in
response to the injected payload — a strong signal the input is evaluated
server-side in a way consistent with the template's vulnerability class.
Treat it as the start of a manual writeup, not an automatic bug bounty
submission: confirm the finding manually, determine real-world impact, and
follow the target program's reporting format.

`NOT_VULNERABLE` means no callback arrived within the template's timeout. It
is not proof of absence — a WAF, network egress filtering, or a slower
execution path could all suppress the callback.

## Machine-readable output

```bash
./rce-finder -targets targets.txt -i-am-authorized -json -oob-server ... | jq 'select(.status == "CONFIRMED")'
```

## SARIF output

Write CI-friendly SARIF 2.1.0 without overwriting an existing file:

```bash
./rce-finder -targets targets.txt -i-am-authorized -sarif findings.sarif
```

## Persistent local results

Write a new immutable JSON snapshot for later reporting or review:

```bash
./rce-finder -targets targets.txt -i-am-authorized -results scans/scan-001.json
```

## Markdown report

```bash
./rce-finder -targets targets.txt -i-am-authorized -markdown findings.md
```

## Authenticated request context

Repeat `-cookie name=value` to supply session cookies held in memory for the
scan. Cookies are secure-only, are not persisted, and are excluded from logs,
terminal/JSON output, SARIF, Markdown, and result snapshots. Error messages
never echo cookie values. Header values supplied with `-header` are likewise
request context, not report content. Shell history can contain command-line
secrets; use an appropriately protected execution environment.

## Local request inventory (no network traffic)

`inventory` reads exactly one local HAR, Postman collection, or OpenAPI v3 JSON
document and prints endpoint metadata. It never sends a request or writes a
scan plan. The explicit target file remains required:

```bash
./rce-finder inventory -targets targets.txt -har reviewed.har
./rce-finder inventory -targets targets.txt -postman collection.json -json
./rce-finder inventory -targets targets.txt -openapi openapi.json
```

HAR imports retain only final request URLs inside an explicit target's scheme,
host, effective port, and path boundary. Postman imports inventory literal,
in-scope URLs only; variables and scripts are not evaluated. OpenAPI imports
only declared paths. Its servers, callbacks, webhooks, and external references
never create targets. Review these inventories manually before creating any
explicit target file or template plan; inventory never starts an active scan.

## Typed request bodies

Templates can declare `application/xml` or `multipart/form-data` with
`body_fields`. Every injection must name a declared text field. XML field names
are dotted element paths, and values are encoded with XML escaping rather than
raw substitution. Multipart bodies have a reviewed, fixed
`multipart_boundary`; file fields and upload mutation are rejected. Encoded
bodies are limited to 1 MiB. The resulting request bytes and content type are
covered by golden tests.

## Flags reference

Run `./rce-finder -h` for the full, current flag list.
