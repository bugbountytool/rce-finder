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
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -dry-run
```

## 4. Run for real

```bash
./rce-finder \
  -targets targets.txt \
  -i-am-authorized \
  -allow-unsigned-local-templates \
  -oob-server https://your-interaction-server.example \
  -rate 2 \
  -concurrency 5
```

To reduce probes to templates applicable to a known stack, select declared
technology tags explicitly:

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -technologies java,jvm -dry-run
```

## 5. Read the results

```
STATUS     SEVERITY  TEMPLATE                  TARGET                        DETAIL
CONFIRMED  critical  jndi-generic-oob          https://api.example.com       OOB dns callback received from 203.0.113.4
NOT_VULNERABLE  high  el-injection-generic-oob  https://api.example.com  no OOB callback observed within timeout
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
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -json -oob-server ... | jq 'select(.status == "CONFIRMED")'
```

## SARIF output

Write CI-friendly SARIF 2.1.0 without overwriting an existing file:

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -sarif findings.sarif
```

## Persistent local results

Write a new immutable JSON snapshot for later reporting or review:

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -results scans/scan-001.json
```

## Markdown report

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -markdown findings.md
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

## Template trust and planning

Unsigned local templates require `-allow-unsigned-local-templates` for scans.
For a signed pack, configure local trusted Ed25519 public keys and omit that
flag:

```bash
./rce-finder templates verify -templates templates/packs -trusted-keys trusted-keys.json
./rce-finder -targets targets.txt -i-am-authorized -templates templates/packs -trusted-template-keys trusted-keys.json
```

Template validation rejects unknown fields, unsupported methods/body types,
invalid canary usage, oversized payloads, and inconsistent prerequisites. The
engine currently permits one request per template/job. No template is fetched
from a remote repository.

List and inspect local definitions:

```bash
./rce-finder templates list
./rce-finder templates inspect -id jndi-generic-oob
./rce-finder templates validate
```

## Passive fingerprints and explainable planning

```bash
./rce-finder fingerprint -targets targets.txt -i-am-authorized -output fingerprints.json
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates \
  -fingerprints fingerprints.json -auto-select-technologies -explain-plan -dry-run
```

Fingerprinting requests only URLs explicitly present in the target file and
never follows redirects or crawls. Its output is applicability evidence, not a
vulnerability finding. Technology auto-selection is opt-in; the default runs
all explicitly selected templates so an unrecognized stack does not create
false assurance.

## Scheduler, snapshots, and resume

`-rate` sets the global request rate and `-host-rate` the per-host rate.
`-retries` (0–5) applies only to transient network failures. The host error
budget opens a circuit after repeated network failures; policy blocks, invalid
templates, and OOB failures are not retried. Jobs are deduplicated by target,
template ID, and request shape. `-progress` emits redacted structured events.

Write a snapshot and resume it later:

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -results scans/run.json
./rce-finder scan -targets targets.txt -i-am-authorized -allow-unsigned-local-templates -resume scans/run.json
```

Resume requires matching scope, template, and non-secret execution-policy
fingerprints. Completed terminal jobs are not resent. Errors, blocked work, and
inconclusive results remain pending for review or retry. Cookies, authorization
headers, and other request secrets are never written to snapshots.

## HTML, CSV, and stored-snapshot reports

```bash
./rce-finder report -snapshot scans/run.json -format html -output report.html
./rce-finder report -snapshot scans/run.json -format csv -output report.csv
```

All report formats share the same classification model and redaction boundary.
Evidence includes safe metadata and hashes, not raw request/response bodies.

## CI exit policy

By default, operational errors and weak findings do not create a separate CI
failure policy. To fail for a confirmed high/critical finding:

```bash
./rce-finder -targets targets.txt -i-am-authorized -allow-unsigned-local-templates \
  -fail-on confirmed -fail-severity high
```

`-fail-on high-confidence` also includes `CONFIRMED`. `POTENTIAL`,
`INCONCLUSIVE`, and passive fingerprints never fail CI by themselves.

## Local integration lab and protocol corpus status

```bash
go test -tags=integration -count=1 ./labs/tests
docker compose -f labs/docker-compose.yml up --build
```

The lab uses local non-executing fixtures and a fake OOB API. It validates
correlation, mismatch rejection, timeouts, redirects, filtering, cancellation,
and concurrency—not real framework exploitability. Framework-specific packs
need controlled version-specific vulnerable/patched application validation
before production reliance.

GraphQL, SOAP/WSDL, and WebSocket helpers currently parse bounded explicit
request corpora only. They do not create targets or perform live protocol
scans. Live TCP/WebSocket adapters and enterprise/distributed features remain
unimplemented pending complete scope, correlation, redaction, and lab controls.

## Flags reference

Run `./rce-finder -h` for the full, current flag list.

## Investigation workflow (static source-to-sink)

Analyze a local Go module for source→sink flows and produce a rich finding
report. No network target is contacted; findings are source-classified.

```bash
./rce-finder investigate -source ./path/to/go/module -format markdown
./rce-finder investigate -source ./path/to/go/module -format json -output findings.jsonl
```

A complete reachable source→sink flow is `HIGH_CONFIDENCE (source)`; a sink with
no established flow is `POTENTIAL`. Dynamic confirmation requires the OOB scan
path or a repeated controlled differential.

## Security graph

Build a local SQLite graph of assets, endpoints, and parameters from an explicit
target plus a local import. No network I/O; imports never create targets.

```bash
./rce-finder graph -targets targets.txt -openapi openapi.json -db graph.db
./rce-finder graph -db graph.db -show endpoints
```

## Software composition analysis

Parse a local dependency manifest and report applicability. Add `-query-osv` to
query the OSV API (network, opt-in). A version match is never a confirmed
vulnerability.

```bash
./rce-finder sca -gomod go.mod
./rce-finder sca -package-lock package-lock.json -query-osv
./rce-finder sca -requirements requirements.txt
```
