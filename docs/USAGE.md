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

## Flags reference

Run `./rce-finder -h` for the full, current flag list.
