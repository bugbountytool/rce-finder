# Out-of-band (OOB) interaction server

RCE Finder's confirmations depend entirely on an OOB interaction backend:
something that hands out unique canary identifiers and tells the scanner
when one of them was looked up (DNS) or requested (HTTP) by a target.

**The tool ships with no real OOB backend.** By default it uses
`oob.NewLocalStubClient`, which issues plausible-looking canary strings but
never reports a hit — useful for template development, `--dry-run`, and CI
smoke tests, but it will never produce a `CONFIRMED` result. For a real
scan, you need to point `-oob-server` at infrastructure you control.

## Why you must run your own

OOB callback data (which canary fired, from which source IP, for which
target) is sensitive — it's effectively your findings in real time. Don't
route scan traffic for a real engagement through a shared or third-party
interaction server you don't operate and trust.

## Server API contract

`-oob-server` expects a base URL serving two endpoints:

### `POST {base}/issue`

Request body:
```json
{"probe_id": "<uuid supplied by the scanner>"}
```

Response body:
```json
{"canary": "<unique hostname or path segment>"}
```

The canary should be unique per call and should be a valid DNS label (for
`dns`-protocol templates) or URL path segment (for `http`-protocol
templates) under a domain/path you control and are monitoring.

### `GET {base}/poll?probe_id=<uuid>`

Response body when nothing has been observed yet:
```json
{"interaction": null}
```

Response body once a matching DNS lookup or HTTP request arrives:
```json
{
  "interaction": {
    "probe_id": "<uuid>",
    "protocol": "dns",
    "source_ip": "203.0.113.4",
    "at": "2026-10-31T12:00:00Z",
    "raw_info": "optional free-text detail"
  }
}
```

## Building your own server

A minimal implementation needs:

1. **A DNS server** authoritative for a domain you own (e.g.
   `oob.yourdomain.com`), logging every query it receives along with the
   source IP, keyed by the queried label.
2. **An HTTP server** on that same domain (or a separate one), logging every
   request path and source IP.
3. **A small API layer** implementing `/issue` and `/poll` above, backed by
   a simple in-memory map or small database correlating `probe_id` →
   canary → observed interactions.

This is the same shape as existing open-source interaction-server projects;
if you already run one, you can likely write a thin adapter in front of its
existing API instead of building from scratch — implement the `oob.Client`
interface in `internal/oob/oob.go` directly rather than going through HTTP
if that's more convenient.

## Self-hosting checklist

- Own or control the DNS domain and the server receiving HTTP callbacks.
- Don't reuse the same interaction domain across unrelated engagements if
  confidentiality between them matters — interaction logs will mix.
- Rate-limit and authenticate the `/issue` and `/poll` endpoints if the
  server is reachable beyond your own machine.
