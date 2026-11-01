# RCE Finder architecture

RCE Finder is an evidence-first, scope-constrained validation tool. It does
not discover targets, run arbitrary commands, create persistence, or use
callbacks as proof unless the callback is uniquely correlated to a probe.

## Execution path

```text
explicit target file -> scope policy -> validated template -> bounded request
-> self-hosted OOB correlation -> evidence-based result
```

## Current safety invariants

- HTTP(S) target files are explicit and operator supplied.
- Private and loopback numeric targets require `-allow-private`, intended
  only for an authorized local test lab.
- Target URLs with embedded credentials are rejected by default.
- HTTP redirects are never followed automatically, since a redirect may leave
  the explicitly authorized scope.
- Response reads are bounded to 1 MiB by default.
- Templates declare a capability mode. The default policy executes only
  `safe-validation` templates; `advanced-authorized` templates are skipped.
- A `CONFIRMED` result requires the probe ID and callback protocol to match.
- The default OOB client is a local stub which cannot report a confirmation.

## Template schema

Templates use `rce-finder/v2`. In addition to the request definition, v2
templates carry CWE/CVE mapping, technology applicability, capability mode,
evidence requirements, remediation, and references. Template data cannot
execute local code.

The HTTP adapter supports form-encoded bodies and an intentionally limited
JSON object body mode. XML is a declared, escaped text-field tree; multipart
bodies contain declared text fields only and use a fixed reviewed boundary.
Both are limited to 1 MiB and reject file fields and undeclared mutations.

Local HAR and Postman imports are inventory-only and constrained by the
explicit target file. OpenAPI imports remain path-only; server URLs, callbacks,
webhooks, and external references are ignored. No importer performs network
I/O or creates a scan target. GraphQL, SOAP, WebSocket, and TCP remain planned
protocol adapters.

## Planned extensions

Fingerprinting, protocol adapters, persistent evidence, signed template packs,
SARIF, and distributed workers remain planned work. They must preserve the
same safety invariants rather than bypass them.
