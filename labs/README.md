# Laboratory design

All lab targets are local `httptest` servers by default. Integration tests are
opt-in with `-tags=integration`; ordinary `go test ./...` runs unit tests only.

The fake OOB server implements `POST /issue` and `GET /poll?probe_id=...` from
`docs/OOB.md`, plus a local `/callback/<token>` test-only endpoint. Its modes
can delay callbacks or deliberately mismatch probe IDs and protocols. The
fixture never evaluates payload source, invokes a command, reads secrets, or
writes files. Vulnerable mode simply forwards the issued canary to the local
fake OOB service; patched mode does not.

The framework packs are reviewed callback-only examples, not CVE exploit
implementations. Applicability fingerprints are weak unless verified manually;
false positives include unrelated callback-capable template evaluation and
false negatives include patched engines, sandboxes, blocked egress, unsupported
contexts, and WAF filtering. Each must be validated against its own vulnerable
and patched application before treating it as a production-quality detector.
The included generic fixture tests engine correlation, not real framework
vulnerability detection.

Docker Compose binds published ports to loopback, drops capabilities, and uses
read-only containers. The fixture starts patched by default. To opt into the
non-executing vulnerable callback simulation:

```bash
RCE_FINDER_VULNERABLE=true docker compose -f labs/docker-compose.yml up --build
# When finished:
docker compose -f labs/docker-compose.yml down
```

No public targets are used in lab tests or CI.
