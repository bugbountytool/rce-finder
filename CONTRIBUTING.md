# Contributing

Thanks for considering a contribution. Most contributions will be new
detection templates, so start there.

## Adding a template

1. Copy an existing file in `templates/` as a starting point.
2. Every template **must**:
   - Use OOB (out-of-band) confirmation as its only proof mechanism. The
     payload must contain the literal `{{canary}}` placeholder, and the
     only observable effect of a vulnerable target firing should be a DNS
     lookup or HTTP request back to the canary — never a destructive action
     (no file writes, no reverse shells, no data exfiltration, no actual OS
     command execution beyond what's needed to trigger the callback).
   - Include `references` pointing to a CVE, advisory, or technical write-up
     describing the vulnerability class, so reviewers and users can verify
     the check is grounded in real, documented behavior.
   - Have a clear, accurate `vuln_class` and `severity`.
   - Pass validation (`Template.Validate()` in
     `internal/template/template.go` — run `go run ./cmd/rce-finder
     -targets <any-file> -templates templates -i-am-authorized -dry-run` to
     confirm your template loads correctly).
3. Open a PR. Describe: what vulnerability class this detects, why the OOB
   signal is a reliable indicator for it, and any known false-positive /
   false-negative conditions.

Templates that embed a specific exploitation gadget chain (e.g. a full
ysoserial-style Java deserialization chain, a working command-execution
payload) will not be accepted. The project's design boundary is detection
and confirmation, not exploitation — once a finding is confirmed, the
operator is expected to use their own authorized, separately-reviewed
tooling for deeper exploitation if that's within their engagement's scope.

## Code contributions

- Keep the core engine (`internal/engine`), scope loader
  (`internal/scope`), and OOB client interface (`internal/oob`) free of
  anything destructive or scope-expanding (no auto-discovery, no
  CIDR/range scanning, no removing the `-i-am-authorized` gate).
- Run `go vet ./...` and `go build ./...` before opening a PR.
- New OOB backend implementations (beyond the included stub and HTTP
  polling client) are welcome — please document the API contract they
  expect, similar to `docs/OOB.md`.

## Code of conduct

Be respectful. Assume good faith. This project exists to make authorized
security testing more effective, not to lower the bar for unauthorized
access — PRs that work against that goal (e.g. adding auto-scope-expansion,
destructive payloads, or features clearly aimed at mass/opportunistic
scanning) will be declined regardless of technical quality.
