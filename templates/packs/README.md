# Safe validation packs

Each pack declares applicability, a canary-only callback strategy, and
remediation. Templates never contain command execution, reverse shells,
persistence, file writes, credential access, or gadget-chain generation.
A `CONFIRMED` result requires exact OOB probe/protocol correlation; a
fingerprint alone is not a finding.

Packs are examples until verified against a real, controlled version-specific
vulnerable and patched application. The local fixture is intentionally a
non-executing simulator and is not proof that a real framework is vulnerable.
