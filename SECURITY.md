# Security & Authorized Use Policy

RCE Finder is a template-driven scanner that sends crafted HTTP requests
designed to trigger an out-of-band (OOB) network callback if a target is
vulnerable to a known class of remote code execution (RCE) issue. It does
not, by design, deliver destructive payloads (no reverse shells, no file
writes, no data exfiltration) — but it still sends traffic that a target's
security monitoring may flag, and it is still testing for a serious
vulnerability class.

## Scope of authorized use

**Only run this tool against systems you are explicitly authorized to
test.** That means one of:

- A bug bounty or vulnerability disclosure program whose published scope
  includes the target, and whose rules of engagement you have read and are
  following
- A system you own or administer yourself
- A system covered by a signed penetration testing agreement naming you (or
  your organization) as an authorized tester, for the duration specified

Running network probes against systems outside of one of these categories
may be illegal in your jurisdiction (e.g. under the U.S. Computer Fraud and
Abuse Act, the UK Computer Misuse Act, or equivalent laws elsewhere),
regardless of intent.

### How the tool enforces this

- Targets are **only** read from an explicit file you supply with
  `-targets`. There is no crawler, subdomain brute-forcer, or "scan this
  CIDR" mode, and there never will be — scope must be enumerated by a human.
- The CLI requires an explicit `-i-am-authorized` flag before it will send
  any request. This is not a technical control (it cannot verify your
  authorization), it is a deliberate point of friction and a clear record of
  intent.
- All included templates use OOB confirmation rather than destructive
  payloads, by the project's own contribution rules (see CONTRIBUTING.md).

None of this makes misuse impossible — it is a scanner, and a sufficiently
motivated person can always point a scanner at the wrong thing. The controls
exist to keep accidental and casual misuse low and to make the tool's
intended use unambiguous.

## Reporting a vulnerability in RCE Finder itself

If you find a security issue in this tool's own code (not a finding
produced by using the tool), please open a private security advisory on
GitHub (Security tab → "Report a vulnerability") rather than a public issue.

## Responsible disclosure of findings

If you use this tool and confirm an RCE in a system, follow the disclosure
process defined by that system's bug bounty program or your engagement's
rules of engagement. If no formal program exists, follow general responsible
disclosure norms (e.g. CERT/CC guidelines) — notify the affected
organization privately and give them reasonable time to remediate before
any public disclosure.
