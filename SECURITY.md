# Security policy

## Supported versions

This repository has not yet been published or tagged as a release —
`v0.1.0` is Phase 9's own deliverable (see [`PLAN.md`](PLAN.md) §13's
versioning plan and [`CHANGELOG.md`](CHANGELOG.md)). Everything on the
`main` branch is pre-release, evaluation-grade software. There is currently
no "supported version" in the sense of a maintained release line; this
section will be filled in with real supported-version ranges once `v0.1.0`
ships.

## Reporting a vulnerability

**This repository is not yet public.** It does not yet live at
`github.com/debster9755/real-guard-v1` (PLAN.md §13 names that as the
target, Phase 9's own deliverable) and therefore has no GitHub Security
Advisories channel, no issue tracker, and no other live intake mechanism
today. Stating this plainly, rather than inventing a contact address or a
link that does not resolve, is this project's own standing rule (`DOC-012`:
no placeholder text; PLAN.md's guiding principle 9: no invented content).

Once the repository is public (Phase 9), this section will be updated with
a real, working process: private reporting via GitHub Security Advisories,
a 90-day disclosure window, and an explicit statement of what does and does
not qualify as a security report versus a general bug (PLAN.md §13:
"`SECURITY.md` with supported versions, a private disclosure channel via
GitHub Security Advisories, a 90-day disclosure window, and an explicit
statement of residual risks" — the target this document is written toward).

Until then, if you have access to this source tree through a channel other
than a public GitHub repository (e.g. you were given the code directly),
report a finding the same way you would report any other issue with the
person who gave it to you — there is no other channel to offer honestly.

## Residual risks

Stated without hedging, exactly as [`docs/threat-model.md`](docs/threat-model.md)
and `SPEC.md` §19.5 require:

- **Detection is heuristic.** It has false positives and false negatives.
  It is one layer of defence in depth, not a substitute for upstream-model
  safety controls or application-level authorization.
- **The audit chain is tamper-evident, not tamper-proof.** Every
  `audit_events` row is hash-chained to the one before it
  (`app/audit.py`, `DAT-005`) — altering or deleting a row breaks the chain
  detectably from that point forward. It does not stop someone with direct
  write access to the SQLite database file from rewriting the entire chain
  consistently. The chain proves nothing about an actor who already has
  that level of access; its value is detecting tampering by anyone who
  does not.
- **The MVP is single-instance.** No multi-instance coordination, no
  distributed rate limiting or approval-queue consistency guarantee across
  more than one process.
- **Streaming (`stream: true`) is unsupported and rejected outright**
  rather than partially inspected — a partially-inspected token stream is
  a real leak risk this MVP declines to ship rather than ship unsafely.
- **A compromised reviewer credential defeats human-in-the-loop entirely.**
  The approval workflow's entire security value rests on the reviewer key
  (or session) remaining secret, the same way any credential-gated control
  does. There is no secondary factor.
- **The firewall does not and cannot know the calling application's
  authorization model.** It is a network control point, not a replacement
  for your application's own entitlements or authorization checks
  (`SEC-020`; this is stated as an explicit non-goal in `PLAN.md` §2.5, not
  a gap).

### Adversarial-review findings (Phase 7, `docs/adr/0009`)

Thirteen deliberate evasion attempts were run by hand against the real
detectors. Seven real gaps found were fixed (narrow, additive,
corpus-preserving). Four real gaps found were **not** fixed and remain
open, each pinned by a regression test in
`tests/test_adversarial.py::TestDocumentedResidualRisks` so neither a
silent regression nor an unnoticed future fix goes unnoticed:

1. A domestic phone number with no leading `+` (E.164 form) is not
   recognised as PII.
2. A destructive shell command reworded with long-form flags
   (`rm --recursive --force` vs. the recognised `rm -rf`) evades that
   specific rule's pattern list (the overall verdict still denies today
   because the tool itself is not allowlisted by default).
3. Splitting an injection keyword with ordinary visible punctuation or
   spaces (`I.g.n.o.r.e`, `I g n o r e`) evades every pattern.
4. A base64 payload nested five layers deep is not decoded — this is
   `MAX_DECODE_DEPTH = 3` (`SYS-012`) working exactly as designed, a
   deliberate bound against decode-bomb denial of service, not an
   oversight.

Full reasoning for each — including why it was judged not worth fixing
right now — is in
[`docs/adr/0009-phase7-benchmarking-and-adversarial-review.md`](docs/adr/0009-phase7-benchmarking-and-adversarial-review.md)
and [`docs/threat-model.md`](docs/threat-model.md).

### Dependency and container scanning

`pip-audit` and Trivy run in CI (`.github/workflows/ci.yml`'s `security`
job). As of the last real run against this codebase (Phase 6,
`docs/adr/0008`): `pip-audit` found zero known vulnerabilities against the
production dependency set; Trivy, scanned against the actual built image,
found zero *fixable* HIGH/CRITICAL findings (`--ignore-unfixed`). This is
**not** an unqualified "clean" scan — 54 Debian OS-package CVEs (51 HIGH, 3
CRITICAL) remain, inherited from the pinned `python:3.12-slim` base image,
with no upstream fix available as of that writing. `gitleaks` (full-history
secret scanning) is Phase 9's own deliverable and has not been run yet —
see `README.md`'s "Limitations" section for the same caveat stated to an
evaluator.

## Related documents

- [`docs/threat-model.md`](docs/threat-model.md) — assets, trust
  boundaries, threat actors, and the full threats-and-controls table.
- [`docs/architecture.md`](docs/architecture.md) — where each control
  actually runs.
- [`docs/adr/`](docs/adr/) — the reasoning behind every security-relevant
  decision made in this repository.
