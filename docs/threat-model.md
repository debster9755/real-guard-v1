# Threat model

Derived from [`SPEC.md` §19](../SPEC.md#19-security-threat-model), the
normative source. Where this document and `SPEC.md` disagree, `SPEC.md`
wins. This document organizes and cross-references that section; it does
not add a single threat, control, or residual risk beyond what `SPEC.md`
§19.4/§19.5 and the ADRs already establish.

## Assets

Client prompts and completions · PII and secrets in transit · the system
prompt and its canaries · the policy file · the audit log · service and
reviewer keys · the session secret and hash salt · the approval queue · the
upstream credential.

## Trust boundaries

| # | Boundary | Crossing |
|---|---|---|
| TB1 | Client → firewall | Untrusted content authenticated by a service key |
| TB2 | Retrieved context → firewall | **Fully untrusted** even inside an authenticated request |
| TB3 | Firewall → upstream | Firewall-originated, credentialed |
| TB4 | Reviewer → firewall | Privileged, session-authenticated |
| TB5 | Firewall → database | Local, filesystem-permission bounded |
| TB6 | Operator → configuration | Trusted, validated at startup |

TB2 is worth dwelling on: a request can be fully authenticated at TB1 (a
legitimate service key, a legitimate caller) and still carry, in its
retrieved-document or tool-result content, an instruction an attacker
planted somewhere upstream of this system entirely — a wiki page, a support
ticket, a web-search result. The context plane's detectors run with a lower
deny threshold than the input plane's for exactly this reason (see
`docs/architecture.md`'s "five inspection planes" table, `THR-002` below).

## Threat actors

An **external end user** typing into an app the firewall protects · a
**malicious content author** planting instructions in a document a
retriever will fetch · a **compromised or confused agent** issuing
out-of-policy tool calls · a **curious insider** with a service key · a
**malicious insider** with a reviewer key · a **network attacker** on the
firewall–upstream path.

## Threats and controls

| ID | Threat | Boundary | Control | Requirement | Residual |
|---|---|---|---|---|---|
| THR-001 | Direct prompt injection | TB1 | Injection detectors + hard-deny rule | `DET-004`, `POL-004` | Novel phrasings |
| THR-002 | Indirect injection via retrieved content | TB2 | Context-plane detection weighted higher | `SYS-004`, `DET-006` | Semantically novel payloads |
| THR-003 | Encoding and homoglyph evasion | TB1 | Normalization + bounded decoding | `DET-007`, `DET-008` | Multi-layer novel encodings |
| THR-004 | PII leakage inbound and outbound | TB1, TB3 | Bidirectional PII detection + `REDACT` | `DET-010`, `TRN-001` | Unusual or non-Western formats |
| THR-005 | Secret leakage in a response | TB3 | Secret detection + hard deny | `POL-004` | Novel key formats |
| THR-006 | System-prompt exfiltration | TB3 | Similarity + canary detection | `DET-011` | Paraphrased leakage |
| THR-007 | Identity spoofing via headers | TB1 | Identity only from the key or session | `SEC-009` | — |
| THR-008 | Tool abuse — destructive or high-value | TB1, TB3 | Allowlist + argument rules + approval | `DET-016`, `DET-017` | Novel tool schemas |
| THR-009 | SSRF via the upstream URL | TB3 | Startup URL validation; no URL following | `SYS-013`, `DET-012` | Operator misconfiguration |
| THR-010 | Approval replay | TB4 | Idempotency keys, single-use decisions | `APR-010` | Compromised reviewer key |
| THR-011 | Confused deputy — app self-approves | TB1, TB4 | Separate key classes; self-approval refused | `SEC-006`, `APR-009` | Operator issues one key for both |
| THR-012 | Argument swap after approval | TB4 | Material-argument hash re-validated on resume | `APR-013` | — |
| THR-013 | Policy tampering | TB6 | Schema validation; policy hash in every audit event | `POL-015`, `POL-020` | Filesystem write access |
| THR-014 | Audit tampering | TB5 | Append-only tables; hash chain | `DAT-004`, `DAT-005` | Direct DB access; **tamper-evident only** |
| THR-015 | Denial of service | TB1 | Size limits, rate limiting, detector deadlines, ReDoS review | `API-006`, `DET-019` | Distributed abuse |
| THR-016 | Dependency compromise | TB6 | Pinned hashes, `pip-audit`, Trivy, pinned base digest | PLAN WS-17 | Transitive zero-days |
| THR-017 | Unsafe logging | TB5 | Field allowlist, never-log denylist, a grep test | `PRV-007`, `PRV-008` | `CONTENT_RETENTION=full` |
| THR-018 | CSRF on the dashboard | TB4 | `SameSite=Strict`, CSRF tokens, CSP | `SEC-005`, `SEC-007` | — |
| THR-019 | Timing attack on keys | TB1, TB4 | Constant-time comparison | `SEC-002` | — |
| THR-020 | Silent mock mode in production | TB6 | Four-place visibility; startup refusal | `DEP-004`, `DEP-005` | Explicit operator override |

Every control column cites a real requirement ID and, in turn, a real
component and test — see `SPEC.md` §20's traceability table for the
requirement-to-test mapping, and `docs/architecture.md` for where each
component sits in the request lifecycle.

## Residual risks

Stated without hedging, as `SPEC.md` §19.5 requires:

- Heuristic detection has false positives and false negatives.
- The audit chain is tamper-**evident**, not tamper-proof (`THR-014` above;
  see `docs/architecture.md`'s "Audit chain integrity" section and
  `SECURITY.md`).
- The MVP is single-instance — no multi-instance coordination, no
  distributed rate limiting or approval-queue consistency.
- Streaming (`stream: true`) is unsupported; the MVP rejects it outright
  rather than partially inspecting a token stream (`API-014`).
- A compromised reviewer credential defeats human-in-the-loop entirely —
  the approval workflow's security rests on that key remaining secret,
  the same way any credential-gated control does.
- The firewall does not and cannot know the calling application's
  authorization model — it is a network control point, not a replacement
  for application-level entitlements (`SEC-020`, PLAN.md's non-goal 1).

### Phase 7 adversarial-review findings (`docs/adr/0009`)

Thirteen deliberate evasion attempts were run against the real detectors;
nine confirmed real gaps, of which seven were fixed (narrow, additive,
corpus-preserving — see the ADR). The four that were **not** fixed each
have a pinning test in
`tests/test_adversarial.py::TestDocumentedResidualRisks`, so a silent
regression — or an unnoticed future fix — would be caught:

- **THR-004 extension** — a domestic phone number with no leading `+`
  (E.164 form) is not recognised as PII at all. Not fixed: a general
  national-phone-number pattern is a well-documented false-positive source
  (order numbers, zip codes, dates), and PLAN.md's own R1 risk exists to
  warn against exactly this trade.
- **THR-008 extension** — a destructive shell command reworded with
  long-form flags (`rm --recursive --force` vs. the recognised `rm -rf`)
  evades the `destructive_sql_command`/`destructive_shell_command` rule's
  own pattern list, though today's default policy still denies the call
  overall (the tool itself is not allowlisted). An open-ended
  alternate-spelling arms race, judged out of a "narrow fix"'s scope.
- **THR-001 extension** — splitting a keyword with ordinary visible
  punctuation or spaces (`I.g.n.o.r.e`, `I g n o r e`) evades every
  pattern; these are readable characters, not invisible ones normalization
  can strip, and closing this generically risks a much higher
  false-positive rate against ordinary spaced-out or acronym-style text.
- **THR-003 restated with a confirmed bound** — a base64 payload nested
  five layers deep is not decoded. Not a bug: `MAX_DECODE_DEPTH = 3`
  (`SYS-012`) is a deliberate bound, confirmed still exactly 3; raising it
  arbitrarily trades this residual risk for a denial-of-service one
  (`THR-015`, unbounded decode recursion).

Seven other probes (Unicode confusables missing from the homoglyph table;
invisible characters outside the previously-stripped set; an SSN/IBAN
separator or case variant; an AWS STS temporary-credential prefix; a
SQL-comment-prefixed destructive statement; a whitespace-doubled shell
command) were real gaps and are now fixed — see `docs/adr/0009` for each and
`tests/test_adversarial.py::TestFixedEvasions` for the pinned regression
test.

## Reporting a new threat or gap

See [`SECURITY.md`](../SECURITY.md) for how to report a vulnerability or a
detector-evasion gap not already listed above.

## Related documents

- [`SPEC.md` §19](../SPEC.md#19-security-threat-model) — the normative
  source for everything in this document.
- [`docs/architecture.md`](architecture.md) — where each control in the
  table above actually runs in the request lifecycle.
- [`docs/adr/0009-phase7-benchmarking-and-adversarial-review.md`](adr/0009-phase7-benchmarking-and-adversarial-review.md)
  — the full account of the adversarial-review findings above.
- [`SECURITY.md`](../SECURITY.md) — disclosure process and the same
  residual risks stated for an evaluator arriving from the README.
