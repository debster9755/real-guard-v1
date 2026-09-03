# ADR 0004: NEED_APPROVAL is a real, persisted workflow — pulled forward from Phase 4

## Status

Accepted. Implemented and tested before Phase 3, at the user's explicit direction.

## Context

Phase 2's completion report flagged an honest gap: `NEED_APPROVAL` had no
durable infrastructure. `app/main.py`'s `_need_approval_stub` refused every
`NEED_APPROVAL` verdict outright (`403`) rather than issue a `202` with an
`approval_id` nothing could ever resolve — refusing was judged safer than
faking a promise, but it meant the verdict didn't actually work.

The user asked for this closed properly: 4-5 realistic test cases (real
inputs, real expected outputs), a genuine end-to-end implementation rather
than a fake `202`, verification that it actually works, and documentation of
the test cases in `README.md` — completed *before* Phase 3 starts, as a
deliberate reordering of PLAN.md's phase sequence for this one piece of work.

SPEC.md §9's approval state machine, §2.13/§2.14 (approval service, resume
worker), §10 (data model), and §11 (auth) together specify a large surface:
SQLAlchemy/SQLite persistence, the full 8-state machine, a resume worker,
reviewer bearer-key **and** session-cookie authentication, CSRF, an HTML
dashboard, and several tables (`detector_findings`, `policy_hits`,
`idempotency_records`, `rate_limit_state`, `encrypted_payloads`) that belong
to other, still-future workstreams. Building all of it now would have
silently absorbed most of Phase 4 (WS-09..WS-11) under cover of "closing one
gap." This ADR draws the line: **everything APR-001..015 actually requires
for `NEED_APPROVAL` to be real is in scope; the reviewer HTML dashboard,
session-cookie auth, and the broader per-request audit/rate-limit tables are
not**, and remain Phase 4 as originally planned.

## Decision

### 1. A new detector pattern makes `review_probable_jailbreak` reachable

Before this change, every `PROMPT_INJECTION`/`JAILBREAK` pattern in
`app/detectors/prompt_injection.py` scored `>= 0.85`, so
`policies/default_policy.yaml`'s `review_probable_injection` and
`review_probable_jailbreak` rules (`score_gte: 0.50, score_lt: 0.85`) had no
reachable trigger — dead policy. A new pattern, `roleplay_no_restrictions_v1`
("let's roleplay a character with no restrictions"), scored `0.65`
(`Confidence.MEDIUM`), gives `review_probable_jailbreak` a genuine,
realistic trigger: a soft social-engineering cue that's ambiguous enough to
warrant human review rather than an automatic verdict either way. Checked
against `tests/data/golden_corpus.jsonl` for accidental overlap (none) and
against the full 54-case suite (unaffected — `pytest` still reports the same
42 passing / 12 skipped as Phase 2).

### 2. Persistence scope: only `NEED_APPROVAL` transactions are written

`app/db.py` adds `transactions`, `approvals`, `approval_decisions`, and
`audit_events` (SQLite, WAL mode, SQLAlchemy 2.0). A `transactions` row is
written **only** when the verdict is `NEED_APPROVAL` — the `ALLOW`/`DENY`
paths in `app/main.py` are untouched from Phase 2 and have no DB dependency.
Full per-request persistence for every verdict (the broader observability
goal WS-09 names) is still Phase 4. `detector_findings`, `policy_hits` (as
tables — the list itself is still carried as JSON on `approvals`),
`idempotency_records`, and `rate_limit_state` are not created; nothing here
forecloses adding them later (SQLAlchemy models and Alembic migrations are
additive). Alembic itself is not wired up — there is no prior deployment to
migrate from yet, so `Base.metadata.create_all()` is sufficient until a real
upgrade path is needed.

### 3. Two additive columns beyond SPEC.md §10's explicit list

- `approvals.creator_identity_id` — required to enforce APR-009
  (self-approval forbidden): the check is "does the deciding identity equal
  the identity that created this transaction," which needs the creator's
  identity stored somewhere.
- `approvals.completion_result` — required so the poll endpoint can deliver
  the completed response **at all**. SPEC.md's `transactions.response_content`
  is marked `SENSITIVE` and gated by `CONTENT_RETENTION` (default
  `metadata`), which — read literally — would mean a `NEED_APPROVAL` request
  could never actually receive its answer back in the default configuration,
  defeating the verdict's entire purpose. Resolution: `CONTENT_RETENTION`
  governs the long-term **audit** copy on `transactions.response_content`
  (purged independently per `CONTENT_RETENTION_DAYS`); `approvals.completion_result`
  is live delivery state, not audit retention, and is always written on
  `COMPLETED` regardless of the retention mode. Same reasoning applies to
  `approvals.preview_content`/`transformed_payload`, which the feature
  cannot function without.

### 4. Audit hash chain is per-`approval_id`, not global

DAT-005 requires `event_hash = SHA-256(prev_hash || canonical(payload))`
"forming a per-stream chain" without naming the stream. Chained per
`approval_id`: it's the natural unit a reviewer or auditor would want to
verify in isolation, and avoids a single global chain becoming a write
bottleneck across unrelated approvals. `AuditEventRow` still carries
`transaction_id` for cross-referencing.

### 5. No output-plane inspection during resume

SPEC.md §3.4's resume flow implies the completion is output-guarded before
`COMPLETED`. That guard (WS-07) does not exist yet for the immediate-`ALLOW`
path either — Phase 2 forwards the upstream completion unfiltered. Rather
than build output inspection uniquely for the approval-resume path (which
would also mean inventing an undrawn `RESUMING -> DENIED` "output blocked"
transition not on SPEC.md §9.2's diagram, violating APR-001's "only the
drawn transitions are permitted"), resume stays at the same maturity level
as the rest of the system: it completes to `COMPLETED` once the provider
call succeeds. When Phase 3's output guard lands, it runs identically on
both paths via one shared function — no change to the state machine.

### 6. `reconcile_resuming_on_startup`'s `RESUMING -> FAILED` edge

APR-014 requires moving a stuck `RESUMING` row to `FAILED` once
`MAX_RESUME_ATTEMPTS` is exhausted, but SPEC.md §9.2's diagram draws
`RESUMING` only to `COMPLETED`/`DENIED`/`APPROVED` — `FAILED` never appears
as a drawn destination from `RESUMING` (`FAILED` isn't drawn as reachable
from anywhere in the Mermaid diagram at all, despite being a documented
state in §9.1's table). This is treated as a specification gap, not a
license to skip APR-014: `reconcile_resuming_on_startup` applies the
`RESUMING -> FAILED` edge directly, documented in code as the one exception
to `ALLOWED_TRANSITIONS`/`_transition()`'s enforcement, rather than silently
extending the "authoritative" transition table to paper over the gap.

### 7. `review_sensitive_topic` gains `transformation: REDACT`

Previously `NONE`. Added so a sensitive-topic hold doesn't show a reviewer a
caller's raw PII/secrets any more than a plain `ALLOW` would (APR-012,
TRN-008). `apply_redact()` is a documented no-op when nothing matches
(`app/transform.py`), so this changes no existing case's outcome — verified
via the full test suite and `scripts/validate_contracts.py` — only what a
reviewer sees when PII/secrets happen to be present alongside a
sensitive-topic phrase. No golden-corpus case exercises `SENSITIVE_TOPIC`
(ADR 0001 addendum), so this is unaffected by the frozen corpus.

### 8. Authentication: bearer keys only, not the session-cookie route

SPEC.md §4.6 names two valid auth routes for the decision endpoint: a
reviewer bearer key, or a session cookie plus a CSRF token. `app/auth.py`
implements only the bearer-key route. The cookie-exchange flow (SEC-005),
CSRF (SEC-007), and the `/dashboard` login page belong to WS-10 (the
reviewer HTML dashboard) and are deferred there. `FIREWALL_API_KEYS`/
`FIREWALL_REVIEWER_KEYS` parsing, constant-time comparison, and the
disjoint-key-sets startup validation (SEC-006/APR-009) already existed in
`app/config.py` from Phase 1 — this ADR wires them to actual identity
resolution for the first time.

Self-approval (APR-009) is realistically triggered not by "the same literal
key registered in both `FIREWALL_API_KEYS` and `FIREWALL_REVIEWER_KEYS`"
(already refused at startup by `app/config.py`'s disjoint-key-sets check,
independently of this ADR) but by **the same reviewer key used for both
actions** — a reviewer key is a valid identity for `/v1/chat/completions`
too (nothing in SEC-001's table forbids it), so a reviewer who creates a
request and then tries to decide their own approval is caught. This is
exercised directly in `tests/test_approvals_api.py::test_scenario_4_self_approval_is_refused`.

### 9. The "resume worker" is folded into the decision request

SPEC.md §2.14 describes the resume worker as conceptually separate from the
decision endpoint (§3.4's sequence diagram shows the reviewer's `APPROVE`
persisted first, a worker claiming it later). This MVP has no separate
worker process or queue, so `POST /v1/firewall/approvals/{id}/decision`
calls `resume_approved()` inline, synchronously, immediately after recording
an `APPROVE` decision — before the HTTP response is returned. All of the
state machine's atomicity guarantees still hold (the `APPROVED -> RESUMING`
claim is still a single `BEGIN IMMEDIATE` write, independent of whether the
caller is a background worker or this same request), verified directly by
`tests/test_approvals_engine.py::test_resume_claims_exactly_once_under_concurrent_attempts_apr011`
(20 concurrent `resume_approved()` calls against one approval; exactly one
completes, the provider is called exactly once). The practical consequence:
in this MVP, there is no real-world window between a reviewer's `APPROVE`
and the resume attempt in which material arguments could change — the
material-argument re-validation path (APR-013) is real and tested, but only
reachable directly against `app/approvals.py` in tests, not through the live
HTTP flow. A true background worker is a natural, non-essential enhancement
for whenever request volume makes synchronous resume undesirable; nothing in
this design blocks adding one later.

### 10. All approval-workflow DB calls are synchronous, inline

`app/db.py`/`app/approvals.py` use plain (blocking) SQLAlchemy calls inside
`async def` route handlers, not wrapped in `asyncio.to_thread`. Acceptable
at SQLite's single-writer MVP scale, consistent with `BEGIN IMMEDIATE`
already serializing writes; a candidate for Phase 4 hardening if request
concurrency grows enough for it to matter.

## Verified, not merely asserted

- `pytest`: 223 passed, 12 skipped (unchanged skip set from Phase 2 — the
  output-plane/tool-call corpus buckets), 0 failed.
- `ruff check .`: clean. `mypy app`: clean (30 source files).
- `scripts/validate_contracts.py`: all checks pass, including the frozen
  54-case corpus (unaffected by anything in this ADR).
- A live `uvicorn` process was driven end-to-end with real `curl` requests
  (not just the test client) for every scenario below, including a
  deliberately corrupted `expires_at` row to force real TTL expiry and a
  genuine self-approval attempt using one reviewer key for both actions —
  the exact commands are reproduced in `README.md`'s "Approval workflow"
  section.
- `tests/test_approvals_engine.py::test_resume_claims_exactly_once_under_concurrent_attempts_apr011`
  actually races 20 concurrent `resume_approved()` calls through
  `asyncio.gather` against a call-counting provider double — APR-011's
  "exactly once" is measured, not just claimed by the code's shape.
- The full forbidden-transition matrix (`APR-003`) is exercised as a
  parametrized test over every `(from_state, to_state)` pair not on
  `ALLOWED_TRANSITIONS`, asserting both the `409`-equivalent error and that
  the row is provably unmutated afterward.

## Consequences

- `NEED_APPROVAL` now behaves as SPEC.md promises for every case the 54-case
  corpus and PLAN.md's phase sequence actually require today: durable,
  resolvable, auditable, safe under concurrent and self-approval attempts,
  and safe under TTL expiry.
- The reviewer HTML dashboard (WS-10), session-cookie auth (SEC-005/007),
  and the remaining SPEC.md §10 tables (full per-request audit trail,
  rate-limit state, idempotency records as a generic mechanism) are
  explicitly still open — Phase 4 is not fully "done early" by this ADR,
  only the approval lifecycle itself.
- Phase 3 (output guard, tool-call inspection) is unaffected and unblocked
  by this work; §5's reasoning is why resume deliberately does not reach
  ahead into Phase 3's territory.
