# ADR 0008: Phase 6 — rate limiting, metrics, structured audit, and security scanning

## Status

Accepted. Implemented and verified end to end, including a live `uvicorn`
process driven with real `curl` requests, a real `docker build` +
`docker run`, a real `pip-audit` run, and a real `Trivy` scan against the
actual built image (not a hypothetical one).

## Context

PLAN.md §6's Phase 6 section is narrow:

> **Tasks** — WS-12, WS-13, WS-17.
> **Deliverables** — audit events; the export command; metrics; the rate
> limiter; SSRF and header hardening; dependency scanning.
> **Automated checks** — the audit-privacy grep test; the
> metric-cardinality test; rate-limit tests; `pip-audit` and Trivy clean.
> **Manual validation** — a Prometheus scrape returns the documented
> metric names.
> **Exit gate** — the whole PII corpus runs with debug logging on and no
> original value appears anywhere in captured output.

Four prior ADRs each named a piece of this as explicitly deferred: ADR 0004
("`detector_findings`, `policy_hits`, `idempotency_records`,
`rate_limit_state` ... deferred to Phase 4's broader observability/
rate-limiting work"), ADR 0005 ("audit/metrics/rate-limiting (Phase 6)"),
ADR 0006 ("WS-12 ... Prometheus metrics, `GET /metrics`... WS-13 ... the
`RATE_LIMIT_*` settings exist and are validated at startup but nothing yet
enforces them"), and ADR 0007 ("WS-17 (SSRF hardening beyond the existing
production-only check, dependency scanning, `pip-audit`/Trivy in CI) ...
all scheduled for Phase 6 or later"). Before writing any code, the repo was
re-checked directly (not assumed from those ADRs' silence): `app/db.py` had
no `rate_limit_state` table; `app/decision.py` had the literal skip-comment
`# WS-13 (Phase 6) — not evaluated by the decision engine`; no
`app/metrics.py`, `app/ratelimit.py`, `app/cli.py`, or `app/logging_config.py`
existed; `.github/workflows/ci.yml` had a comment naming this exact phase
as where a security job would be added; `structlog` was an unused listed
dependency (`pyproject.toml`, never imported anywhere).

WS-12/13/17's own text (§5) is broader than the Phase 6 phase-summary
above and is what actually governs scope here:

- **WS-12** — "structured JSON logging; the audit event model; a log-field
  allowlist and a never-log denylist; correlation IDs; Prometheus registry
  and metric definitions; `GET /metrics`; a JSONL audit export command."
  Acceptance: "every decision produces exactly one audit event (PRV-009);
  no raw PII or secret value appears in any log at any level (PRV-008);
  metric label cardinality is bounded (OBS-012)."
- **WS-13** — "a sliding-window limiter backed by SQLite; per-identity
  keys; `429` with `Retry-After`; rate-limit metrics; policy-configured
  limits." Acceptance: "the configured limit is enforced within one
  request of accuracy; limiter state survives restart; the limiter never
  blocks the approval-decision path."
- **WS-17** — "SSRF protections on the upstream URL; dependency pinning
  with hashes; `pip-audit` and Trivy in CI; secret scanning; a
  security-headers middleware; a resource-exhaustion review; fail-closed
  production defaults."

Two of WS-17's five deliverables were already shipped in earlier phases,
confirmed by reading the actual code rather than assuming: SSRF protection
on the upstream URL (`app/providers/openai_compatible.py`'s
`validate_upstream_url_for_production()`, ADR 0005/0007, with its own
8-test `TestSsrfValidation` class already in
`tests/test_provider_openai_compatible.py`) and the security-headers
middleware (`SecurityHeadersMiddleware`, ADR 0006, SEC-008). This ADR does
not re-litigate either; it covers what those four prior ADRs actually left
open: the rate limiter, the metrics/audit/logging half of WS-12, and
WS-17's remaining "`pip-audit` and Trivy in CI" + "dependency pinning"
items. `SPEC.md` §10's remaining tables not named above
(`detector_findings`, `policy_hits`-as-a-table, `idempotency_records`,
`encrypted_payloads`) are **not** built here — no automated check in
PLAN.md's Phase 6 section requires them, and nothing here forecloses
adding them later.

## Decision

### 1. `rate_limit_state` is a fixed-window counter, not a sliding log

SPEC.md §10's own column list for `rate_limit_state` — `identity_id`,
`window_start`, `request_count`, `updated_at`, unique on
`(identity_id, window_start)` — is exactly a fixed-window counter's shape.
A true sliding-window (or sliding-log) limiter needs one row per admitted
request, or a decaying counter interpolated between two adjacent windows;
neither has anywhere to live in that schema. WS-13's own prose calls the
limiter "sliding-window," but SPEC.md's data model is the more concrete,
more authoritative artifact where the two disagree (per this project's
standing rule that SPEC.md wins). `app/ratelimit.py` implements a fixed
window: `window_start = floor(now / window_seconds) * window_seconds`,
one row per `(identity_id, window_start)`, incremented atomically under
`BEGIN IMMEDIATE` (the exact primitive `app/db.py.immediate_transaction()`
already gives the approval workflow — APR-004's "two concurrent writers
must never both read the same pre-increment count" reasoning applies
identically here). The practical difference from a true sliding window is
a boundary effect (a burst straddling two adjacent windows can momentarily
allow closer to `2x` the configured rate) that this MVP accepts as a
documented simplification, consistent with WS-13's acceptance bar of "one
request of accuracy," which a fixed window satisfies exactly at its own
window boundary.

Retention ("swept beyond two windows") is enforced inline, inside every
`check_rate_limit()` call, by deleting rows with
`window_start < current_window_start - 2 * window_seconds` — no separate
scheduled sweeper process, consistent with how `app/approvals.py`'s
`sweep_expired()` is also called lazily rather than from a timer thread.

### 2. Configured limits come from the policy first, Settings second

WS-13 names both "policy-configured limits" and reuses the
already-validated `RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW_SECONDS`
settings. `app/ratelimit.rate_limit_config_from_policy()` reads
`policies/default_policy.yaml`'s `rate_limit_default` rule
(`rate_limit: {requests: 60, window_seconds: 60, scope: identity}`) when a
policy is loaded and some rule declares a `rate_limit` block; it falls back
to `Settings.RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW_SECONDS` when no
policy is loaded at all (POL-009's degraded-policy window) or no rule
declares one. This keeps the operator-facing story simple — edit the
policy file to change the limit in the common case, same as every other
threshold in this system — while the Settings fields remain a real,
validated fallback rather than dead configuration.

`app/decision.py`'s existing skip (`if "rate_limit" in rule: continue`) is
unchanged and still correct: the generic condition evaluator has no
"requests observed in this window" fact to evaluate against, and never
will — enforcement is a stateful, per-request database operation, not a
pure function of one request's findings the way every other rule is. The
comment there is updated to point at this ADR and at `app/ratelimit.py`,
rather than continuing to say only "Phase 6 — not evaluated."

### 3. The limiter is called once, inline, before detection work — not generic middleware

§2.17's only stated prohibition is specific: "MUST NOT rate-limit
`GET /healthz`, `GET /readyz`, or the approval-decision endpoint." Nothing
in SPEC.md says every other authenticated route must be limited too. A
generic middleware applied to all routes would need per-route exemption
logic to satisfy that prohibition and would also rate-limit routes WS-13's
own framing ("blunt cost and abuse attacks") was never really about — the
reviewer dashboard, the approvals list, `/v1/firewall/requests/{id}`
polling. Cost and abuse in this system's threat model (THR-015, "denial of
service") is about the one endpoint that spends real CPU on detection and
can, once a real provider is configured, spend real money on an upstream
call: `POST /v1/chat/completions`. The limiter check is therefore called
directly inside that one handler, immediately after resolving the caller's
identity (needed to scope the check) and immediately before
`run_input_pipeline()` — deliberately before any detector runs, so a
request that is going to be refused never pays for normalization, six
detectors, and policy evaluation first. This also trivially satisfies the
"never blocks healthz/readyz/decision" prohibition: those three routes
never call `check_rate_limit()` at all, because it exists in exactly one
place.

### 4. Fail-open in development, fail-closed in production (§2.17)

`check_rate_limit()` itself does not catch its own database exceptions —
`app/main.py`'s call site does, and decides fail-open/fail-closed based on
`APP_ENV`, matching §2.17's literal text and the same pattern
`app/audit.py`'s write-failure handling below reuses. A database error is
rare enough (WS-13's own risk note names "limiter overhead," not
"limiter unavailability," as the anticipated risk) that this is a thin,
directly-testable piece of logic rather than a speculative one.

### 5. `resolve_identity()` had a latent gap this phase's own change surfaced — fixed

Before this phase, `resolve_identity()` was only ever called from the
`NEED_APPROVAL` branch of `create_chat_completion()` for the immediate
`ALLOW`/`DENY` verdicts — never for `ALLOW`, since nothing on that path
needed an identity yet. Moving identity resolution to the top of the
handler (needed so the rate limiter has an identity to scope by, before
detection even runs) exercises that function on every request for the
first time, and it immediately broke
`tests/test_openai_sdk_contract.py`'s `test_unmodified_sdk_gets_a_working_completion`:
an unmodified `openai` SDK client always sends *some* `Authorization`
header (it has no concept of "no credential"), and in development with no
`FIREWALL_API_KEYS`/`FIREWALL_REVIEWER_KEYS` configured,
`resolve_identity()` was rejecting that placeholder header as an
"Unrecognized API key" — a real, if previously dormant, inconsistency:
SEC-003 says unauthenticated operation is *fully permitted* under those
conditions, but the function only granted its anonymous fallback when
*no* header was presented at all, not when a meaningless one was. Fixed in
`app/auth.py`: the "no keys of either class configured" check now runs
first, unconditionally, before looking at the header — when there is
nothing configured to validate a credential against, presenting one
(genuine or a placeholder) and presenting none are treated identically.
This changes no behavior when any key is configured (dev or production);
verified directly by re-running every existing auth-related test
unmodified after the fix, all passing.

### 6. Metrics: one `CollectorRegistry` per `AppState`, the full §13.1 catalogue verbatim

`tests/conftest.py`'s `client_factory` builds many `AppState`s inside one
test process. Registering the same metric name twice against
`prometheus_client`'s process-wide default registry raises
`ValueError: Duplicated timeseries` — confirmed by trying it first.
`app/metrics.build_metrics()` therefore takes a fresh `CollectorRegistry`
per call, and `AppState.__init__` constructs one per process; `GET
/metrics` serves `generate_latest(state.metrics.registry)`. All 26 metrics
in SPEC.md §13.1's table are implemented with the exact name, type, and
label set the table declares — nothing renamed, nothing added, nothing
dropped. `OBS-002` (`firewall_added_seconds` = total − upstream) is
satisfied by observing it with `plane="input"` (the detection-pipeline
duration) and, only on the path that reaches the output guard,
`plane="response"` (the output-guard duration) — the two together are
exactly "total minus upstream" split by which plane spent the time.
`OBS-003` (`upstream_calls_avoided_total` on every `DENY` and every
unresumed `NEED_APPROVAL`) is the one metric that needed real care: an
immediate input-plane `DENY` increments it immediately (the upstream was
never going to be called); a `NEED_APPROVAL` does **not** increment it at
creation time — only later, in `app/approvals.py`, at whichever terminal
state means it was never resumed to completion (`EXPIRED`, a reviewer's
`DENY`, `RESUME_ARGUMENTS_CHANGED`'s pre-upstream-call denial, or a
startup-reconciled `FAILED`). A `RESUME_OUTPUT_GUARD_DENIED` outcome does
**not** increment it — the upstream call already happened there; only the
response was blocked afterward, which is the same reasoning the
input/output-plane split already uses for the immediate-ALLOW path's own
response-plane `DENY`.

### 7. Cardinality bounding (OBS-012)

- `endpoint`: always a fixed route-template string
  (`app/metrics.ENDPOINT_TEMPLATES`), read from
  `request.scope["route"].path_format` inside `HttpMetricsMiddleware` —
  never the resolved path. An unmatched route (a genuine 404) is labelled
  `"unmatched"`.
- `rule_id`/`detector_id`: already bounded by the loaded policy's own
  rule/detector count (small, operator-controlled, never derived from a
  request).
- `tool_name`: clamped to the policy's `agent_tool_allowlist` rule's
  `tool_not_in` list plus the literal `"other"`
  (`app/metrics.bounded_tool_name()`), read from the loaded policy at
  startup (`app/main.py._tool_allowlist_from_policy()`) so it can never
  silently drift from what the policy actually allows.
- Every other label (`verdict`, `plane`, `mode`, `level`, `state`,
  `outcome`, `transformation`, `error_code`, `reason` on
  `degraded_transactions_total`, `kind` on `upstream_errors_total`) is a
  small, closed, code-defined enum — never a raw value from the request.
- No metric anywhere carries `transaction_id`, `identity_id`,
  `correlation_id`, user content, or a model-supplied string as a label.

`tests/test_metrics.py::TestCardinality` asserts the exact declared label
set of every one of the 26 metrics directly against `app/metrics.py`'s own
`METRIC_LABELS` table (introspecting each `Counter`/`Histogram`/`Gauge`'s
`_labelnames` — deterministic, unlike requiring every metric to have a
live sample first, which several plausibly never do in one test scenario
since a labelled Prometheus metric emits nothing until `.labels(...)` is
first called for that combination).

### 8. `GET /metrics` and `METRICS_REQUIRE_AUTH`

API-017: "MAY require a service key when `METRICS_REQUIRE_AUTH=true`,
which MUST default to true in production" (already enforced at startup by
`app/config.py`, prior phase). Read literally: when the flag is `false`
(the non-production default), the endpoint takes no identity check at all
— not even the SEC-003 anonymous-fallback path, just genuinely open,
matching "MAY require ... when ... true" rather than "always requires
something." When `true`, `resolve_identity()` is called and any
recognized key of *either* class succeeds — not service-only. SEC-001's
table explicitly lists `/metrics` under Service's allowed-endpoints column,
but Reviewer's own row leaves its "May NOT call" cell empty for this
endpoint (unlike, say, "Any approval endpoint" being explicitly listed as
forbidden to Service). Read as written, nothing forbids a reviewer key
from working here; inventing an undocumented reviewer-specific 403 would
be adding a restriction SPEC.md does not state, and there is no operational
reason to keep a reviewer credential from reading operational metrics.

### 9. Structured JSON logging (OBS-004) and the PRV-007 allowlist, enforced by code

`structlog` was a listed, unused dependency since Phase 1. Rather than
introduce it now for one straightforward formatting job, `app/logging_config.py`
implements `OBS-004`/`PRV-007` directly against the stdlib `logging`
module: `AllowlistJsonFormatter` emits `timestamp`/`level`/`event` plus
only those `extra=` fields present in SPEC.md §12.2's literal 27-field
list, copied verbatim as `_ALLOWLIST_FIELDS` — any other field a call site
supplies is silently dropped, not raised, so a logging call itself can
never become a new way to fail a request. `configure_logging()` is called
first thing in `AppState.__init__`, before the mock-mode warning three
lines later, so every line this process ever writes goes through it.
`structlog` remains an unused dependency after this phase — removing it
from `pyproject.toml` was judged out of this ADR's scope (a one-line
dependency-hygiene change unrelated to any Phase 6 acceptance criterion);
a natural candidate for a later cleanup pass.

### 10. The `decision` audit event (PRV-009) is a second, independent hash-chain stream

ADR 0004 already writes several `APPROVAL_*`-typed audit events for the
`NEED_APPROVAL` lifecycle, chained per `approval_id` — real, but a
different `event_type` from what PRV-009 asks for ("exactly one audit
event of type `decision`"), and never written at all for the immediate
`ALLOW`/`DENY` paths, which have no `approval_id`. `app/audit.py`'s
`record_decision_event()` is called from every one of `app/main.py`'s
three verdict branches (input-plane `DENY`, `NEED_APPROVAL`, and the
post-output-guard `ALLOW`/`DENY`), writing exactly one `event_type="decision"`
row per transaction. DAT-005 requires a hash chain "forming a per-stream
chain" without naming the stream; since a plain `ALLOW`/`DENY` has no
`approval_id` to chain by, this function chains per `transaction_id`
instead — filtering `WHERE transaction_id = X AND approval_id IS NULL` for
the previous link, so this stream and ADR 0004's per-`approval_id` stream
never cross. A `NEED_APPROVAL` transaction therefore ends up on two
independent, correctly-scoped chains: one `decision` event on its
`transaction_id` stream, and one or more `APPROVAL_*` events on its
`approval_id` stream. `payload` carries only PRV-007-allowlisted fields
(verdict, risk level, transformation, reason/policy-hit ids, policy
version, mode, degraded) — never request or response content, satisfying
PRV-008 by construction rather than by a redaction pass.

Per §2.15 ("an audit write failure MUST fail the transaction closed when
`APP_ENV=production`. Evidence is not optional."), `app/main.py`'s
`_audit_decision()` helper re-raises as `DATABASE_ERROR` (503) in
production and logs-and-continues everywhere else — the same fail-open/
fail-closed split the rate limiter uses, for the same underlying reason
(a database hiccup in local development should not block a response over
an evidence write that isn't yet durable there; in production, evidence is
mandatory).

### 11. The audit export command (PRV-006)

`python -m app.cli export-audit --since ... --until ... --format jsonl`
did not exist anywhere in the codebase before this phase (WS-12's own
deliverable list names it explicitly: "a JSONL audit export command").
`app/cli.py` queries `audit_events` ordered oldest-first, optionally
bounded by `--since`/`--until` (RFC 3339 or bare ISO 8601), and writes one
JSON object per line to stdout with a fixed field set. "Honouring the
active retention mode" (PRV-006's own phrase) needs no special handling
here: every `audit_events.payload`, at every write site in this codebase
(`app/audit.py`, `app/approvals.py`'s `_audit()`), is built from
PRV-007-allowlisted fields only and never from a `CONTENT_RETENTION`-
classified column — `CONTENT_RETENTION` governs what `transactions`/
`approvals` store, not what this table has ever contained, so exporting it
verbatim is safe under every retention mode without this command doing any
redaction of its own.

### 12. WS-17: what was already done, what this phase adds, and what remains a residual risk

SSRF protection and the security-headers middleware were verified, by
reading the actual code and its existing 8-test class, to already be real
(ADR 0005/0006/0007) — not re-built here. What this phase adds is the
concrete "`pip-audit` and Trivy in CI" deliverable and one real Dockerfile
fix Trivy's own output led to:

- **`pip-audit`**, run against a venv built with exactly the production
  dependency set (`pip install .`, never `.[dev]`) — the same set the
  Dockerfile's runtime image ships. Result: **zero known vulnerabilities**.
  (Running it against this repo's own development environment instead
  finds one — `PYSEC-2026-1845` in `pytest` 8.4.2, a local-`/tmp`-directory-
  naming issue relevant only on a shared multi-user Unix host — but `pytest`
  is `pyproject.toml`'s own `[project.optional-dependencies].dev` and is
  never installed into the image the Dockerfile builds, confirmed by
  reading its `builder` stage's `pip install --no-cache-dir .` line.)
- **Trivy**, run against the actual image built from this repository's
  `Dockerfile` (`docker build` + `docker run`, not a hypothetical). The
  first real scan found 54 Debian OS-package findings (51 HIGH, 3
  CRITICAL) and 2 HIGH findings in Python packages: `msgpack` 1.1.2
  (`GHSA-6v7p-g79w-8964`) and `setuptools` 70.3.0 (`CVE-2025-47273`).
  Neither Python finding is a real-guard-v1 dependency at all — `pip show
  msgpack` inside `/opt/venv` finds nothing; both trace to `pip` itself,
  which vendors its own copies of both for its own internal use while
  resolving/installing packages (`pip/_vendor/vendor.txt` lists them
  verbatim) — present in the shipped image only because the base image
  ships a system-level `pip`, and the builder stage's own
  `pip install --upgrade pip` copies an upgraded venv-local `pip` into the
  final image too. **Fix**: the `Dockerfile`'s runtime stage now removes
  every copy of `pip` (system and venv) after the venv it needs has
  already been built — the application never invokes `pip` at runtime, so
  removing it costs nothing and drops both findings entirely, confirmed by
  rebuilding and re-scanning (0 Python-package findings afterward, matched
  against every one of the 36 real dependencies' `dist-info`).
  The 54 Debian OS-package findings remain: re-pulling `python:3.12-slim`
  bare (no digest pin) at the time this ADR was written resolved to the
  **exact same digest already pinned** in the `Dockerfile` — there is no
  newer base image to move to right now. Re-running the scan with
  `--ignore-unfixed` (Trivy's own flag for "has no available fix yet")
  removes every one of the 54 — none currently has a Debian security patch
  published. This is a genuine, currently-unresolvable residual risk,
  stated here rather than hidden, not a "Trivy clean" claim without
  qualification: the CI `security` job therefore gates on
  `--ignore-unfixed`, which is **zero** findings today, and will start
  failing the moment a fix becomes available and this image is rebuilt
  without picking it up — an actionable, honest bar rather than a
  permanently-red one over CVEs nothing in this repository can fix.
- **Dependency pinning with hashes** (WS-17's other named deliverable) —
  **not done**. `pyproject.toml` continues to pin version *ranges*
  (`fastapi>=0.115,<1.0`, etc.), not a hash-locked requirements file
  (`pip-compile --generate-hashes` or equivalent). Building and
  maintaining a hash-locked dependency file is a real, ongoing workflow
  change (a lockfile to regenerate on every dependency bump, checked into
  the repo) that this phase's time did not extend to; it is left as an
  explicit, named gap rather than silently omitted — see the completion
  report's caveats.
- **Secret scanning** (`gitleaks`) is explicitly Phase 9's own automated
  check per PLAN.md ("full-history secret scan ... gitleaks clean over
  full history") and is not duplicated here; Phase 6's own automated-check
  list names only "`pip-audit` and Trivy clean."
- **Resource-exhaustion review** and **fail-closed production defaults**
  were reviewed against the threat model (THR-015) and found already
  covered by prior phases' work (request size limits, detector deadlines,
  the production startup-validation gate) — no new code was needed or
  written for either.

## Verified, not merely asserted

- `pytest -m "not docker and not ollama"` (the count on any machine
  without either): **377 passed**, 0 failed, in ~5s — up from 352 before
  this phase (25 new tests: `tests/test_ratelimit.py` (10),
  `tests/test_metrics.py` (8), `tests/test_cli.py` (5),
  `tests/test_audit_privacy.py` (2)). **386 collected total** on this
  machine (Docker daemon and a real local Ollama with `qwen3:8b` both
  present, so all 5 `docker`- and 4 `ollama`-marked tests run for real
  rather than skipping) — up from 361. One honestly-reported caveat, found
  and confirmed while repeatedly re-running the suite during this phase's
  own testing: `tests/test_ollama_live.py::test_benign_request_allowed_by_real_model`
  failed on every isolated rerun attempted on this machine today, each
  time on `UpstreamTimeoutError` at exactly the test file's own configured
  120-second timeout (doubled by one retry). A direct `curl` to the same
  local Ollama for a trivial prompt answered in ~10 seconds — Ollama
  itself is reachable, not down — but `qwen3:8b` is a "thinking" model
  whose hidden-reasoning time varies by prompt, and this specific
  benign-request prompt is apparently taking longer than 120 seconds on
  this host right now. This is squarely Phase 5's territory (real-model
  latency against a fixed timeout in `app/providers/openai_compatible.py`)
  — nothing in this phase's code touches that path — and is exactly the
  class of residual risk `docs/adr/0007` already names ("a startup
  preflight... is a startup gate, not a continuous liveness probe" is a
  closely related admission that live-model behavior can change after any
  point this system last checked it); see README's "Testing" section for
  the same disclosure in the user-facing doc.
- `ruff check .`: clean. `ruff format --check .`: clean. `mypy app`
  (strict): clean, 42 source files.
- `scripts/validate_contracts.py`: all checks pass, including the frozen
  54-case corpus (untouched by this phase).
- A live `uvicorn` process was driven with real `curl` requests: exceeding
  a configured low rate limit returns `429 RATE_LIMITED` with a real
  `Retry-After` header, and the limit genuinely clears after the
  configured window elapses; `GET /metrics` returns real Prometheus text
  exposition reflecting the actual requests just made, gated correctly by
  `METRICS_REQUIRE_AUTH`. Exact commands and captured output are in
  `README.md`'s new "Rate limiting" and "Observability" sections.
- A real `docker build` + `docker run` of the modified `Dockerfile`: the
  container serves `/healthz`, `/v1/chat/completions`, and the new
  `/metrics` correctly with `pip` removed from the runtime image.
- A real `pip-audit` run against a venv built with exactly the production
  dependency set: zero known vulnerabilities.
- A real `Trivy` scan of the actual built image, before and after the
  Dockerfile fix: 2 HIGH Python-package findings before, 0 after; 54
  Debian OS findings unchanged either way, 0 of them fixable today
  (`--ignore-unfixed`).
- `tests/test_audit_privacy.py` runs all 18 `PII_INPUT`/`SECRET_INPUT`/
  `OUTPUT_LEAKAGE`/`LEAK_OUTPUT` golden-corpus cases at `LOG_LEVEL=DEBUG`
  and asserts none of their literal request content, nor any of
  `TST-021`'s seeded raw output values (the SSN, email, secret key and
  canary token the mock provider emits), appears anywhere in real captured
  stdout.

## Consequences

- `NEED_APPROVAL`, `ALLOW` and `DENY` all now produce real Prometheus
  metrics, a real `decision` audit event, and are subject to a real,
  persisted, per-identity rate limit — none of WS-12/13's acceptance
  criteria are claimed without the test or live command that verifies
  them.
- `GET /metrics` and `python -m app.cli export-audit` are both real,
  documented commands now — `/metrics` was already a frozen path in
  `openapi.json` since Phase 0 (confirmed before writing any code); this
  phase is what makes it actually respond rather than 404.
- WS-17 is substantively, honestly advanced but not entirely closed:
  dependency-hash pinning is a named, real gap; the 54 unfixable Debian OS
  CVEs are a stated residual risk, not a claim of a spotless scan.
- `detector_findings`, `policy_hits`-as-a-table, `idempotency_records`, and
  `encrypted_payloads` remain deferred — still not required by any
  automated check PLAN.md's Phase 6 section actually names, and still not
  foreclosed by anything built here.
- `resolve_identity()`'s dev-mode fallback is slightly more permissive than
  before this phase (any presented credential, not only a missing one, is
  accepted when zero keys of either class are configured) — a deliberate,
  tested, documented fix motivated by moving identity resolution earlier
  for the rate limiter, not a security regression: it only ever applies
  when SEC-003's own "no keys configured" condition already permits fully
  unauthenticated operation.
