# ADR 0006: Reviewer dashboard, session-cookie authentication, and CSRF (Phase 4 / WS-10, WS-11)

## Status

Accepted. Implemented and tested end to end.

## Context

ADR 0004 deliberately deferred three things out of the approval-workflow
pull-forward: the reviewer HTML dashboard (WS-11), session-cookie
authentication and CSRF (WS-10/SEC-005/SEC-007), and the remaining SPEC.md
§10 tables that belong to other workstreams. This phase (PLAN.md Phase 4)
closes the first two. It picks up from a partially-built, uncommitted
working tree left by two earlier, interrupted sessions — `app/session.py`,
`app/dashboard.py`, the Jinja2 templates, vendored HTMX, and
`app/auth.py`'s `resolve_decision_identity()` already existed on disk and,
on inspection, were substantially correct. This ADR documents every
judgment call in that design (whether made by an earlier session or by this
one), the two real defects this session found and fixed, and what was
verified before any of it was trusted.

## Decisions

### 1. Two independent, stateless HMAC primitives — no server-side session store

`app/session.py` implements SEC-005's signed session cookie and SEC-007's
CSRF token as two separate, stateless constructions:

- **Session cookie**: `session_id|identity_id|issued_epoch|expires_epoch`,
  base64url-encoded, HMAC-SHA256-signed with
  `Settings.effective_session_secret()`. Verification is "does the
  signature match, and has `expires_at` not passed" — no database lookup, no
  server-side revocation list. `identity_class` is deliberately not part of
  the payload: a session is only ever minted for a reviewer identity
  (`dashboard_login_submit` rejects a service key before a cookie is ever
  created), so nothing decoding a cookie can produce anything but a
  reviewer `Identity`.
- **CSRF token**: `HMAC(SESSION_SECRET, "csrf:" + session_id)` — a
  synchronizer token, deterministically derived, not a random value stored
  anywhere. Rejected the double-submit-cookie pattern (a second,
  JS-readable cookie mirroring the token): that pattern needs a second
  cookie and a client-side script to copy it into a header, which is more
  moving parts than deriving the token directly from a value the server
  already has. The token is rendered directly into the dashboard's HTML
  (inside each pending item's `hx-headers` attribute) and read from there by
  the vendored HTMX build — a cross-site page has neither the `HttpOnly`
  session cookie's `session_id` nor `SESSION_SECRET`, so it cannot compute a
  valid token even though a browser will still attach the session cookie
  itself to a forged cross-origin request. This is the standard
  synchronizer-token security property, achieved without a session table.

Trade-off accepted: a token cannot be individually revoked before its
session expires (there is nothing to revoke — it is recomputed from the
session, not stored). `SESSION_TTL_SECONDS` (default 3600) bounds the
exposure window, consistent with SEC-005's own cookie-expiry design.

### 2. `resolve_decision_identity()` is the single place SEC-007 is enforced

SPEC.md §4.6 names two valid auth routes for the canonical decision
endpoint: `Authorization: Bearer <reviewer key>`, or a session cookie plus
`X-CSRF-Token`. `app/auth.py::resolve_decision_identity()` tries the bearer
header first (identical behaviour to the pre-Phase-4 `resolve_identity()` —
every existing bearer-only test keeps passing unmodified), and only when no
`Authorization` header is present does it consult the session cookie, where
a missing or mismatched CSRF token raises `CSRF_TOKEN_INVALID` (403) before
the caller ever reaches `decide_and_resume()`. Both
`POST /v1/firewall/approvals/{id}/decision` (`app/main.py`) and, indirectly,
the dashboard's own decision route funnel through this one function's
reasoning (the dashboard route re-implements the same cookie+CSRF check
inline rather than calling `resolve_decision_identity()` itself — see
decision 4 below for why it needs its own route at all).

### 3. `CSRF_TOKEN_INVALID` is a new error code, not an overload of an existing one

SPEC.md §16's original 21 error codes predate the session-cookie auth route
they'd need to describe a CSRF failure for. Added `CSRF_TOKEN_INVALID`
(403, `authorization_error`) rather than reusing `INSUFFICIENT_PRIVILEGE`:
the two failure modes are genuinely different (a stale or forged form vs. a
wrong identity), and a caller scripting against the dashboard benefits from
being able to tell them apart and retry accordingly (re-fetch the page for a
fresh token vs. re-authenticate entirely).

### 4. The dashboard's approve/deny buttons call a dedicated route, not the canonical one

The session cookie is issued with `Path=/dashboard` (SEC-005, literal). A
browser therefore never attaches it to `POST
/v1/firewall/approvals/{id}/decision` (path `/v1/firewall/...`, outside the
cookie's scope) — confirmed directly with a curl cookie jar during manual
verification (an attempt to reuse the same cookie against the canonical path
without explicitly supplying it fails exactly as a browser's automatic jar
would). Rather than widen the cookie's path (weakening SEC-005's literal
scope for a convenience) or accept that the dashboard's buttons simply
cannot use session auth in a real browser, `app/dashboard.py` adds its own
`POST /dashboard/approvals/{id}/decide` route, which the cookie does reach.
This is **not** a second implementation of the approval lifecycle: both
routes call the exact same `app/approvals.decide_and_resume()`. The only
differences are (1) the auth mechanism the route accepts (session+CSRF only
here; the dashboard route has no bearer-key path at all — see decision 6),
(2) the CSRF check, and (3) the response shape (an HTML fragment for HTMX to
swap in, vs. the canonical endpoint's JSON body).

### 5. `decide_and_resume()` consolidates what was previously inline in one HTTP handler

Before this phase, `POST /v1/firewall/approvals/{id}/decision`
(`app/main.py`) called `decide_approval()` and then, inline, conditionally
called `resume_approved()` itself — the sequencing ("sweep expiry, record
the decision, resume in the same request if it just became `APPROVED`")
lived in exactly one HTTP handler because there was exactly one caller.
Adding the dashboard's own decision route meant a second caller needed the
same sequencing. Rather than duplicate it, `app/approvals.py` gained
`decide_and_resume()`, factoring the existing logic out unchanged (same
`decide_approval()` call, same conditional `resume_approved()` call, same
`POL-009` "no cached policy" guard) so there is exactly one place this
sequencing can be gotten wrong, regardless of how many HTTP routes need it —
consistent with this project's standing "one function decides" preference
(ADR 0005 §4 applied the same reasoning to `combine_decisions()`). Both
`app/main.py`'s canonical endpoint and `app/dashboard.py`'s route call
`decide_and_resume()`; neither calls `decide_approval()` or
`resume_approved()` directly any more from an HTTP handler.

### 6. The dashboard decision route has no bearer-key path at all (SEC-006)

`app/dashboard.py::dashboard_decide()` only ever reads
`request.cookies.get(SESSION_COOKIE_NAME)` — it never inspects the
`Authorization` header. A service bearer key presented to this route (with
no session cookie) is therefore indistinguishable from no credential at all
and gets `401`, never a code path that could evaluate whether the key is
service- or reviewer-class. Combined with decision 1 (a session is only ever
minted for a reviewer identity), this makes SEC-006 structurally
unreachable-to-violate on this route rather than merely checked at runtime.
`tests/test_dashboard.py::TestDashboardDecide::test_service_bearer_key_has_no_route_in_here_sec006`
asserts this directly.

### 7. `GET /dashboard` accepts a reviewer bearer key too, read-only

SPEC.md §4.1's route table lists `GET /dashboard`'s auth as "reviewer
session." Nothing in SPEC.md prohibits also accepting a bearer key, and
doing so is useful for `curl`-based verification and for a reviewer who
hasn't gone through the login form. When accessed via bearer key rather
than a session cookie, the page renders **read-only**: there is no session
to bind a CSRF token to, so the approve/deny controls are omitted entirely
rather than rendered non-functional (`tests/test_dashboard.py::test_reviewer_bearer_key_gets_a_readonly_view`
asserts neither `approve-button` nor `deny-button` appears). A service
identity, by either route, still gets `403`.

### 8. No third-party CDN — HTMX and a small `json-enc` extension are vendored

SPEC.md §2.19's prohibition is literal: `app/static/vendor/` ships
`htmx.min.js` and a hand-written `htmx-json-enc.js` extension (so
approve/deny requests serialize as `application/json`, matching
`ApprovalDecisionRequest`'s Pydantic schema rather than a form-encoded
body), served same-origin from `/dashboard/static/`. `dashboard.css` is
authored locally, no icon font, no web font — the page falls back to system
UI fonts. `tests/test_dashboard.py::test_dashboard_pages_load_no_third_party_cdn_assets`
greps every rendered page for an `http(s)://` reference and asserts the two
vendored files actually resolve over the dashboard's own static mount.

### 9. `Content-Security-Policy: default-src 'self'` is enforced as a real constraint, not just claimed

`app/main.py`'s `SecurityHeadersMiddleware` sets `default-src 'self'` with
no `unsafe-inline`, applied globally (see decision 10). This session found
that the CSP claim in the code — "no inline `<script>` or `<style>` exists
anywhere in this codebase" — was true only for `<script>`/`<style>` *tags*.
`app/templates/dashboard/index.html` as left by a prior session had an
inline `onchange="this.form.submit()"` handler on the status filter
`<select>` and several inline `style="..."` attributes. Under a real,
enforced CSP with no `unsafe-inline`, inline event-handler attributes fall
under `script-src-attr` (falling back to `script-src`, then `default-src`)
and inline `style="..."` attributes fall under `style-src-attr` (same
fallback chain) — both are blocked by the browser exactly as inline
`<script>`/`<style>` tags would be. The practical effect would have been
silent breakage: the status filter's auto-submit would simply not fire in
any browser actually enforcing the header this codebase sends, and the
inline layout styling would be dropped. Fixed by removing both: the
`<select>` lost its `onchange`, and the filter form gained an explicit
"Filter" submit `<button>` instead (works with JavaScript disabled too, and
needs no CSP allowance at all); the inline `style` attributes moved to two
new CSS classes (`.rg-toolbar`, `.rg-filter-form`, `.rg-filter-label`) in
`dashboard.css`. This was caught by re-reading the template against the CSP
header's actual semantics — no test in the suite renders the dashboard in a
real browser with CSP enforcement turned on, so this class of defect is
inherently a code-reading catch, not a `pytest` one. Documented here as a
gap in what the automated suite can catch, not only as a fix.

### 10. SEC-008 headers are global middleware, not scoped to `/dashboard*`

SPEC.md §11.4 states SEC-008 without a "for the dashboard" qualifier
(contrast §2.19, which does scope its own three dashboard-specific
prohibitions explicitly). Read as written, SEC-008 is system-wide, and
PLAN.md's fail-safe-defaults principle tie-breaks toward the broader
reading wherever SPEC.md is ambiguous — global middleware also means the
headers cannot be forgotten on a future route the way a per-router opt-in
could be. Verified directly against both `/healthz` (JSON API) and
`/dashboard/login` (HTML) — same four headers on both, `Strict-Transport-Security`
added only when `APP_ENV=production`.

### 11. Which SPEC.md §10 tables this phase does and does not build

Checked against `app/db.py`: this phase adds no new tables. `transactions`,
`approvals`, `approval_decisions`, and `audit_events` already existed from
ADR 0004. `detector_findings`, `policy_hits` (as a table — the rule-id list
itself is already carried as JSON on `approvals.policy_hits`),
`idempotency_records` (as a generic, reusable mechanism — approval-decision
idempotency already exists, scoped to `approval_decisions.idempotency_key`),
`rate_limit_state`, and `encrypted_payloads` remain unbuilt. PLAN.md's own
WS-09 acceptance criteria (restart-recovery, replay rejection, exactly-once
resume, fail-closed expiry) were already satisfied by ADR 0004 and are
unaffected by this phase; PLAN.md's Phase 4 exit gate text
("`docker compose restart` during a pending approval loses no state and
resume still occurs exactly once") names exactly that behaviour and nothing
about the remaining tables. Those tables belong to WS-12 (audit/metrics) and
WS-13 (rate limiting), both explicitly out of scope for this phase per the
task's own deferral list — verified by reading PLAN.md's WS-09/12/13
sections rather than assumed.

## Found while verifying, fixed

- **Inline `onchange`/`style` attributes contradicting the CSP claim** —
  decision 9 above; the real defect this session's code-reading pass found
  and fixed.
- **A stale, inaccurate comment in `_decision_result.html`** claimed the
  fragment was "the response body `app/main.py`'s decision endpoint returns
  instead of its normal JSON body when the request carries `HX-Request:
  true`" — untrue on two counts: the canonical endpoint in `app/main.py`
  performs no content negotiation at all and always returns JSON (per
  `app/dashboard.py`'s own, correct docstring on `render_decision_fragment()`),
  and the fragment is actually returned by the dashboard's own separate
  `POST /dashboard/approvals/{id}/decide` route. Corrected to describe the
  actual route.
- **`tests/test_dashboard.py` did not exist.** Both `app/dashboard.py` and
  `app/auth.py`'s docstrings referenced it directly (e.g. "`tests/test_dashboard.py`
  asserts this directly with a service bearer key and no cookie"), but no
  such file was present in the working tree from either prior interrupted
  session — the referenced coverage was aspirational, not real. Written
  from scratch this session: 25 tests across login (valid/invalid/service-key/
  missing-field/logout), the production `Secure` cookie attribute, `GET
  /dashboard` (unauthenticated redirect, service-403, reviewer-bearer
  read-only, reviewer-session interactive, the DEP-004 mock-mode banner,
  APR-012 transformed-preview-only), the CSRF-protected decision route
  (missing/mismatched/valid token, no-session, service-bearer-key-has-no-route,
  missing Idempotency-Key, full approve and deny round trips against the
  real approval state machine, self-approval refusal through this route
  specifically), security headers (all four, plus HSTS production-only),
  and the CDN-avoidance check. One test (`test_reviewer_session_gets_the_full_interactive_queue`)
  initially asserted a CSRF token appears on any authenticated dashboard
  load — failed against an empty queue, because the token is only rendered
  inside a pending item's own approve/deny controls (nothing to bind a
  token to with no items). Not a product defect: fixed the test to create a
  pending approval first, matching every other scenario-style test in this
  suite.
- **`tests/test_session.py`** was found essentially complete on inspection
  (17 tests covering cookie round-trip, tampering, expiry, cross-secret
  rejection, CSRF determinism/mismatch, and ephemeral-secret process
  stability) — salvaged as-is, no changes needed.

## Verified, not merely asserted

- `ruff check .`: clean. `ruff format --check .`: clean, 67 files.
  `mypy app` (strict): clean, 36 source files.
- `pytest`: 335 passed, 0 skipped, 0 failed (up from the 295-passed baseline
  at the start of this phase — 40 new tests: 25 in `tests/test_dashboard.py`,
  15 already present in `tests/test_session.py`).
- Coverage: 90% line / unchanged from Phase 3's gate; `app/dashboard.py`
  itself at 98% line coverage, `app/session.py` at 97%.
- `python scripts/validate_contracts.py`: all checks pass, including the
  frozen 54-case corpus (untouched by this phase).
- A live `uvicorn` process (mock mode, real `FIREWALL_API_KEYS`/
  `FIREWALL_REVIEWER_KEYS` configured) was driven end to end with real
  `curl` requests, not just the test client: a service key creates a
  `NEED_APPROVAL` transaction; a service key is refused a dashboard session
  (`403`, SEC-006); a reviewer key is exchanged for a session cookie
  carrying `HttpOnly`, `Path=/dashboard`, `SameSite=strict`, `Max-Age=3600`,
  and correctly *no* `Secure` attribute in development; `GET /dashboard`
  with that cookie renders the pending item and a CSRF token; a decision
  request with no CSRF token gets `403 CSRF_TOKEN_INVALID`; the same request
  with a wrong token also gets `403`; the same request with the real token
  gets `200`, the approval transitions to `COMPLETED`, and the original
  caller's poll of `/v1/firewall/requests/{id}` returns the actual (mock)
  completion — the full loop a real reviewer would drive in a browser.
  Exact commands and captured output are in `README.md`'s new "Reviewer
  dashboard" section.

## Consequences

- SPEC.md §4.6's two named auth routes for the canonical decision endpoint
  both now exist and are tested; SEC-005/006/007/008 are all implemented
  and directly asserted, not merely documented as intended.
- The reviewer dashboard is genuinely driveable end to end — login, queue,
  approve, deny, decision history — with vendored-only assets and no
  content ever rendered that bypasses the existing `preview_content`
  transformation.
- Still open, unaffected by this phase, and not claimed otherwise: WS-12
  (structured audit logging beyond the existing hash-chained `audit_events`
  rows, Prometheus metrics, `GET /metrics`), WS-13 (rate limiting — the
  `RATE_LIMIT_*` settings exist and are validated at startup but nothing
  yet enforces them), the Ollama compose profile and preflight check
  (Phase 5), and `encrypted_payloads` (`CONTENT_RETENTION=encrypted` has no
  storage backend yet).
