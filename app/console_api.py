"""`/console` JSON API and static SPA mount. See
docs/adr/0014-console-spa-frontend.md for every judgment call this module
makes.

Like `app/dashboard.py` — whose docstring already says the same of itself —
**this module owns no business logic of its own.** Every route below is a
JSON-shaped call to a function `app/dashboard.py` already calls for the HTMX
UI: session/CSRF primitives from `app/session.py`, identity resolution from
`app/auth.py`, and every read or write against the approval queue through
`app/approvals.py`'s existing functions. Nothing here re-derives an approval
state, a verdict, or a metric.

Two deliberate separations from the Phase 4 HTMX dashboard (ADR 0006), which
this module does not touch in any way:

1. **A different cookie.** `rg_console_session` at `Path=/console/api`, not
   `rg_session` at `Path=/dashboard`. Distinct name *and* distinct path, so
   the two UIs' sessions can never collide, and a browser never attaches one
   UI's cookie to the other UI's requests. The cookie value itself is minted
   and verified by the exact same `app/session.py` primitives (SEC-005), and
   a session is still only ever issued to a REVIEWER identity (SEC-006).

2. **A different error shape.** `{"error": <message>, "code": <ErrorCode>}`
   with the `FirewallError`'s own `.status`, produced by an explicit
   `try/except` per route. `app/main.py`'s `register_exception_handlers()`
   installs a `FirewallError` handler that produces the richer
   `{"error": {code, type, message, transaction_id}}` envelope ERR-001
   specifies for `/v1/firewall/*`; that envelope is a *transaction*-shaped
   contract (it carries a `transaction_id`), and a console session/CSRF
   failure is not a transaction. Rather than mint a meaningless
   `transaction_id` per UI click, these routes catch their own errors and
   return the flatter shape the SPA's `fetch` wrapper reads. The `code`
   value is always a real `ErrorCode` member, never an invented string, so
   the two shapes never disagree about *what* went wrong — only about how
   much envelope surrounds it.

The static SPA mount is deliberately conditional: a fresh checkout that has
never run `npm run build` (and every Python-only `pytest` run, which never
runs npm at all) has no `web/out` directory, and the Python application must
still start and serve `/dashboard`, `/v1/firewall/*` and `/console/api/*`
normally. A missing build logs one clear WARNING line and skips the mount —
the same graceful-degradation-with-a-visible-signal posture
`app/main.py`'s mock-mode banner and POL-009's degraded policy mode already
take, rather than a crash at import time.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import CollectorRegistry
from pydantic import ValidationError
from starlette.staticfiles import StaticFiles

from app.approvals import (
    APPROVAL_STATES,
    count_by_state,
    decide_and_resume,
    list_approvals,
    list_recent_decisions,
    sweep_expired,
)
from app.auth import Identity, IdentityClass, resolve_identity
from app.errors import ErrorCode, FirewallError
from app.schemas import ApprovalDecisionRequest
from app.session import (
    SessionData,
    create_session_cookie,
    csrf_token_for_session,
    verify_csrf_token,
    verify_session_cookie,
)

logger = logging.getLogger("realguard")

CONSOLE_SESSION_COOKIE_NAME = "rg_console_session"
"""Deliberately *not* `app/session.py`'s `SESSION_COOKIE_NAME` (`rg_session`).
ADR 0014 §2: a distinct name at a distinct path, so `/console` and
`/dashboard` sessions never interact. The signing/verification primitives
are shared; only the cookie's identity on the wire differs."""

CONSOLE_COOKIE_PATH = "/console/api"

_PACKAGE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_DIR.parent

# Two locations, in priority order:
#   1. `app/console_static/` — where the Dockerfile's `web-builder` stage
#      copies `/web/out` (ADR 0014 §3), and where `pyproject.toml`'s
#      package-data declaration picks it up for an installed wheel.
#   2. `web/out/` — a local `npm run build` in a source checkout, so a
#      developer iterating on the frontend does not have to copy files
#      into `app/` to see them served.
_CONSOLE_STATIC_CANDIDATES: tuple[Path, ...] = (
    _PACKAGE_DIR / "console_static",
    _REPO_ROOT / "web" / "out",
)


def find_console_static_dir() -> Path | None:
    """The built SPA's directory, or `None` if no build exists yet.

    Requires an actual `index.html`, not merely a directory — an empty or
    half-deleted `web/out` is treated exactly like no build at all, so the
    mount either serves a real application or does not exist.
    """
    for candidate in _CONSOLE_STATIC_CANDIDATES:
        if (candidate / "index.html").is_file():
            return candidate
    return None


def _rfc3339(dt: datetime) -> str:
    """API-005, mirroring `app/main.py`'s and `app/dashboard.py`'s helper of
    the same name — every datetime reaching here is naive-but-UTC by
    `app/approvals.py`'s `_now()` convention."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _error(message: str, code: ErrorCode, status: int) -> JSONResponse:
    """ADR 0014 §2's error shape, in one place so no route can drift from
    it. `code` is always a real `app/errors.ErrorCode` member."""
    return JSONResponse(status_code=status, content={"error": message, "code": code.value})


def _firewall_error_response(exc: FirewallError) -> JSONResponse:
    """A `FirewallError` raised by `app/approvals.py` carries its own status
    and code — both are used verbatim, so a console client sees exactly the
    same failure classification a `/v1/firewall/*` client would (APR-008's
    409 `APPROVAL_EXPIRED`, APR-009's 403 `SELF_APPROVAL_FORBIDDEN`,
    APR-010's 409 `IDEMPOTENCY_CONFLICT`, ...), only in a flatter envelope."""
    return _error(exc.message, exc.code, exc.status)


def _cookie_kwargs(settings: Any, *, max_age: int) -> dict[str, Any]:
    """SEC-005's cookie attributes, with `/console/api` in place of
    `app/dashboard.py`'s `/dashboard` path."""
    return {
        "path": CONSOLE_COOKIE_PATH,
        "httponly": True,
        "secure": settings.APP_ENV.value == "production",
        "samesite": "strict",
        "max_age": max_age,
    }


def _session_payload(session: SessionData, settings: Any) -> dict[str, Any]:
    """The body `POST /console/api/login` and `GET /console/api/session` both
    return. Handing the CSRF token to the client that just authenticated over
    this same channel does not weaken SEC-007: the synchronizer-token
    property is that a *cross-site* page cannot compute the token (it has
    neither the `HttpOnly` cookie's `session_id` nor `SESSION_SECRET`), which
    is unaffected by where the legitimate same-origin client keeps it."""
    return {
        "identity_id": session.identity_id,
        "csrf_token": csrf_token_for_session(session.session_id, settings),
        "expires_at": _rfc3339(session.expires_at.replace(tzinfo=None)),
    }


def _counter_samples(registry: CollectorRegistry, sample_name: str) -> list[tuple[Any, float]]:
    """Every `(labels, value)` pair the live registry currently holds for one
    counter's `_total` sample.

    ADR 0014 §2: `/console/api/stats` performs **no new measurement**. This
    reads the same `CollectorRegistry` instance `/metrics` serves, so
    `/console` and `/metrics` cannot disagree with each other. Matching on
    the *sample* name rather than the metric-family name is deliberate:
    `prometheus_client` strips the `_total` suffix from a `Counter`'s family
    name (`realguard_decisions_total` becomes the family `realguard_decisions`
    with samples `..._total` and `..._created`), so family-name matching would
    silently pick up the `_created` timestamp sample too.
    """
    out: list[tuple[Any, float]] = []
    for metric in registry.collect():
        for sample in metric.samples:
            if sample.name == sample_name:
                out.append((sample.labels, float(sample.value)))
    return out


def _series(
    registry: CollectorRegistry, sample_name: str, label: str
) -> list[dict[str, Any]]:
    """One counter reshaped as a chart-ready `[{name, value}, ...]` list,
    highest first, dropping zero-valued series (a `Counter.labels(...)` that
    was created but never incremented would otherwise render as an empty bar).
    """
    rows = [
        {"name": labels.get(label, "unknown"), "value": value}
        for labels, value in _counter_samples(registry, sample_name)
        if value > 0
    ]
    rows.sort(key=lambda r: (-float(r["value"]), str(r["name"])))
    return rows


def register_console_api_routes(app: FastAPI) -> None:
    """ADR 0014 §2. Registered from `app/main.py`'s `create_app()` alongside
    `register_dashboard_routes(app)`.

    Route registration happens *before* the `StaticFiles` mount at the bottom
    of this function, and that ordering is load-bearing: Starlette matches
    routes in registration order, and a `Mount("/console", ...)` added first
    would swallow every `/console/api/*` path and answer it with a static-file
    404 instead of reaching the handlers below.
    """

    @app.post("/console/api/login")
    async def console_login(request: Request) -> JSONResponse:
        """SEC-005/SEC-006, mirroring `dashboard_login_submit()` exactly: a
        reviewer key is exchanged for a signed session; a service key (or any
        unrecognized key) never gets one. This is the only place a console
        session is ever minted, so — exactly as ADR 0006 reasoned for the
        HTMX dashboard — decoding a cookie later never has to re-derive an
        identity class."""
        state = app.state.rg
        try:
            body = await request.json()
        except ValueError:
            return _error("A JSON body is required.", ErrorCode.INVALID_REQUEST, 400)

        reviewer_key = body.get("reviewer_key") if isinstance(body, dict) else None
        if not isinstance(reviewer_key, str) or not reviewer_key:
            return _error("A reviewer key is required.", ErrorCode.INVALID_REQUEST, 400)

        try:
            identity = resolve_identity(f"Bearer {reviewer_key}", state.settings)
        except FirewallError as exc:
            return _error("Invalid reviewer key.", exc.code, exc.status)

        if identity.identity_class != IdentityClass.REVIEWER:
            # SEC-006: "A service-class identity MUST NOT be able to decide
            # an approval by any route." Refusing it a console session here
            # is the `/console` leg of that, exactly as `app/dashboard.py`
            # refuses it the HTMX dashboard's session.
            return _error(
                "Service keys cannot sign in to the reviewer console (SEC-006).",
                ErrorCode.INSUFFICIENT_PRIVILEGE,
                403,
            )

        cookie_value, session = create_session_cookie(identity.identity_id, state.settings)
        response = JSONResponse(
            status_code=200, content=_session_payload(session, state.settings)
        )
        response.set_cookie(
            CONSOLE_SESSION_COOKIE_NAME,
            cookie_value,
            **_cookie_kwargs(state.settings, max_age=state.settings.SESSION_TTL_SECONDS),
        )
        return response

    @app.post("/console/api/logout")
    async def console_logout(request: Request) -> JSONResponse:
        state = app.state.rg
        response = JSONResponse(status_code=200, content={"ok": True})
        response.delete_cookie(
            CONSOLE_SESSION_COOKIE_NAME,
            path=CONSOLE_COOKIE_PATH,
            httponly=True,
            secure=state.settings.APP_ENV.value == "production",
            samesite="strict",
        )
        return response

    def _require_session(request: Request) -> SessionData | None:
        state = app.state.rg
        return verify_session_cookie(
            request.cookies.get(CONSOLE_SESSION_COOKIE_NAME), state.settings
        )

    @app.get("/console/api/session")
    async def console_session(request: Request) -> JSONResponse:
        """Session restore / CSRF refresh on SPA page load. 401 when the
        cookie is absent, tampered or expired — `verify_session_cookie()`
        treats all three identically (SEC-005), and so does this."""
        state = app.state.rg
        session = _require_session(request)
        if session is None:
            return _error("Not authenticated.", ErrorCode.INVALID_AUTHENTICATION, 401)
        return JSONResponse(status_code=200, content=_session_payload(session, state.settings))

    @app.get("/console/api/approvals")
    async def console_approvals(request: Request) -> JSONResponse:
        """The same two calls `dashboard_index()` makes — `sweep_expired()`
        then `list_approvals()` — with `preview_content` returned as real
        JSON rather than the pre-stringified blob the Jinja template needed
        for its `<pre>`. APR-012 still holds: this is the already-transformed
        preview `app/approvals.py` stored at creation time, never a second,
        untransformed query path.

        `status` is read straight off the query string (repeatable) rather
        than declared as a typed list parameter, so the valid values are
        whatever `app/approvals.list_approvals()` accepts —
        `app/approvals.APPROVAL_STATES` — with no second, drifting copy of
        that vocabulary declared here.
        """
        state = app.state.rg
        session = _require_session(request)
        if session is None:
            return _error("Not authenticated.", ErrorCode.INVALID_AUTHENTICATION, 401)

        requested = [s.upper() for s in request.query_params.getlist("status") if s]
        # Reject if *any* value is unknown, rather than silently dropping the
        # bad ones and answering with a narrower filter than was asked for —
        # a caller who mistypes one state in a list would otherwise get a
        # plausible-looking partial result and no indication of the typo.
        unknown = [s for s in requested if s not in APPROVAL_STATES]
        if unknown:
            return _error(
                f"Unknown `status` value(s) {', '.join(sorted(set(unknown)))} — "
                f"must be one of {', '.join(APPROVAL_STATES)}.",
                ErrorCode.INVALID_REQUEST,
                400,
            )
        statuses: list[str] | None = requested or None

        try:
            limit = max(1, min(int(request.query_params.get("limit", "100")), 200))
        except ValueError:
            return _error("`limit` must be an integer.", ErrorCode.INVALID_REQUEST, 400)

        sweep_expired(state.db_engine, metrics=state.metrics)
        rows, next_cursor = list_approvals(
            state.db_engine,
            statuses=statuses,
            limit=limit,
            cursor=request.query_params.get("cursor"),
        )
        items = [
            {
                "approval_id": r.id,
                "transaction_id": r.transaction_id,
                "status": r.state,
                "risk_level": r.risk_level,
                "reason_codes": r.reason_codes,
                "policy_hits": r.policy_hits,
                "preview": r.preview_content,
                "created_at": _rfc3339(r.created_at),
                "expires_at": _rfc3339(r.expires_at),
            }
            for r in rows
        ]
        return JSONResponse(
            status_code=200, content={"items": items, "next_cursor": next_cursor}
        )

    @app.get("/console/api/decisions")
    async def console_decisions(request: Request) -> JSONResponse:
        """`list_recent_decisions()` — the same rows the HTMX dashboard's
        history panel renders."""
        state = app.state.rg
        session = _require_session(request)
        if session is None:
            return _error("Not authenticated.", ErrorCode.INVALID_AUTHENTICATION, 401)

        try:
            limit = max(1, min(int(request.query_params.get("limit", "50")), 200))
        except ValueError:
            return _error("`limit` must be an integer.", ErrorCode.INVALID_REQUEST, 400)

        items = [
            {
                "approval_id": d.approval_id,
                "decision": d.decision,
                "reviewer_id": d.reviewer_id,
                "note": d.note,
                "from_state": d.from_state,
                "to_state": d.to_state,
                "created_at": _rfc3339(d.created_at),
            }
            for d in list_recent_decisions(state.db_engine, limit=limit)
        ]
        return JSONResponse(status_code=200, content={"items": items})

    @app.post("/console/api/approvals/{approval_id}/decide")
    async def console_decide(approval_id: str, request: Request) -> JSONResponse:
        """The exact same `app/approvals.decide_and_resume()` call
        `dashboard_decide()` and the canonical
        `POST /v1/firewall/approvals/{id}/decision` both make — session
        checked (SEC-005), CSRF checked (SEC-007), `Idempotency-Key` required
        (API-007) — returning JSON instead of an HTML fragment, because there
        is no HTMX here to swap one into.

        SEC-006: this handler never accepts a bearer key at all, only a
        console session, and a console session is only ever minted for a
        reviewer identity (`console_login` above). The body is validated
        explicitly rather than through a FastAPI `body:` parameter so that a
        malformed body returns *this* module's flat error shape rather than
        `app/main.py`'s transaction-shaped `RequestValidationError` envelope.
        """
        state = app.state.rg
        session = _require_session(request)
        if session is None:
            return _error(
                "Not authenticated — sign in again at /console/login.",
                ErrorCode.INVALID_AUTHENTICATION,
                401,
            )

        if not verify_csrf_token(
            request.headers.get("X-CSRF-Token"), session.session_id, state.settings
        ):
            return _error(
                "Missing or invalid CSRF token (SEC-007).", ErrorCode.CSRF_TOKEN_INVALID, 403
            )

        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            return _error(
                "The Idempotency-Key header is required for this endpoint (API-007).",
                ErrorCode.INVALID_REQUEST,
                400,
            )

        try:
            raw_body = await request.json()
        except ValueError:
            return _error("A JSON body is required.", ErrorCode.INVALID_REQUEST, 400)
        try:
            body = ApprovalDecisionRequest.model_validate(raw_body)
        except ValidationError:
            # ERR-022: structural only — the field name and the permitted
            # values, never the submitted content.
            return _error(
                "`decision` must be APPROVE or DENY.", ErrorCode.INVALID_REQUEST, 400
            )

        identity = Identity(IdentityClass.REVIEWER, session.identity_id)
        try:
            result = await decide_and_resume(
                state.db_engine,
                approval_id,
                decision=body.decision,
                note=body.note,
                reviewer_identity=identity,
                idempotency_key=idempotency_key,
                correlation_id=getattr(request.state, "correlation_id", approval_id),
                provider=state.provider,
                policy=state.policy,
                salt=state.settings.effective_hash_salt(),
                detector_timeout_ms=state.settings.DETECTOR_TIMEOUT_MS,
                retain_response_content=state.settings.CONTENT_RETENTION.value
                in ("full", "encrypted"),
                metrics=state.metrics,
            )
        except FirewallError as exc:
            return _firewall_error_response(exc)

        return JSONResponse(
            status_code=200,
            content={
                "approval_id": approval_id,
                "decision": result.decision_row.decision,
                "status": result.final_approval.state,
                "outcome": result.outcome.value,
                "decided_at": _rfc3339(result.decision_row.created_at),
            },
        )

    @app.get("/console/api/stats")
    async def console_stats(request: Request) -> JSONResponse:
        """ADR 0014 §2: **no new measurement.** Queue depth by state runs the
        same `count_by_state()` query the `realguard_approval_queue_depth`
        gauge already runs at scrape time; every other number is read
        straight out of the same `CollectorRegistry` instance `/metrics`
        serves. If a number here looks wrong, it was already wrong in
        `/metrics`.

        `mock_mode` is DEP-004's visible mock-mode marker for this UI, the
        `/console` counterpart of the HTMX dashboard's own banner.
        """
        state = app.state.rg
        session = _require_session(request)
        if session is None:
            return _error("Not authenticated.", ErrorCode.INVALID_AUTHENTICATION, 401)

        registry: CollectorRegistry = state.metrics.registry
        approvals_by_state = {
            name: count_by_state(state.db_engine, name) for name in APPROVAL_STATES
        }
        decisions = _counter_samples(registry, "realguard_decisions_total")
        http_requests = _counter_samples(registry, "realguard_http_requests_total")

        return JSONResponse(
            status_code=200,
            content={
                "mock_mode": bool(state.settings.mock_mode),
                "policy_version": (
                    state.policy.policy_version if state.policy is not None else None
                ),
                "approvals_by_state": approvals_by_state,
                "totals": {
                    "approvals": sum(approvals_by_state.values()),
                    "pending": approvals_by_state["PENDING"],
                    "decisions": sum(value for _labels, value in decisions),
                    "http_requests": sum(value for _labels, value in http_requests),
                },
                "decisions_by_verdict": _series(
                    registry, "realguard_decisions_total", "verdict"
                ),
                "risk_levels": _series(registry, "realguard_risk_level_total", "level"),
                "policy_hits": _series(registry, "realguard_policy_hits_total", "rule_id"),
                "reason_codes": _series(
                    registry, "realguard_reason_codes_total", "reason_code"
                ),
            },
        )

    # --- static SPA mount (registered last; see this function's docstring) ---
    static_dir = find_console_static_dir()
    if static_dir is None:
        logger.warning(
            "console SPA not mounted: no built frontend found (looked for index.html in %s). "
            "/console/api/* is live; run `npm ci && npm run build` in web/ (or build the "
            "Docker image, whose web-builder stage does it) to serve the UI at /console/. "
            "The /dashboard HTMX UI is unaffected and needs no Node toolchain.",
            " and ".join(str(p) for p in _CONSOLE_STATIC_CANDIDATES),
        )
        return

    app.mount(
        "/console",
        StaticFiles(directory=str(static_dir), html=True),
        name="console-spa",
    )
