"""Reviewer HTML dashboard. SPEC.md §2.19, §11.3 (SEC-005, SEC-006, SEC-007);
PLAN.md WS-11. See docs/adr/0006-reviewer-dashboard-session-auth-and-csrf.md
for every judgment call this module makes.

Scope, per WS-11's own risk mitigation ("scope creep into a full admin
console... the four screens above are the entire deliverable"): a login
screen, a pending-approvals queue with a status filter and a sanitised
preview per item (APR-012 — this reuses `app/approvals.list_approvals()`'s
already-transformed `preview_content`, never a second, untransformed query
path), inline approve/deny (a required note for deny) driven by the
vendored HTMX build against this module's own CSRF-protected
`POST /dashboard/approvals/{id}/decide` route (below) — a deliberately
*separate* route from the canonical `POST
/v1/firewall/approvals/{id}/decision`, not a second implementation of the
approval lifecycle: both call the exact same `app/approvals.decide_and_resume()`.
See docs/adr/0006 for why the session cookie's `Path=/dashboard` scope makes
a dedicated route necessary rather than optional — and a decision history
panel.

This module owns no business logic of its own: session/CSRF primitives live
in `app/session.py`, identity resolution in `app/auth.py`, and every read or
write against the approval queue goes through `app/approvals.py`'s existing
functions.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.staticfiles import StaticFiles

from app.approvals import decide_and_resume, list_approvals, list_recent_decisions, sweep_expired
from app.auth import Identity, IdentityClass, resolve_identity
from app.errors import FirewallError
from app.ids import new_id
from app.schemas import ApprovalDecisionRequest
from app.session import (
    SESSION_COOKIE_NAME,
    create_session_cookie,
    csrf_token_for_session,
    verify_csrf_token,
    verify_session_cookie,
)

_TEMPLATES_DIR = Path(__file__).parent / "templates" / "dashboard"
_STATIC_DIR = Path(__file__).parent / "static"

_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def _render(template_name: str, **context: Any) -> str:
    return str(_jinja_env.get_template(template_name).render(**context))


def _rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cookie_kwargs(settings: Any, *, max_age: int) -> dict[str, Any]:
    """SEC-005: `HttpOnly`; `Secure` when `APP_ENV=production`; `SameSite=Strict`;
    `Path=/dashboard`; expiry `SESSION_TTL_SECONDS`."""
    return {
        "path": "/dashboard",
        "httponly": True,
        "secure": settings.APP_ENV.value == "production",
        "samesite": "strict",
        "max_age": max_age,
    }


def render_decision_fragment(
    *,
    approval_id: str,
    decision: str | None = None,
    status: str | None = None,
    decided_at: str | None = None,
    error: str | None = None,
) -> str:
    """Renders the HTML swap-target fragment `dashboard_decide()` (below)
    returns for every response — this route is used only by the dashboard's
    own vendored htmx, so unlike the canonical JSON decision endpoint in
    `app/main.py` (which is unaffected by this module and always returns
    JSON), there is no content-negotiation here: this route's body is always
    the fragment, swapped in place via `hx-swap="outerHTML"` so the queue row
    updates without a full page reload (WS-11's acceptance criterion)."""
    return _render(
        "_decision_result.html",
        approval_id=approval_id,
        decision=decision,
        status=status,
        decided_at=decided_at,
        error=error,
    )


def register_dashboard_routes(app: FastAPI) -> None:
    app.mount("/dashboard/static", StaticFiles(directory=str(_STATIC_DIR)), name="dashboard-static")

    @app.get("/dashboard/login")
    async def dashboard_login_form(request: Request) -> HTMLResponse:
        state = app.state.rg
        html = _render("login.html", mock_mode=state.settings.mock_mode, error=None)
        return HTMLResponse(html)

    @app.post("/dashboard/login")
    async def dashboard_login_submit(request: Request) -> Any:
        """SEC-005: exchanges a reviewer key for a signed session cookie.
        SEC-006: a service key (or any unrecognized key) is rejected here,
        the only place a session is ever minted — decoding a cookie later
        never has to re-derive identity class."""
        state = app.state.rg
        form = await request.form()
        reviewer_key = form.get("reviewer_key")
        if not isinstance(reviewer_key, str) or not reviewer_key:
            html = _render(
                "login.html",
                mock_mode=state.settings.mock_mode,
                error="A reviewer key is required.",
            )
            return HTMLResponse(html, status_code=400)

        try:
            identity = resolve_identity(f"Bearer {reviewer_key}", state.settings)
        except FirewallError:
            html = _render(
                "login.html", mock_mode=state.settings.mock_mode, error="Invalid reviewer key."
            )
            return HTMLResponse(html, status_code=401)

        if identity.identity_class != IdentityClass.REVIEWER:
            # SEC-006: "A service-class identity MUST NOT be able to decide
            # an approval by any route — bearer, cookie or dashboard form."
            # Refusing it a session here is the dashboard-form leg of that.
            html = _render(
                "login.html",
                mock_mode=state.settings.mock_mode,
                error="Service keys cannot sign in to the reviewer dashboard (SEC-006).",
            )
            return HTMLResponse(html, status_code=403)

        cookie_value, _session = create_session_cookie(identity.identity_id, state.settings)
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            cookie_value,
            **_cookie_kwargs(state.settings, max_age=state.settings.SESSION_TTL_SECONDS),
        )
        return response

    @app.post("/dashboard/logout")
    async def dashboard_logout(request: Request) -> Any:
        state = app.state.rg
        response = RedirectResponse(url="/dashboard/login", status_code=303)
        response.delete_cookie(
            SESSION_COOKIE_NAME,
            path="/dashboard",
            httponly=True,
            secure=state.settings.APP_ENV.value == "production",
            samesite="strict",
        )
        return response

    @app.get("/dashboard")
    async def dashboard_index(request: Request, status: str = "PENDING") -> Any:
        """SPEC.md §4.1: `GET /dashboard` requires a reviewer session.
        Also accepts a reviewer bearer key directly (consistency with the
        rest of the API, and useful for `curl`-based verification) — in
        that mode the page renders read-only, since there is no session to
        bind a CSRF token to (see docs/adr/0006). A service identity, by
        either route, gets 403. No credential at all redirects to the login
        screen rather than a bare 401 — this is a browser-facing page."""
        state = app.state.rg
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        session = verify_session_cookie(session_cookie, state.settings)

        readonly: bool
        csrf_token: str | None = None
        if session is not None:
            readonly = False
            csrf_token = csrf_token_for_session(session.session_id, state.settings)
        else:
            auth_header = request.headers.get("Authorization")
            if auth_header is None:
                return RedirectResponse(url="/dashboard/login", status_code=303)
            try:
                identity = resolve_identity(auth_header, state.settings)
            except FirewallError as e:
                return HTMLResponse(
                    _render(
                        "login.html", mock_mode=state.settings.mock_mode, error="Not authenticated."
                    ),
                    status_code=e.status,
                )
            if identity.identity_class != IdentityClass.REVIEWER:
                return HTMLResponse(
                    _render(
                        "login.html",
                        mock_mode=state.settings.mock_mode,
                        error="This endpoint requires a reviewer-class identity.",
                    ),
                    status_code=403,
                )
            readonly = True  # bearer-key access: view-only, no session to bind CSRF to

        sweep_expired(state.db_engine)
        status_filter = status.upper()
        rows, _next_cursor = list_approvals(
            state.db_engine, statuses=[status_filter], limit=200, cursor=None
        )
        items = [
            {
                "approval_id": r.id,
                "transaction_id": r.transaction_id,
                "status": r.state,
                "risk_level": r.risk_level,
                "reason_codes": r.reason_codes,
                "policy_hits": r.policy_hits,
                # APR-012: `preview_content` is already transformed at
                # creation time (app/main.py) — never the raw request.
                "preview_json": json.dumps(r.preview_content, indent=2, sort_keys=True),
                "created_at": _rfc3339(r.created_at),
                "expires_at": _rfc3339(r.expires_at),
                "dashboard_idempotency_key": new_id("idm"),
            }
            for r in rows
        ]
        decisions = [
            {
                "approval_id": d.approval_id,
                "decision": d.decision,
                "reviewer_id": d.reviewer_id,
                "note": d.note,
                "created_at": _rfc3339(d.created_at),
            }
            for d in list_recent_decisions(state.db_engine, limit=20)
        ]
        html = _render(
            "index.html",
            mock_mode=state.settings.mock_mode,
            readonly=readonly,
            csrf_token=csrf_token,
            status_filter=status_filter,
            items=items,
            recent_decisions=decisions,
        )
        return HTMLResponse(html)

    @app.post("/dashboard/approvals/{approval_id}/decide")
    async def dashboard_decide(
        approval_id: str, request: Request, body: ApprovalDecisionRequest
    ) -> HTMLResponse:
        """The dashboard's own CSRF-protected decision route (ADR 0006).

        Not a second implementation of the approval lifecycle: this calls
        the exact same `app/approvals.decide_and_resume()` the canonical
        `POST /v1/firewall/approvals/{id}/decision` uses (app/main.py) —
        the only things this route does differently are (1) authenticate
        via the SEC-005 session cookie rather than a bearer header, which
        works here specifically because the cookie's `Path=/dashboard`
        scope covers this URL (it does not cover `/v1/firewall/...` — see
        the module docstring and docs/adr/0006), (2) enforce SEC-007's CSRF
        check, and (3) render a small HTML fragment for HTMX to swap in,
        instead of the canonical endpoint's JSON body.

        SEC-006: a service identity has no route in here at all — this
        handler never accepts a bearer key, only a session, and a session
        is only ever minted for a reviewer identity (`dashboard_login_submit`
        above). `tests/test_dashboard.py` asserts this directly with a
        service bearer key and no cookie, and separately with a
        hand-crafted request that has no valid session.
        """
        state = app.state.rg
        session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
        session = verify_session_cookie(session_cookie, state.settings)
        if session is None:
            html = render_decision_fragment(
                approval_id=approval_id,
                error="Not authenticated — sign in again at /dashboard/login.",
            )
            return HTMLResponse(html, status_code=401)

        csrf_header = request.headers.get("X-CSRF-Token")
        if not verify_csrf_token(csrf_header, session.session_id, state.settings):
            html = render_decision_fragment(
                approval_id=approval_id, error="Missing or invalid CSRF token (SEC-007)."
            )
            return HTMLResponse(html, status_code=403)

        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            html = render_decision_fragment(
                approval_id=approval_id, error="Missing Idempotency-Key header."
            )
            return HTMLResponse(html, status_code=400)

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
            )
        except FirewallError as e:
            html = render_decision_fragment(approval_id=approval_id, error=e.message)
            return HTMLResponse(html, status_code=e.status)

        html = render_decision_fragment(
            approval_id=approval_id,
            decision=result.decision_row.decision,
            status=result.final_approval.state,
            decided_at=_rfc3339(result.decision_row.created_at),
        )
        return HTMLResponse(html, status_code=200)
