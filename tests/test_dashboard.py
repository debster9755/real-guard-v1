"""End-to-end reviewer-dashboard tests, exercised over real HTTP through the
TestClient — SPEC.md §2.19, §11.3 (SEC-005, SEC-006, SEC-007), §11.4
(SEC-008); PLAN.md WS-10/WS-11; docs/adr/0006-reviewer-dashboard-session-auth-and-csrf.md.

tests/test_session.py covers the signing/verification primitives in
isolation; this module covers the HTTP surface app/dashboard.py builds on
top of them: the login form, the cookie it sets, CSRF enforcement on the
decision route, the rendered queue page, and security headers on every
response.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

SERVICE_KEY = "svc_test_key_0123456789abcdef0123456789"
REVIEWER_KEY = "rev_test_key_0123456789abcdef0123456789"


@pytest.fixture
def dash_client(client_factory: Callable[..., TestClient]) -> TestClient:
    return client_factory(
        FIREWALL_API_KEYS=SERVICE_KEY,
        FIREWALL_REVIEWER_KEYS=REVIEWER_KEY,
    )


def _login(client: TestClient, key: str) -> object:
    return client.post("/dashboard/login", data={"reviewer_key": key}, follow_redirects=False)


def _set_cookie_header(response: object) -> str:
    """The raw `Set-Cookie` header value for the session cookie — httpx
    exposes repeated response headers via `.get_list`, not `.headers[...]`,
    which would silently return only the first one if there were several."""
    values = response.headers.get_list("set-cookie")  # type: ignore[attr-defined]
    (session_header,) = [v for v in values if v.startswith("rg_session=")]
    return session_header


def _extract_csrf_token(html: str) -> str:
    match = re.search(r'X-CSRF-Token":\s*"([^"]+)"', html)
    assert match is not None, "no CSRF token found in rendered dashboard HTML"
    return match.group(1)


# ---------------------------------------------------------------------------
# Login flow (SEC-005, SEC-006)
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_form_renders(self, dash_client: TestClient) -> None:
        response = dash_client.get("/dashboard/login")
        assert response.status_code == 200
        assert "reviewer_key" in response.text

    def test_valid_reviewer_key_issues_a_session_cookie(self, dash_client: TestClient) -> None:
        response = _login(dash_client, REVIEWER_KEY)
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard"
        cookie = _set_cookie_header(response)
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie
        assert "Path=/dashboard" in cookie
        # SEC-005: Secure only in production — this client runs in
        # development (client_factory's default APP_ENV).
        assert "Secure" not in cookie
        assert "Max-Age=3600" in cookie  # default SESSION_TTL_SECONDS

    def test_invalid_reviewer_key_is_rejected(self, dash_client: TestClient) -> None:
        response = _login(dash_client, "not-a-real-key")
        assert response.status_code == 401
        assert "set-cookie" not in {k.lower() for k in response.headers}
        assert "Invalid reviewer key" in response.text

    def test_service_key_cannot_sign_in_sec006(self, dash_client: TestClient) -> None:
        """SEC-006: a service-class identity must not gain a session by any
        route, including the dashboard login form."""
        response = _login(dash_client, SERVICE_KEY)
        assert response.status_code == 403
        assert "set-cookie" not in {k.lower() for k in response.headers}
        assert "Service keys cannot sign in" in response.text

    def test_missing_reviewer_key_field_is_rejected(self, dash_client: TestClient) -> None:
        response = dash_client.post("/dashboard/login", data={}, follow_redirects=False)
        assert response.status_code == 400

    def test_logout_clears_the_cookie(self, dash_client: TestClient) -> None:
        login = _login(dash_client, REVIEWER_KEY)
        assert dash_client.cookies.get("rg_session")
        response = dash_client.post("/dashboard/logout", follow_redirects=False)
        assert response.status_code == 303
        cookie = _set_cookie_header(response)
        assert 'rg_session=""' in cookie or "rg_session=;" in cookie or "Max-Age=0" in cookie
        assert login  # keep the earlier response referenced


class TestSessionCookieProductionAttributes:
    def test_secure_attribute_is_set_when_app_env_is_production(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        client = client_factory(
            APP_ENV="production",
            FIREWALL_API_KEYS=SERVICE_KEY,
            FIREWALL_REVIEWER_KEYS=REVIEWER_KEY,
            SESSION_SECRET="a-production-session-secret-of-at-least-32-bytes",
            HASH_SALT="a-production-hash-salt-of-16b+",
            METRICS_REQUIRE_AUTH="true",
            ALLOW_MOCK_IN_PRODUCTION="true",
        )
        response = _login(client, REVIEWER_KEY)
        assert response.status_code == 303
        cookie = _set_cookie_header(response)
        assert "Secure" in cookie


# ---------------------------------------------------------------------------
# GET /dashboard (SEC-005, SEC-006, APR-012)
# ---------------------------------------------------------------------------


class TestDashboardIndex:
    def test_unauthenticated_request_redirects_to_login(self, dash_client: TestClient) -> None:
        response = dash_client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/dashboard/login"

    def test_service_identity_via_bearer_is_rejected(self, dash_client: TestClient) -> None:
        response = dash_client.get("/dashboard", headers={"Authorization": f"Bearer {SERVICE_KEY}"})
        assert response.status_code == 403

    def test_reviewer_bearer_key_gets_a_readonly_view(self, dash_client: TestClient) -> None:
        response = dash_client.get(
            "/dashboard", headers={"Authorization": f"Bearer {REVIEWER_KEY}"}
        )
        assert response.status_code == 200
        assert 'data-testid="readonly-note"' in response.text
        # A read-only view has nothing to bind a CSRF token to; the approve/
        # deny buttons must not be rendered at all.
        assert 'data-testid="approve-button"' not in response.text
        assert 'data-testid="deny-button"' not in response.text

    def test_reviewer_session_gets_the_full_interactive_queue(
        self, dash_client: TestClient
    ) -> None:
        # The CSRF token is only rendered inside a pending item's own
        # approve/deny controls (app/templates/dashboard/index.html) — an
        # empty queue has nothing to bind a token to, so create one first.
        create = dash_client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
            json={
                "messages": [
                    {"role": "user", "content": "Give me a specific medical diagnosis please."}
                ]
            },
        )
        assert create.status_code == 202

        _login(dash_client, REVIEWER_KEY)
        response = dash_client.get("/dashboard")
        assert response.status_code == 200
        assert 'data-testid="readonly-note"' not in response.text
        assert 'data-testid="approve-button"' in response.text
        assert 'data-testid="deny-button"' in response.text
        assert "X-CSRF-Token" in response.text

    def test_mock_mode_banner_is_visible_dep004(self, dash_client: TestClient) -> None:
        """DEP-004's fourth mandatory visible mock-mode marker."""
        _login(dash_client, REVIEWER_KEY)
        response = dash_client.get("/dashboard")
        assert 'data-testid="mock-mode-banner"' in response.text
        assert "MOCK MODE" in response.text

    def test_queue_shows_only_transformed_preview_content_apr012(
        self, dash_client: TestClient
    ) -> None:
        create = dash_client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
            json={
                "messages": [
                    {
                        "role": "user",
                        "content": "Contact me at dashboard.review@example.com with a "
                        "specific medical diagnosis for these symptoms.",
                    }
                ]
            },
        )
        assert create.status_code == 202

        _login(dash_client, REVIEWER_KEY)
        response = dash_client.get("/dashboard", params={"status": "PENDING"})
        assert response.status_code == 200
        assert "dashboard.review@example.com" not in response.text
        assert "[REDACTED:EMAIL]" in response.text


# ---------------------------------------------------------------------------
# POST /dashboard/approvals/{id}/decide (SEC-006, SEC-007, APR-009/010)
# ---------------------------------------------------------------------------


class TestDashboardDecide:
    def _create_pending_approval(self, client: TestClient) -> tuple[str, str]:
        create = client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
            json={
                "messages": [
                    {
                        "role": "user",
                        "content": "Based on these symptoms, can you give me a "
                        "specific medical diagnosis?",
                    }
                ]
            },
        )
        assert create.status_code == 202
        body = create.json()
        return body["approval_id"], body["request_id"]

    def test_missing_csrf_token_is_rejected_sec007(self, dash_client: TestClient) -> None:
        approval_id, _ = self._create_pending_approval(dash_client)
        _login(dash_client, REVIEWER_KEY)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={"Idempotency-Key": "dash-no-csrf-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403
        assert "CSRF" in response.text

    def test_mismatched_csrf_token_is_rejected_sec007(self, dash_client: TestClient) -> None:
        approval_id, _ = self._create_pending_approval(dash_client)
        _login(dash_client, REVIEWER_KEY)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={
                "Idempotency-Key": "dash-bad-csrf-1",
                "X-CSRF-Token": "0" * 64,
            },
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403
        assert "CSRF" in response.text

    def test_no_session_at_all_is_rejected(self, dash_client: TestClient) -> None:
        approval_id, _ = self._create_pending_approval(dash_client)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={"Idempotency-Key": "dash-no-session-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 401

    def test_service_bearer_key_has_no_route_in_here_sec006(self, dash_client: TestClient) -> None:
        """SEC-006: this handler never accepts a bearer key at all — a
        service key with no session cookie is indistinguishable from no
        credential and fails the same way (401), never 200."""
        approval_id, _ = self._create_pending_approval(dash_client)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={
                "Authorization": f"Bearer {SERVICE_KEY}",
                "Idempotency-Key": "dash-svc-key-1",
            },
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 401

    def test_missing_idempotency_key_is_rejected(self, dash_client: TestClient) -> None:
        approval_id, _ = self._create_pending_approval(dash_client)
        _login(dash_client, REVIEWER_KEY)
        index = dash_client.get("/dashboard")
        csrf_token = _extract_csrf_token(index.text)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 400

    def test_valid_csrf_token_approves_end_to_end(self, dash_client: TestClient) -> None:
        approval_id, request_id = self._create_pending_approval(dash_client)
        _login(dash_client, REVIEWER_KEY)
        index = dash_client.get("/dashboard")
        csrf_token = _extract_csrf_token(index.text)

        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={
                "X-CSRF-Token": csrf_token,
                "Idempotency-Key": "dash-approve-1",
            },
            json={"decision": "APPROVE", "note": "Cleared with clinical lead."},
        )
        assert response.status_code == 200
        assert 'data-testid="decision-status"' in response.text
        assert "APPROVE" in response.text
        assert "COMPLETED" in response.text

        # The resume actually happened — the caller's poll now returns a
        # real completion, exactly as the canonical JSON decision route
        # would have produced (they share app/approvals.decide_and_resume()).
        poll = dash_client.get(
            f"/v1/firewall/requests/{request_id}",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        )
        poll_body = poll.json()
        assert poll_body["status"] == "COMPLETED"
        assert poll_body["response"]["object"] == "chat.completion"

    def test_valid_csrf_token_denies_end_to_end_with_a_note(self, dash_client: TestClient) -> None:
        approval_id, request_id = self._create_pending_approval(dash_client)
        _login(dash_client, REVIEWER_KEY)
        index = dash_client.get("/dashboard")
        csrf_token = _extract_csrf_token(index.text)

        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={
                "X-CSRF-Token": csrf_token,
                "Idempotency-Key": "dash-deny-1",
            },
            json={"decision": "DENY", "note": "Escalation required, denying for now."},
        )
        assert response.status_code == 200
        assert "DENY" in response.text
        assert "DENIED" in response.text

        poll = dash_client.get(
            f"/v1/firewall/requests/{request_id}",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        )
        assert poll.json()["status"] == "DENIED"

    def test_self_approval_is_still_refused_through_the_dashboard_route(
        self, dash_client: TestClient
    ) -> None:
        """APR-009/SEC-006: the dashboard route reuses decide_and_resume(),
        so the reviewer-identity-created-this-transaction check still
        applies even though the auth mechanism (session, not bearer) is
        different from the canonical endpoint's."""
        create = dash_client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {REVIEWER_KEY}"},
            json={
                "messages": [
                    {"role": "user", "content": "Give me a specific medical diagnosis please."}
                ]
            },
        )
        assert create.status_code == 202
        approval_id = create.json()["approval_id"]

        _login(dash_client, REVIEWER_KEY)
        index = dash_client.get("/dashboard")
        csrf_token = _extract_csrf_token(index.text)
        response = dash_client.post(
            f"/dashboard/approvals/{approval_id}/decide",
            headers={
                "X-CSRF-Token": csrf_token,
                "Idempotency-Key": "dash-self-approve-1",
            },
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Security headers (SEC-008) — asserted on both the JSON API and the
# dashboard, since app/main.py's SecurityHeadersMiddleware is global.
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    def test_headers_present_on_the_dashboard_login_page(self, dash_client: TestClient) -> None:
        response = dash_client.get("/dashboard/login")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert response.headers["Content-Security-Policy"] == "default-src 'self'"
        assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
        assert "Strict-Transport-Security" not in response.headers  # not production

    def test_headers_present_on_the_json_api_too(self, dash_client: TestClient) -> None:
        response = dash_client.get("/healthz")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Content-Security-Policy"] == "default-src 'self'"

    def test_hsts_present_only_in_production(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        client = client_factory(
            APP_ENV="production",
            FIREWALL_API_KEYS=SERVICE_KEY,
            FIREWALL_REVIEWER_KEYS=REVIEWER_KEY,
            SESSION_SECRET="a-production-session-secret-of-at-least-32-bytes",
            HASH_SALT="a-production-hash-salt-of-16b+",
            METRICS_REQUIRE_AUTH="true",
            ALLOW_MOCK_IN_PRODUCTION="true",
        )
        response = client.get("/healthz")
        assert "Strict-Transport-Security" in response.headers
        assert "max-age" in response.headers["Strict-Transport-Security"]


# ---------------------------------------------------------------------------
# No third-party CDN assets (SPEC.md §2.19)
# ---------------------------------------------------------------------------


def test_dashboard_pages_load_no_third_party_cdn_assets(dash_client: TestClient) -> None:
    _login(dash_client, REVIEWER_KEY)
    for path in ("/dashboard/login", "/dashboard"):
        html = dash_client.get(path).text
        for marker in ("http://", "https://", "//cdn.", "//unpkg", "//jsdelivr", "//googleapis"):
            assert marker not in html, f"{path} references an external asset: {marker}"

    css = dash_client.get("/dashboard/static/dashboard.css")
    assert css.status_code == 200
    htmx = dash_client.get("/dashboard/static/vendor/htmx.min.js")
    assert htmx.status_code == 200
