"""End-to-end `/console/api/*` tests over real HTTP through the TestClient —
ADR 0014 §2; SPEC.md §11.3 (SEC-005, SEC-006, SEC-007), §9 (APR-008/009/010).

Deliberately browser-free: `tests/test_console_browser.py` drives the real
Next.js SPA in a real Chromium against a real `uvicorn` process (ADR 0012's
pattern), and self-skips where Chromium is unavailable. *This* module must
run everywhere, with no Node toolchain and no `npm run build` output on
disk — which is also the state that exercises `app/console_api.py`'s
graceful "no built frontend, mount skipped, API still live" path, since the
`client_factory` fixture never runs npm.

Fixtures are `tests/conftest.py`'s existing `client_factory`, and the
NEED_APPROVAL seeding helper is the same `POST /v1/chat/completions` call
`tests/test_dashboard.py::TestDashboardDecide._create_pending_approval`
already uses — no new fixture pattern is introduced where a usable one
exists.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

SERVICE_KEY = "svc_console_test_key_0123456789abcdef01"
REVIEWER_KEY = "rev_console_test_key_0123456789abcdef01"

# The same prompt tests/test_dashboard.py uses to provoke a real
# NEED_APPROVAL verdict from the default policy's `review_sensitive_topic`
# rule — not a hand-inserted database row, so every case below reviews an
# approval the real pipeline actually created.
SENSITIVE_PROMPT = "Based on these symptoms, can you give me a specific medical diagnosis?"


@pytest.fixture
def console_client(client_factory: Callable[..., TestClient]) -> TestClient:
    return client_factory(
        FIREWALL_API_KEYS=SERVICE_KEY,
        FIREWALL_REVIEWER_KEYS=REVIEWER_KEY,
    )


def _login(client: TestClient, key: str) -> Any:
    return client.post("/console/api/login", json={"reviewer_key": key})


def _seed_pending_approval(client: TestClient) -> tuple[str, str]:
    """A real NEED_APPROVAL case created by the service identity, so the
    reviewer deciding it later is never its own creator (APR-009)."""
    create = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        json={"messages": [{"role": "user", "content": SENSITIVE_PROMPT}]},
    )
    assert create.status_code == 202, create.text
    body = create.json()
    return body["approval_id"], body["request_id"]


def _registry_counter_total(client: TestClient, sample_name: str) -> float:
    """The live value of one counter, read straight off the same
    `CollectorRegistry` instance this test's own `AppState` built and
    `/metrics` serves — the source `/console/api/stats` claims to reshape."""
    registry = client.app.state.rg.metrics.registry  # type: ignore[attr-defined]
    total = 0.0
    for metric in registry.collect():
        for sample in metric.samples:
            if sample.name == sample_name:
                total += float(sample.value)
    return total


# ---------------------------------------------------------------------------
# Login / session (SEC-005, SEC-006)
# ---------------------------------------------------------------------------


class TestConsoleLogin:
    def test_reviewer_key_succeeds_and_returns_a_csrf_token(
        self, console_client: TestClient
    ) -> None:
        response = _login(console_client, REVIEWER_KEY)
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"identity_id", "csrf_token", "expires_at"}
        assert body["identity_id"].startswith("key_")
        # The synchronizer token is HMAC-SHA256 hex (app/session.py).
        assert len(body["csrf_token"]) == 64
        assert body["expires_at"].endswith("Z")

    def test_the_cookie_is_console_scoped_and_distinct_from_the_dashboard_one(
        self, console_client: TestClient
    ) -> None:
        """ADR 0014 §2: a deliberately distinct name *and* path, so the two
        reviewer UIs' sessions can never collide or interact."""
        response = _login(console_client, REVIEWER_KEY)
        values = response.headers.get_list("set-cookie")
        (cookie,) = [v for v in values if v.startswith("rg_console_session=")]
        assert "Path=/console/api" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie
        assert "Secure" not in cookie  # development; asserted for production below
        assert not [v for v in values if v.startswith("rg_session=")]

    def test_service_key_is_rejected_sec006(self, console_client: TestClient) -> None:
        """SEC-006: a service-class identity must not gain a session by any
        route — the `/console` leg of the same rule
        `tests/test_dashboard.py::test_service_key_cannot_sign_in_sec006`
        asserts for the HTMX dashboard."""
        response = _login(console_client, SERVICE_KEY)
        assert response.status_code == 403
        assert response.json()["code"] == "INSUFFICIENT_PRIVILEGE"
        assert "set-cookie" not in {k.lower() for k in response.headers}

    def test_unrecognized_key_is_401(self, console_client: TestClient) -> None:
        response = _login(console_client, "not-a-real-key")
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_AUTHENTICATION"
        assert "set-cookie" not in {k.lower() for k in response.headers}

    def test_missing_reviewer_key_field_is_400(self, console_client: TestClient) -> None:
        response = console_client.post("/console/api/login", json={})
        assert response.status_code == 400
        assert response.json()["code"] == "INVALID_REQUEST"

    def test_secure_attribute_is_set_in_production(
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
        assert response.status_code == 200
        (cookie,) = [
            v for v in response.headers.get_list("set-cookie")
            if v.startswith("rg_console_session=")
        ]
        assert "Secure" in cookie


class TestConsoleSessionEndpoint:
    def test_without_a_cookie_is_401(self, console_client: TestClient) -> None:
        response = console_client.get("/console/api/session")
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_AUTHENTICATION"

    def test_with_a_cookie_returns_the_same_shape_login_did(
        self, console_client: TestClient
    ) -> None:
        login_body = _login(console_client, REVIEWER_KEY).json()
        response = console_client.get("/console/api/session")
        assert response.status_code == 200
        body = response.json()
        assert body["identity_id"] == login_body["identity_id"]
        # SEC-007's token is a deterministic HMAC over the session id, so a
        # restore on page load recovers the *same* token, not a new one.
        assert body["csrf_token"] == login_body["csrf_token"]

    def test_a_tampered_cookie_is_treated_as_no_cookie(
        self, console_client: TestClient
    ) -> None:
        _login(console_client, REVIEWER_KEY)
        console_client.cookies.set("rg_console_session", "forged.deadbeef", path="/console/api")
        response = console_client.get("/console/api/session")
        assert response.status_code == 401

    def test_logout_clears_the_cookie(self, console_client: TestClient) -> None:
        _login(console_client, REVIEWER_KEY)
        response = console_client.post("/console/api/logout")
        assert response.status_code == 200
        (cookie,) = [
            v for v in response.headers.get_list("set-cookie")
            if v.startswith("rg_console_session=")
        ]
        assert 'rg_console_session=""' in cookie or "Max-Age=0" in cookie


# ---------------------------------------------------------------------------
# Reads: approvals and decisions
# ---------------------------------------------------------------------------


class TestConsoleReads:
    def test_approvals_requires_a_session(self, console_client: TestClient) -> None:
        assert console_client.get("/console/api/approvals").status_code == 401

    def test_decisions_requires_a_session(self, console_client: TestClient) -> None:
        assert console_client.get("/console/api/decisions").status_code == 401

    def test_empty_queue_returns_an_empty_list_not_an_error(
        self, console_client: TestClient
    ) -> None:
        _login(console_client, REVIEWER_KEY)
        response = console_client.get("/console/api/approvals", params={"status": "PENDING"})
        assert response.status_code == 200
        assert response.json() == {"items": [], "next_cursor": None}

    def test_seeded_approval_appears_with_json_preview_and_evidence(
        self, console_client: TestClient
    ) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        _login(console_client, REVIEWER_KEY)
        response = console_client.get("/console/api/approvals", params={"status": "PENDING"})
        assert response.status_code == 200
        (item,) = [i for i in response.json()["items"] if i["approval_id"] == approval_id]
        assert item["status"] == "PENDING"
        assert item["reason_codes"]
        assert item["policy_hits"]
        # ADR 0014 §2: real JSON, not the pre-stringified blob the Jinja
        # template needed — the SPA pretty-prints it client-side.
        assert isinstance(item["preview"], dict)
        assert isinstance(item["preview"]["messages"], list)

    def test_preview_is_the_transformed_content_only_apr012(
        self, console_client: TestClient
    ) -> None:
        """APR-012: the console reuses the already-transformed
        `preview_content` `app/approvals.py` stored at creation time — it
        never opens a second, untransformed query path."""
        create = console_client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
            json={
                "messages": [
                    {
                        "role": "user",
                        "content": "Contact me at console.review@example.com with a "
                        "specific medical diagnosis for these symptoms.",
                    }
                ]
            },
        )
        assert create.status_code == 202
        _login(console_client, REVIEWER_KEY)
        raw = console_client.get("/console/api/approvals", params={"status": "PENDING"}).text
        assert "console.review@example.com" not in raw
        assert "[REDACTED:EMAIL]" in raw

    def test_an_unknown_status_value_is_rejected_not_silently_ignored(
        self, console_client: TestClient
    ) -> None:
        _login(console_client, REVIEWER_KEY)
        response = console_client.get("/console/api/approvals", params={"status": "NONSENSE"})
        assert response.status_code == 400
        assert response.json()["code"] == "INVALID_REQUEST"

    def test_a_partially_valid_status_list_is_rejected_whole(
        self, console_client: TestClient
    ) -> None:
        """A mixed list must not quietly degrade to the valid subset: a
        caller who mistypes one state would otherwise get a plausible-looking
        partial result with no indication of the typo."""
        _login(console_client, REVIEWER_KEY)
        response = console_client.get(
            "/console/api/approvals?status=PENDING&status=NONSENSE"
        )
        assert response.status_code == 400
        assert "NONSENSE" in response.json()["error"]

    def test_multiple_valid_statuses_are_accepted(self, console_client: TestClient) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        _login(console_client, REVIEWER_KEY)
        response = console_client.get(
            "/console/api/approvals?status=PENDING&status=COMPLETED"
        )
        assert response.status_code == 200
        assert approval_id in {i["approval_id"] for i in response.json()["items"]}


# ---------------------------------------------------------------------------
# Decide (SEC-005, SEC-007, APR-008/009/010)
# ---------------------------------------------------------------------------


class TestConsoleDecide:
    def test_full_flow_login_list_approve_moves_state(self, console_client: TestClient) -> None:
        approval_id, request_id = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]

        listing = console_client.get("/console/api/approvals", params={"status": "PENDING"})
        assert approval_id in {i["approval_id"] for i in listing.json()["items"]}

        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token, "Idempotency-Key": "console-approve-1"},
            json={"decision": "APPROVE", "note": "Cleared with clinical lead."},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["decision"] == "APPROVE"
        # APR-011: the resume ran inline in this same request, exactly as it
        # does through the dashboard and the canonical JSON route — all three
        # call app/approvals.decide_and_resume().
        assert body["status"] == "COMPLETED"
        assert body["outcome"] == "applied"

        # It really left PENDING, observed through the console's own read
        # route rather than by trusting the decide response alone.
        after = console_client.get("/console/api/approvals", params={"status": "PENDING"})
        assert approval_id not in {i["approval_id"] for i in after.json()["items"]}
        completed = console_client.get("/console/api/approvals", params={"status": "COMPLETED"})
        assert approval_id in {i["approval_id"] for i in completed.json()["items"]}

        # And the original caller's request actually resumed.
        poll = console_client.get(
            f"/v1/firewall/requests/{request_id}",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        )
        assert poll.json()["status"] == "COMPLETED"

        decisions = console_client.get("/console/api/decisions").json()["items"]
        assert any(d["approval_id"] == approval_id for d in decisions)

    def test_deny_requires_a_note_server_side(self, console_client: TestClient) -> None:
        """The SPA disables its own Deny button without a note, but the
        server is the enforcement point: `app/approvals.decide_approval()`
        raises 422 INVALID_REQUEST for an empty note regardless of client."""
        approval_id, _ = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token, "Idempotency-Key": "console-deny-empty-1"},
            json={"decision": "DENY", "note": "   "},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "INVALID_REQUEST"

    def test_deny_with_a_note_succeeds(self, console_client: TestClient) -> None:
        approval_id, request_id = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token, "Idempotency-Key": "console-deny-1"},
            json={"decision": "DENY", "note": "Escalation required, denying for now."},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "DENIED"
        poll = console_client.get(
            f"/v1/firewall/requests/{request_id}",
            headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        )
        assert poll.json()["status"] == "DENIED"

    def test_missing_csrf_token_is_403_sec007(self, console_client: TestClient) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        _login(console_client, REVIEWER_KEY)
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"Idempotency-Key": "console-no-csrf-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "CSRF_TOKEN_INVALID"

    def test_stale_csrf_token_from_a_previous_session_is_403_sec007(
        self, console_client: TestClient
    ) -> None:
        """A token is bound to *its own* session id, so the token from a
        session that has since been replaced by a fresh login no longer
        verifies — the synchronizer property, exercised against a real
        stale token rather than a made-up string."""
        approval_id, _ = _seed_pending_approval(console_client)
        stale_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        fresh_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        assert stale_token != fresh_token

        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": stale_token, "Idempotency-Key": "console-stale-csrf-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "CSRF_TOKEN_INVALID"

    def test_foreign_csrf_token_is_403_sec007(self, console_client: TestClient) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        _login(console_client, REVIEWER_KEY)
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": "0" * 64, "Idempotency-Key": "console-foreign-csrf-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403

    def test_no_session_at_all_is_401(self, console_client: TestClient) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": "0" * 64, "Idempotency-Key": "console-no-session-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 401

    def test_a_service_bearer_key_has_no_route_in_here_sec006(
        self, console_client: TestClient
    ) -> None:
        """SEC-006: this handler never accepts a bearer key at all — a
        service key with no console session is indistinguishable from no
        credential and fails the same way."""
        approval_id, _ = _seed_pending_approval(console_client)
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={
                "Authorization": f"Bearer {SERVICE_KEY}",
                "Idempotency-Key": "console-svc-key-1",
            },
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 401

    def test_missing_idempotency_key_is_400(self, console_client: TestClient) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 400

    def test_deciding_an_already_decided_approval_surfaces_the_real_error(
        self, console_client: TestClient
    ) -> None:
        """The SPA shows this message rather than failing silently — so the
        API must actually return the underlying `FirewallError`'s own status
        and code, not a generic 500 (ADR 0014 §2's error-shape rule)."""
        approval_id, _ = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf_token}

        first = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={**headers, "Idempotency-Key": "console-double-1"},
            json={"decision": "APPROVE"},
        )
        assert first.status_code == 200

        second = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={**headers, "Idempotency-Key": "console-double-2"},
            json={"decision": "APPROVE"},
        )
        assert second.status_code == 409
        assert second.json()["code"] == "INVALID_APPROVAL_STATE"
        assert second.json()["error"]

    def test_replaying_the_same_idempotency_key_is_not_an_error_apr010(
        self, console_client: TestClient
    ) -> None:
        approval_id, _ = _seed_pending_approval(console_client)
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        headers = {"X-CSRF-Token": csrf_token, "Idempotency-Key": "console-replay-1"}
        body = {"decision": "APPROVE", "note": "same body both times"}

        first = console_client.post(
            f"/console/api/approvals/{approval_id}/decide", headers=headers, json=body
        )
        second = console_client.post(
            f"/console/api/approvals/{approval_id}/decide", headers=headers, json=body
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["outcome"] == "replayed"

    def test_self_approval_is_still_refused_apr009(self, console_client: TestClient) -> None:
        create = console_client.post(
            "/v1/chat/completions",
            headers={"Authorization": f"Bearer {REVIEWER_KEY}"},
            json={"messages": [{"role": "user", "content": SENSITIVE_PROMPT}]},
        )
        assert create.status_code == 202
        approval_id = create.json()["approval_id"]
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]
        response = console_client.post(
            f"/console/api/approvals/{approval_id}/decide",
            headers={"X-CSRF-Token": csrf_token, "Idempotency-Key": "console-self-1"},
            json={"decision": "APPROVE"},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "SELF_APPROVAL_FORBIDDEN"


# ---------------------------------------------------------------------------
# Stats (ADR 0014 §2: no new measurement)
# ---------------------------------------------------------------------------


class TestConsoleStats:
    def test_requires_a_session(self, console_client: TestClient) -> None:
        assert console_client.get("/console/api/stats").status_code == 401

    def test_returns_the_expected_keys(self, console_client: TestClient) -> None:
        _login(console_client, REVIEWER_KEY)
        response = console_client.get("/console/api/stats")
        assert response.status_code == 200
        body = response.json()
        assert set(body) == {
            "mock_mode",
            "policy_version",
            "approvals_by_state",
            "totals",
            "decisions_by_verdict",
            "risk_levels",
            "policy_hits",
            "reason_codes",
        }
        # DEP-004: the console's own visible mock-mode marker; the fixture
        # sets no UPSTREAM_BASE_URL, so this must be true here.
        assert body["mock_mode"] is True
        assert set(body["totals"]) == {"approvals", "pending", "decisions", "http_requests"}
        assert body["approvals_by_state"].keys() >= {"PENDING", "APPROVED", "DENIED", "COMPLETED"}

    def test_numbers_are_internally_consistent_with_this_apps_own_registry(
        self, console_client: TestClient
    ) -> None:
        """No hardcoded expected values — every assertion is a *relationship*
        between what this test itself did, what the live `CollectorRegistry`
        holds, and what `/console/api/stats` reports, so the test cannot rot
        as unrelated pipeline work changes absolute counts.
        """
        created = 3
        approval_ids = [_seed_pending_approval(console_client)[0] for _ in range(created)]
        csrf_token = _login(console_client, REVIEWER_KEY).json()["csrf_token"]

        # Decide two of the three: one APPROVE (-> COMPLETED via resume),
        # one DENY (-> DENIED). One stays PENDING.
        for index, (decision, note) in enumerate(
            [("APPROVE", "cleared"), ("DENY", "not this one")]
        ):
            decided = console_client.post(
                f"/console/api/approvals/{approval_ids[index]}/decide",
                headers={
                    "X-CSRF-Token": csrf_token,
                    "Idempotency-Key": f"console-stats-{index}",
                },
                json={"decision": decision, "note": note},
            )
            assert decided.status_code == 200, decided.text

        # Bracketing readings around the stats call: `HttpMetricsMiddleware`
        # is the outermost middleware, so it counts a request *after* the
        # handler has already built its body — the stats response therefore
        # cannot include itself in `http_requests`, and asserting equality
        # against a single after-the-fact reading would be wrong rather than
        # strict. Bracketing states the real invariant instead: the reported
        # figure is a genuine reading of this registry taken somewhere
        # between these two points, never an independently derived number.
        http_before = _registry_counter_total(console_client, "realguard_http_requests_total")
        body = console_client.get("/console/api/stats").json()
        http_after = _registry_counter_total(console_client, "realguard_http_requests_total")
        by_state = body["approvals_by_state"]

        # 1. Every approval this test created is accounted for in exactly one
        #    state — the per-state counts partition the queue, they don't
        #    double-count a row that moved.
        assert sum(by_state.values()) == created
        assert body["totals"]["approvals"] == created
        assert by_state["PENDING"] == 1
        assert by_state["COMPLETED"] == 1
        assert by_state["DENIED"] == 1
        assert body["totals"]["pending"] == by_state["PENDING"]

        # 2. The reported decisions total equals what the very same
        #    CollectorRegistry `/metrics` serves holds right now — the stats
        #    route reshapes that registry, it never re-derives a number.
        assert body["totals"]["decisions"] == _registry_counter_total(
            console_client, "realguard_decisions_total"
        )
        assert http_before <= body["totals"]["http_requests"] <= http_after

        # 3. The per-verdict breakdown sums to that same total (zero-valued
        #    series are dropped for charting, and a counter is never
        #    negative, so equality holds rather than merely `<=`).
        assert (
            sum(row["value"] for row in body["decisions_by_verdict"])
            == body["totals"]["decisions"]
        )

        # 4. Each seeded request produced a NEED_APPROVAL input-plane
        #    decision, so that verdict must be present and at least as large
        #    as the number of approvals this test created.
        need_approval = {row["name"]: row["value"] for row in body["decisions_by_verdict"]}
        assert need_approval.get("NEED_APPROVAL", 0) >= created

        # 5. The policy rule that produced these approvals appears in the
        #    policy-hits series the overview chart renders.
        assert any(row["value"] > 0 for row in body["policy_hits"])
        assert any(row["value"] > 0 for row in body["reason_codes"])


# ---------------------------------------------------------------------------
# Graceful degradation and non-interference
# ---------------------------------------------------------------------------


def test_the_app_starts_and_serves_without_any_built_frontend(
    console_client: TestClient,
) -> None:
    """The whole point of `app/console_api.py`'s conditional mount: this
    test process never ran `npm run build`, and the API surface is live
    regardless. If `web/out` *does* happen to exist in a developer's
    checkout, `/console/` serves the SPA instead of 404ing — either outcome
    is correct, and neither may be a 500."""
    _login(console_client, REVIEWER_KEY)
    assert console_client.get("/console/api/stats").status_code == 200
    assert console_client.get("/console/", follow_redirects=False).status_code in (200, 404)


def test_the_existing_dashboard_is_untouched(console_client: TestClient) -> None:
    """ADR 0014 §4: `/console` is additive. The HTMX dashboard's own login,
    cookie name and page still behave exactly as ADR 0006 specified, with a
    console session present and irrelevant to it."""
    _login(console_client, REVIEWER_KEY)
    assert console_client.get("/dashboard", follow_redirects=False).status_code == 303

    dash_login = console_client.post(
        "/dashboard/login", data={"reviewer_key": REVIEWER_KEY}, follow_redirects=False
    )
    assert dash_login.status_code == 303
    assert [
        v for v in dash_login.headers.get_list("set-cookie") if v.startswith("rg_session=")
    ]
    assert console_client.get("/dashboard").status_code == 200


def test_security_headers_apply_to_the_console_api_too_sec008(
    console_client: TestClient,
) -> None:
    """SEC-008's middleware is global (app/main.py), so the new prefix gains
    it with no per-route opt-in — including the strict CSP the SPA must not
    violate (proved in a real browser by tests/test_console_browser.py)."""
    response = console_client.get("/console/api/session")
    assert response.headers["Content-Security-Policy"] == "default-src 'self'"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
