"""WS-03 gateway tests. SPEC.md §4, API-002, API-006, API-014, ERR-001..004."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def test_healthz_ok(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_reports_mock_mode(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert body["mode"] == "mock"
    assert body["dependencies"]["policy"] == "ok"


def test_benign_request_returns_openai_shape_at_top_level(client: TestClient) -> None:
    """ADR 0002: id/object/created/model/choices/usage MUST be top-level,
    never nested under a `response` field, or the real openai SDK breaks."""
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "What is a good banana bread recipe?"}]},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["object"] == "chat.completion"
    assert body["id"].startswith("chatcmpl_")
    assert isinstance(body["choices"], list) and len(body["choices"]) == 1
    assert body["choices"][0]["message"]["content"]
    assert "usage" in body
    assert "response" not in body  # the old, broken wrapper shape must be gone


def test_benign_request_firewall_metadata(client: TestClient) -> None:
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    body = r.json()
    fw = body["firewall"]
    assert fw["decision"] == "ALLOW"
    assert fw["transformation"] == "NONE"
    assert fw["transaction_id"].startswith("txn_")
    assert fw["mode"] == "mock"
    assert fw["policy_version"].startswith("sha256:")


def test_response_headers_api_002(client: TestClient) -> None:
    r = client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.headers["X-RealGuard-Transaction-Id"].startswith("txn_")
    assert r.headers["X-RealGuard-Mode"] == "mock"


def test_correlation_id_echoed_when_supplied(client: TestClient) -> None:
    r = client.get("/healthz", headers={"X-Correlation-Id": "cor_test123"})
    assert r.headers["X-Correlation-Id"] == "cor_test123"


def test_correlation_id_generated_when_absent(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.headers["X-Correlation-Id"].startswith("cor_")


def test_stream_true_rejected_400(client: TestClient) -> None:
    """API-014: stream:true MUST be rejected before any detection/policy work."""
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
    )
    assert r.status_code == 400
    body = r.json()
    assert body["error"]["code"] == "UNSUPPORTED_FIELD"
    assert body["error"]["details"]["field"] == "stream"
    assert body["error"]["transaction_id"].startswith("txn_")


def test_stream_false_is_accepted(client: TestClient) -> None:
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hi"}], "stream": False},
    )
    assert r.status_code == 200


def test_missing_messages_400(client: TestClient) -> None:
    r = client.post("/v1/chat/completions", json={})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INVALID_REQUEST"


def test_empty_messages_array_400(client: TestClient) -> None:
    r = client.post("/v1/chat/completions", json={"messages": []})
    assert r.status_code == 400


def test_oversized_payload_413(client: TestClient) -> None:
    """API-006: rejected before parsing, based on Content-Length."""
    big_content = "x" * 300_000  # default MAX_REQUEST_BYTES is 262144
    payload = {"messages": [{"role": "user", "content": big_content}]}
    r = client.post("/v1/chat/completions", json=payload)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_unknown_extra_fields_are_forwarded_not_rejected(client: TestClient) -> None:
    """API-013: unknown request fields are forwarded, not rejected."""
    r = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hi"}],
            "some_future_openai_field": {"nested": True},
        },
    )
    assert r.status_code == 200


def test_error_envelope_shape(client: TestClient) -> None:
    """ERR-001: every error uses {"error": {code, type, message, transaction_id}}."""
    r = client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
    )
    err = r.json()["error"]
    assert set(err.keys()) >= {"code", "type", "message", "transaction_id"}


def test_mock_mode_announced_at_startup_dep004(caplog: pytest.LogCaptureFixture) -> None:
    """DEP-004: mock mode must be visible in >=4 places — this is place 1,
    the startup log line. (Places 2 and 3 — /readyz and the response header —
    are covered by test_readyz_reports_mock_mode and
    test_response_headers_api_002 above; place 4, the dashboard header,
    arrives with WS-11 in Phase 4.)"""
    import logging

    from app.main import create_app

    with caplog.at_level(logging.WARNING, logger="realguard"):
        create_app()
    assert any("MOCK MODE" in record.message for record in caplog.records)


# API-009/ERR-022 (a DENY body must not echo request content) has no test
# here: no policy engine exists yet in Phase 1 to ever produce a DENY. Real
# coverage arrives in Phase 2 via tests/test_golden_corpus.py, once decision
# evaluation exists to actually deny something.
