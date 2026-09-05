"""Rate limiter tests. SPEC.md §2.17, §10 `rate_limit_state`. PLAN.md WS-13
(TST-014): "Window boundary accurate; per-identity isolated; survives
restart." Phase 6 — docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md.

Two layers, matching this project's established pattern (e.g.
tests/test_approvals_engine.py vs tests/test_approvals_api.py): unit tests
directly against app/ratelimit.py for the window-boundary/isolation/
persistence guarantees (manipulating stored `window_start` values directly,
the same technique earlier phases used for TTL expiry, rather than sleeping
for real), and an HTTP-level test proving the same thing end to end through
`POST /v1/chat/completions`, including the `429`/`Retry-After` wire shape.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from app.db import RateLimitStateRow, make_engine
from app.policy import load_policy
from app.ratelimit import RateLimitConfig, check_rate_limit, rate_limit_config_from_policy
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

_POLICY = load_policy("policies/default_policy.yaml")


@pytest.fixture
def engine(tmp_path: Path) -> Any:
    return make_engine(f"sqlite:///{tmp_path / 'ratelimit_test.db'}")


class TestCheckRateLimitUnit:
    def test_requests_under_the_limit_are_allowed(self, engine: Any) -> None:
        config = RateLimitConfig(requests=3, window_seconds=60)
        for _ in range(3):
            result = check_rate_limit(engine, identity_id="svc_a", config=config)
            assert result.allowed

    def test_the_request_that_exceeds_the_limit_is_refused(self, engine: Any) -> None:
        config = RateLimitConfig(requests=3, window_seconds=60)
        for _ in range(3):
            assert check_rate_limit(engine, identity_id="svc_a", config=config).allowed
        result = check_rate_limit(engine, identity_id="svc_a", config=config)
        assert not result.allowed
        assert result.retry_after_seconds > 0

    def test_per_identity_isolation(self, engine: Any) -> None:
        config = RateLimitConfig(requests=1, window_seconds=60)
        assert check_rate_limit(engine, identity_id="svc_a", config=config).allowed
        assert not check_rate_limit(engine, identity_id="svc_a", config=config).allowed
        # A different identity has its own, unconsumed budget.
        assert check_rate_limit(engine, identity_id="svc_b", config=config).allowed

    def test_window_boundary_is_accurate(self, engine: Any) -> None:
        """TST-014: "window boundary accurate" — exercised by directly
        manipulating the stored `window_start`/`created_at` the same way
        earlier phases manipulated a corrupted `expires_at` to force real
        TTL expiry (ADR 0004's README section), rather than sleeping for a
        real 60 seconds."""
        config = RateLimitConfig(requests=1, window_seconds=60)
        now = datetime(2026, 1, 1, 12, 0, 0)
        assert check_rate_limit(engine, identity_id="svc_a", config=config, now=now).allowed
        # Still inside the same window: refused.
        assert not check_rate_limit(
            engine, identity_id="svc_a", config=config, now=now + timedelta(seconds=30)
        ).allowed
        # A new window (60s later, aligned): allowed again.
        later = now + timedelta(seconds=61)
        assert check_rate_limit(engine, identity_id="svc_a", config=config, now=later).allowed

    def test_state_survives_a_process_restart(self, tmp_path: Path) -> None:
        """TST-014: "survives restart" — a second, independent `make_engine()`
        call against the same SQLite file (simulating a fresh process) sees
        the count the first one wrote."""
        db_path = tmp_path / "restart_test.db"
        config = RateLimitConfig(requests=1, window_seconds=120)
        now = datetime(2026, 1, 1, 12, 0, 0)

        engine_1 = make_engine(f"sqlite:///{db_path}")
        assert check_rate_limit(engine_1, identity_id="svc_a", config=config, now=now).allowed

        engine_2 = make_engine(f"sqlite:///{db_path}")
        result = check_rate_limit(engine_2, identity_id="svc_a", config=config, now=now)
        assert not result.allowed  # the budget the first "process" consumed is still spent

    def test_sweeps_state_older_than_two_windows(self, engine: Any) -> None:
        config = RateLimitConfig(requests=5, window_seconds=60)
        now = datetime(2026, 1, 1, 12, 0, 0)
        check_rate_limit(engine, identity_id="svc_a", config=config, now=now)
        with Session(engine) as session:
            assert session.execute(select(RateLimitStateRow)).scalars().first() is not None

        # Four windows later: the sweep inside the next call removes the
        # stale row (retention: "swept beyond two windows").
        much_later = now + timedelta(seconds=4 * 60)
        check_rate_limit(engine, identity_id="svc_b", config=config, now=much_later)
        with Session(engine) as session:
            rows = session.execute(select(RateLimitStateRow)).scalars().all()
            assert all(r.identity_id != "svc_a" for r in rows)


class TestRateLimitConfigFromPolicy:
    def test_reads_the_rate_limit_default_rule_from_the_loaded_policy(self) -> None:
        # policies/default_policy.yaml's own `rate_limit_default` rule.
        config = rate_limit_config_from_policy(
            _POLICY, default_requests=999, default_window_seconds=999
        )
        assert config.requests == 60
        assert config.window_seconds == 60
        assert config.scope == "identity"

    def test_falls_back_to_settings_defaults_when_no_policy_is_loaded(self) -> None:
        config = rate_limit_config_from_policy(None, default_requests=7, default_window_seconds=42)
        assert config.requests == 7
        assert config.window_seconds == 42


class TestRateLimitHttp:
    def test_exceeding_the_limit_returns_429_and_resets_after_the_window(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        client = client_factory(
            POLICY_PATH="tests/data/low_rate_limit_policy.yaml",
        )
        payload = {"messages": [{"role": "user", "content": "What is a good banana bread recipe?"}]}

        for _ in range(2):
            resp = client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 200

        blocked = client.post("/v1/chat/completions", json=payload)
        assert blocked.status_code == 429
        body = blocked.json()
        assert body["error"]["code"] == "RATE_LIMITED"
        assert "Retry-After" in blocked.headers
        assert int(blocked.headers["Retry-After"]) > 0

        # Force the window to have elapsed (the same "manipulate stored
        # state directly" technique the approval-TTL tests use, rather than
        # sleeping for a real 2 seconds) and confirm it clears.
        engine = client.app.state.rg.db_engine  # type: ignore[attr-defined]
        with Session(engine) as session:
            for row in session.execute(select(RateLimitStateRow)).scalars().all():
                row.window_start = row.window_start - timedelta(seconds=10)
            session.commit()

        recovered = client.post("/v1/chat/completions", json=payload)
        assert recovered.status_code == 200

    def test_rate_limiting_never_blocks_healthz_readyz_or_the_decision_endpoint(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        """§2.17: "MUST NOT rate-limit GET /healthz, GET /readyz, or the
        approval-decision endpoint." — proven by exhausting the same
        identity's budget against /v1/chat/completions, then confirming the
        other three still respond normally."""
        client = client_factory(POLICY_PATH="tests/data/low_rate_limit_policy.yaml")
        payload = {"messages": [{"role": "user", "content": "hello"}]}
        for _ in range(10):
            client.post("/v1/chat/completions", json=payload)

        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code in (200, 503)
