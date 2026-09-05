"""Rate limiter. SPEC.md §2.17, §10 `rate_limit_state`. PLAN.md WS-13.
Phase 6 — see docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md
for the full account of every judgment call below.

A fixed-window counter per identity, backed by SQLite via the same
`immediate_transaction()` (`BEGIN IMMEDIATE`) discipline app/approvals.py
already uses for the approval state machine (APR-004's reasoning applies
identically: two concurrent requests from the same identity must never
both read the same pre-increment count). "Fixed window" rather than a true
sliding log because SPEC.md's own `rate_limit_state` column list
(`window_start`, `request_count`) is exactly a fixed-window counter's shape,
not a per-request log — see the ADR.

§2.17: "MUST NOT rate-limit `GET /healthz`, `GET /readyz`, or the
approval-decision endpoint." This module is called from exactly one place
(`app/main.py`'s `POST /v1/chat/completions` handler, before any detection
work runs) — the three excluded endpoints, plus every other route, are
never subject to it at all, which trivially satisfies the prohibition
without needing per-route exemption logic.

§2.17: "a limiter backend failure fails open in development and closed in
production." `check_rate_limit()` lets a database exception propagate; the
caller (app/main.py) decides fail-open/fail-closed, since only it knows
`APP_ENV`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, delete, select

from app.db import RateLimitStateRow, immediate_transaction
from app.ids import new_id
from app.policy import Policy


@dataclass(frozen=True)
class RateLimitConfig:
    requests: int
    window_seconds: int
    scope: str = "identity"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    limit: int
    window_seconds: int


def rate_limit_config_from_policy(
    policy: Policy | None,
    *,
    default_requests: int,
    default_window_seconds: int,
) -> RateLimitConfig:
    """WS-13: "policy-configured limits." `policies/default_policy.yaml`'s
    `rate_limit_default` rule (`rate_limit: {requests, window_seconds,
    scope}`) is the primary source when present — the same rule
    app/decision.py's condition evaluator explicitly skips (it has no
    "requests in window" state to evaluate against; enforcement lives here
    instead). `Settings.RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW_SECONDS`
    (already validated at startup, per earlier phases) are the fallback
    when no policy is loaded or no rule declares `rate_limit` — this is
    also what keeps the limiter working during a POL-009 degraded-policy
    window, when `state.policy` is `None`.
    """
    if policy is not None:
        for rule in policy.rules:
            rl = rule.get("rate_limit")
            if rl:
                return RateLimitConfig(
                    requests=int(rl["requests"]),
                    window_seconds=int(rl["window_seconds"]),
                    scope=str(rl.get("scope", "identity")),
                )
    return RateLimitConfig(requests=default_requests, window_seconds=default_window_seconds)


def _window_start(now: datetime, window_seconds: int) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=UTC).replace(tzinfo=None)
    elapsed = (now - epoch).total_seconds()
    aligned = int(elapsed // window_seconds) * window_seconds
    return epoch + timedelta(seconds=aligned)


def check_rate_limit(
    engine: Engine,
    *,
    identity_id: str,
    config: RateLimitConfig,
    now: datetime | None = None,
) -> RateLimitResult:
    """Atomically read-increment-write the counter for
    `(identity_id, current window)`. Returns whether this request is the
    one that pushed the count over `config.requests`, or below it.

    "The configured limit is enforced within one request of accuracy"
    (WS-13's acceptance criterion) — the count is incremented *before* the
    comparison, so the request that reaches exactly `config.requests` is
    still allowed and the `(config.requests + 1)`th is the first refused,
    which is the conventional, unsurprising boundary a caller expects.
    """
    now = now if now is not None else datetime.now(UTC).replace(tzinfo=None)
    window_start = _window_start(now, config.window_seconds)

    with immediate_transaction(engine) as session:
        # Retention: "swept beyond two windows" — done inline, on every
        # call, rather than a separate scheduled job; this MVP's traffic
        # volume makes a per-call sweep cheap, and it means the table never
        # needs an external cron to stay bounded.
        stale_before = window_start - timedelta(seconds=2 * config.window_seconds)
        session.execute(
            delete(RateLimitStateRow).where(RateLimitStateRow.window_start < stale_before)
        )

        row = session.execute(
            select(RateLimitStateRow).where(
                RateLimitStateRow.identity_id == identity_id,
                RateLimitStateRow.window_start == window_start,
            )
        ).scalar_one_or_none()

        if row is None:
            row = RateLimitStateRow(
                id=new_id("rlm"),
                identity_id=identity_id,
                window_start=window_start,
                request_count=0,
                updated_at=now,
            )
            session.add(row)

        row.request_count += 1
        row.updated_at = now
        count = row.request_count

    allowed = count <= config.requests
    remaining = max(0, config.requests - count)
    window_end = window_start + timedelta(seconds=config.window_seconds)
    # ceil, not truncate: a refused request must never report "Retry-After:
    # 0" while still genuinely refused — a caller could reasonably retry
    # immediately and be refused again. At least 1 whenever any time
    # remains in the window.
    seconds_remaining = (window_end - now).total_seconds()
    retry_after = max(1, math.ceil(seconds_remaining)) if not allowed else 0

    return RateLimitResult(
        allowed=allowed,
        remaining=remaining,
        retry_after_seconds=retry_after,
        limit=config.requests,
        window_seconds=config.window_seconds,
    )
