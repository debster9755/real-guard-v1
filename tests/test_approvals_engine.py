"""Unit-level tests against app/approvals.py directly — the state-machine
guarantees SPEC.md §9 requires (APR-001..015) that aren't reachable, or not
reliably reachable, purely through the synchronous HTTP flow tests/
test_approvals_api.py exercises (ADR 0004: this MVP folds the "resume
worker" into the decision request itself, so there is no real-world window
between APPROVE and resume in which to observe e.g. a material-argument
change through HTTP alone — that path is exercised here, directly)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from app.approvals import (
    ALLOWED_TRANSITIONS,
    DecisionOutcome,
    ResumeOutcome,
    create_approval,
    decide_approval,
    get_approval,
    reconcile_resuming_on_startup,
    resume_approved,
    sweep_expired,
)
from app.auth import Identity, IdentityClass
from app.db import ApprovalRow, make_engine
from app.errors import ErrorCode, FirewallError
from app.policy import load_policy
from app.providers.mock import MockProvider

_POLICY = load_policy("policies/default_policy.yaml")


@pytest.fixture
def engine(tmp_path: Path) -> Any:
    return make_engine(f"sqlite:///{tmp_path / 'engine_test.db'}")


def _create(engine: Any, **overrides: Any) -> Any:
    defaults: dict[str, Any] = {
        "transaction_id": "txn_00000000000000000000000001",
        "request_id": "req_00000000000000000000000001",
        "correlation_id": "cor_test",
        "creator_identity_id": "key_creator",
        "mode": "mock",
        "risk_level": "MEDIUM",
        "reason_codes": ["SENSITIVE_TOPIC"],
        "policy_hits": ["review_sensitive_topic"],
        "transformation": "NONE",
        "policy_version": "sha256:test",
        "preview_content": {"messages": [{"role": "user", "content": "hi"}]},
        "transformed_payload": {"messages": [{"role": "user", "content": "hi"}]},
        "material_args_hash": "sha256:abc",
        "ttl_seconds": 3600,
        "retain_raw_content": False,
        "raw_request_content": None,
    }
    defaults.update(overrides)
    return create_approval(engine, **defaults)


def _reviewer(key_id: str = "key_reviewer") -> Identity:
    return Identity(IdentityClass.REVIEWER, key_id)


# ---------------------------------------------------------------------------
# APR-003: the forbidden-transition matrix.
# ---------------------------------------------------------------------------

_ALL_STATES = [
    "PENDING",
    "APPROVED",
    "DENIED",
    "EXPIRED",
    "RESUMING",
    "COMPLETED",
    "CANCELLED",
    "FAILED",
]


@pytest.mark.parametrize(
    "from_state,to_state",
    [
        (f, t)
        for f in _ALL_STATES
        for t in _ALL_STATES
        if (f, t) not in ALLOWED_TRANSITIONS and f != t
    ],
)
def test_forbidden_transitions_matrix_apr003(engine: Any, from_state: str, to_state: str) -> None:
    """APR-001/APR-003: every transition not on the drawn diagram is
    rejected and does not mutate the row, decided via the same
    `_transition` guard every state-changing function in app/approvals.py
    uses."""
    from app.approvals import _transition  # test-only import of the guard itself
    from app.db import immediate_transaction

    creation = _create(engine)

    with immediate_transaction(engine) as session:
        row = session.get(ApprovalRow, creation.approval.id)
        assert row is not None
        row.state = from_state
        session.add(row)

    with immediate_transaction(engine) as session:
        row = session.get(ApprovalRow, creation.approval.id)
        assert row is not None
        with pytest.raises(FirewallError) as exc_info:
            _transition(row, to_state)
        assert exc_info.value.code == ErrorCode.INVALID_APPROVAL_STATE

    # Not mutated: the row on disk is still `from_state`.
    reread = get_approval(engine, creation.approval.id)
    assert reread is not None
    assert reread.state == from_state


def test_allowed_transitions_are_exactly_the_documented_nine(engine: Any) -> None:
    """Locks the transition table itself against silent drift — SPEC.md
    §9.2 draws exactly nine edges."""
    assert (
        frozenset(
            {
                ("PENDING", "APPROVED"),
                ("PENDING", "DENIED"),
                ("PENDING", "EXPIRED"),
                ("PENDING", "CANCELLED"),
                ("APPROVED", "RESUMING"),
                ("APPROVED", "EXPIRED"),
                ("RESUMING", "COMPLETED"),
                ("RESUMING", "DENIED"),
                ("RESUMING", "APPROVED"),
            }
        )
        == ALLOWED_TRANSITIONS
    )


# ---------------------------------------------------------------------------
# APR-013: material-argument re-validation on resume.
# ---------------------------------------------------------------------------


def test_resume_denies_when_material_arguments_changed_apr013(engine: Any) -> None:
    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000002",
        request_id="req_00000000000000000000000002",
        material_args_hash="sha256:stale-hash-that-will-never-match",
    )
    decide_approval(
        engine,
        creation.approval.id,
        decision="APPROVE",
        note=None,
        reviewer_identity=_reviewer(),
        idempotency_key="idem-args-changed",
        correlation_id="cor_test",
    )

    outcome = asyncio.run(
        resume_approved(
            engine,
            creation.approval.id,
            provider=MockProvider(),
            retain_response_content=False,
            policy=_POLICY,
            salt="test-salt",
        )
    )
    assert outcome == ResumeOutcome.DENIED_ARGUMENTS_CHANGED

    final = get_approval(engine, creation.approval.id)
    assert final is not None
    assert final.state == "DENIED"
    assert final.completion_result is None  # the provider must never have been called


def test_resume_completes_when_arguments_are_unchanged(engine: Any) -> None:
    from app.materialargs import compute_material_args_hash

    messages = [{"role": "user", "content": "hi"}]
    real_hash = compute_material_args_hash(messages, None)
    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000003",
        request_id="req_00000000000000000000000003",
        transformed_payload={"messages": messages},
        material_args_hash=real_hash,
    )
    decide_approval(
        engine,
        creation.approval.id,
        decision="APPROVE",
        note=None,
        reviewer_identity=_reviewer(),
        idempotency_key="idem-args-ok",
        correlation_id="cor_test",
    )
    outcome = asyncio.run(
        resume_approved(
            engine,
            creation.approval.id,
            provider=MockProvider(),
            retain_response_content=False,
            policy=_POLICY,
            salt="test-salt",
        )
    )
    assert outcome == ResumeOutcome.COMPLETED
    final = get_approval(engine, creation.approval.id)
    assert final is not None
    assert final.state == "COMPLETED"
    assert final.completion_result is not None


# ---------------------------------------------------------------------------
# APR-011: exactly-once resume under concurrent claims.
# ---------------------------------------------------------------------------


def test_resume_claims_exactly_once_under_concurrent_attempts_apr011(engine: Any) -> None:
    from app.materialargs import compute_material_args_hash

    messages = [{"role": "user", "content": "concurrent-claim-test"}]
    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000004",
        request_id="req_00000000000000000000000004",
        transformed_payload={"messages": messages},
        material_args_hash=compute_material_args_hash(messages, None),
    )
    decide_approval(
        engine,
        creation.approval.id,
        decision="APPROVE",
        note=None,
        reviewer_identity=_reviewer(),
        idempotency_key="idem-concurrent",
        correlation_id="cor_test",
    )

    class _CountingProvider:
        name = "mock"

        def __init__(self) -> None:
            self.calls = 0

        async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
            self.calls += 1
            return await MockProvider().complete(request)

    provider = _CountingProvider()

    async def _run_concurrent() -> list[ResumeOutcome]:
        return await asyncio.gather(
            *[
                resume_approved(
                    engine,
                    creation.approval.id,
                    provider=provider,
                    retain_response_content=False,
                    policy=_POLICY,
                    salt="test-salt",
                )
                for _ in range(20)
            ]
        )

    outcomes = asyncio.run(_run_concurrent())
    assert outcomes.count(ResumeOutcome.COMPLETED) == 1
    assert outcomes.count(ResumeOutcome.NOT_ELIGIBLE) == 19
    assert provider.calls == 1  # APR-011: exactly once, never twice


# ---------------------------------------------------------------------------
# APR-014: startup reconciliation of rows stuck in RESUMING.
# ---------------------------------------------------------------------------


def test_startup_reconciles_resuming_rows_below_max_attempts_to_approved(engine: Any) -> None:
    from app.db import immediate_transaction

    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000005",
        request_id="req_00000000000000000000000005",
    )
    with immediate_transaction(engine) as session:
        row = session.get(ApprovalRow, creation.approval.id)
        assert row is not None
        row.state = "RESUMING"
        row.resume_attempts = 1
        session.add(row)

    reconciled = reconcile_resuming_on_startup(engine, max_resume_attempts=3)
    assert reconciled == 1
    final = get_approval(engine, creation.approval.id)
    assert final is not None
    assert final.state == "APPROVED"


def test_startup_moves_resuming_rows_at_max_attempts_to_failed(engine: Any) -> None:
    from app.db import immediate_transaction

    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000006",
        request_id="req_00000000000000000000000006",
    )
    with immediate_transaction(engine) as session:
        row = session.get(ApprovalRow, creation.approval.id)
        assert row is not None
        row.state = "RESUMING"
        row.resume_attempts = 3
        session.add(row)

    reconciled = reconcile_resuming_on_startup(engine, max_resume_attempts=3)
    assert reconciled == 1
    final = get_approval(engine, creation.approval.id)
    assert final is not None
    assert final.state == "FAILED"


# ---------------------------------------------------------------------------
# POL-001-style determinism check for the sweeper, and a direct APR-010 unit
# check independent of the HTTP layer.
# ---------------------------------------------------------------------------


def test_sweep_expired_is_idempotent(engine: Any) -> None:
    import datetime as dt

    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000007",
        request_id="req_00000000000000000000000007",
        ttl_seconds=1,
    )
    past = dt.datetime.now(dt.UTC).replace(tzinfo=None) - dt.timedelta(seconds=5)
    from app.db import immediate_transaction

    with immediate_transaction(engine) as session:
        row = session.get(ApprovalRow, creation.approval.id)
        assert row is not None
        row.expires_at = past
        session.add(row)

    first = sweep_expired(engine)
    second = sweep_expired(engine)
    assert first == 1
    assert second == 0  # already EXPIRED — nothing left to sweep
    final = get_approval(engine, creation.approval.id)
    assert final is not None
    assert final.state == "EXPIRED"


def test_decision_idempotency_replay_and_conflict_apr010(engine: Any) -> None:
    creation = _create(
        engine,
        transaction_id="txn_00000000000000000000000008",
        request_id="req_00000000000000000000000008",
    )
    first = decide_approval(
        engine,
        creation.approval.id,
        decision="DENY",
        note="initial reason",
        reviewer_identity=_reviewer(),
        idempotency_key="idem-unit-1",
        correlation_id="cor_test",
    )
    assert first.outcome == DecisionOutcome.APPLIED

    replay = decide_approval(
        engine,
        creation.approval.id,
        decision="DENY",
        note="initial reason",
        reviewer_identity=_reviewer(),
        idempotency_key="idem-unit-1",
        correlation_id="cor_test",
    )
    assert replay.outcome == DecisionOutcome.REPLAYED
    assert replay.decision_row.id == first.decision_row.id

    with pytest.raises(FirewallError) as exc_info:
        decide_approval(
            engine,
            creation.approval.id,
            decision="APPROVE",
            note=None,
            reviewer_identity=_reviewer(),
            idempotency_key="idem-unit-1",
            correlation_id="cor_test",
        )
    assert exc_info.value.code == ErrorCode.IDEMPOTENCY_CONFLICT
