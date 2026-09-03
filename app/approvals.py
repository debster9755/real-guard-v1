"""Approval service and resume worker. SPEC.md §2.13, §2.14, §9 (APR-001..015).

ADR 0004 is the authoritative account of this module's scope. In short:
this is the real approval lifecycle — durable persistence before the `202`
(APR-005), the exact state machine of SPEC.md §9.2 with every transition
guarded by an atomic `BEGIN IMMEDIATE` write (APR-004), self-approval
refusal (APR-009), idempotent decisions (APR-010), exactly-once resume
(APR-011), material-argument re-validation on resume (APR-013), and
crash-recovery reconciliation (APR-014) — built and tested end to end,
not a stub.

Phase 3 (ADR 0005) fulfils the forward commitment ADR 0004 §5 made before
the output guard existed: `resume_approved()` now runs
`app/outputguard.run_output_guard()` — the exact same function
app/main.py's immediate-ALLOW path calls — after its own upstream call and
before completing (SYS-014: "An approved transaction is not exempt from
egress inspection"). An output-guard DENY uses the `RESUMING -> DENIED`
transition already present in `ALLOWED_TRANSITIONS` below (added in Phase 2
for APR-013's ARGUMENTS_CHANGED case) — no new state-machine edge was
needed, so the approval engine itself required no structural change to gain
this, exactly as ADR 0004 §5 predicted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.auth import Identity
from app.db import (
    ApprovalDecisionRow,
    ApprovalRow,
    AuditEventRow,
    TransactionRow,
    immediate_transaction,
)
from app.errors import ErrorCode, FirewallError
from app.ids import new_id
from app.materialargs import compute_material_args_hash
from app.outputguard import run_output_guard, system_prompt_text_from_messages
from app.policy import Policy
from app.providers.base import Provider

_GENESIS_HASH = "sha256:" + hashlib.sha256(b"").hexdigest()

# APR-003: the complete set of permitted transitions (SPEC.md §9.2). Anything
# not listed here is rejected with 409 and MUST NOT mutate the row — this
# table is consulted nowhere for enforcement (each function's own state
# check does that), but is kept here as the single source of truth the
# forbidden-transition test matrix asserts against.
ALLOWED_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
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


def _now() -> datetime:
    """Naive-but-semantically-UTC, deliberately: SQLite (via SQLAlchemy)
    does not preserve tzinfo across a write/read round trip, so a
    tz-aware value created in one request would compare against a naive
    value read back in a later request and raise. Every datetime this
    module stores or compares is UTC by convention; callers formatting one
    for the wire (app/main.py's `_rfc3339`) append the `Z` themselves."""
    return datetime.now(UTC).replace(tzinfo=None)


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def _audit(
    session: Session,
    *,
    approval_id: str,
    transaction_id: str | None,
    correlation_id: str,
    event_type: str,
    actor_type: str,
    actor_id: str,
    payload: dict[str, Any],
) -> None:
    """APR-015 / DAT-005: append an audit event, chained per `approval_id`.
    Tamper-evident, not tamper-proof (DAT-005) — a writer with database
    access can rebuild the chain; SECURITY.md documents that."""
    prev = (
        session.query(AuditEventRow)
        .filter_by(approval_id=approval_id)
        .order_by(AuditEventRow.id.desc())
        .first()
    )
    prev_hash = prev.event_hash if prev is not None else _GENESIS_HASH
    event_hash = (
        "sha256:"
        + hashlib.sha256(prev_hash.encode("utf-8") + _canonical_bytes(payload)).hexdigest()
    )
    session.add(
        AuditEventRow(
            id=new_id("evt"),
            transaction_id=transaction_id,
            approval_id=approval_id,
            correlation_id=correlation_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            payload=payload,
            prev_hash=prev_hash,
            event_hash=event_hash,
            created_at=_now(),
        )
    )


def _transition(row: ApprovalRow, to_state: str) -> None:
    """Raises if (row.state, to_state) is not in ALLOWED_TRANSITIONS —
    belt-and-braces beneath each call site's own explicit state check, so a
    future call site that forgets to check can never silently violate
    APR-001."""
    if (row.state, to_state) not in ALLOWED_TRANSITIONS:
        raise FirewallError(
            ErrorCode.INVALID_APPROVAL_STATE,
            f"Transition {row.state} -> {to_state} is not permitted.",
        )
    row.state = to_state
    row.updated_at = _now()


# ---------------------------------------------------------------------------
# Creation (APR-005, APR-006)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalCreationResult:
    approval: ApprovalRow
    transaction: TransactionRow


def create_approval(
    engine: Engine,
    *,
    transaction_id: str,
    request_id: str,
    correlation_id: str,
    creator_identity_id: str,
    mode: str,
    risk_level: str,
    reason_codes: list[str],
    policy_hits: list[str],
    transformation: str,
    policy_version: str,
    preview_content: dict[str, Any],
    transformed_payload: dict[str, Any],
    material_args_hash: str,
    ttl_seconds: int,
    retain_raw_content: bool,
    raw_request_content: dict[str, Any] | None,
) -> ApprovalCreationResult:
    """APR-005: durably persisted *before* the caller returns 202. Runs
    under BEGIN IMMEDIATE even though there is no prior row to race on here
    — consistent with every other state-changing function in this module,
    and cheap at this write volume."""
    now = _now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    with immediate_transaction(engine) as session:
        txn = TransactionRow(
            id=transaction_id,
            correlation_id=correlation_id,
            identity_id=creator_identity_id,
            request_id=request_id,
            final_verdict="NEED_APPROVAL",
            risk_level=risk_level,
            transformation=transformation,
            policy_version=policy_version,
            mode=mode,
            status="PENDING",
            material_args_hash=material_args_hash,
            request_content=raw_request_content if retain_raw_content else None,
            response_content=None,
            created_at=now,
            completed_at=None,
        )
        approval = ApprovalRow(
            id=new_id("apr"),
            transaction_id=transaction_id,
            state="PENDING",
            risk_level=risk_level,
            reason_codes=reason_codes,
            policy_hits=policy_hits,
            preview_content=preview_content,
            transformed_payload=transformed_payload,
            material_args_hash=material_args_hash,
            creator_identity_id=creator_identity_id,
            resume_attempts=0,
            completion_result=None,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
        )
        session.add(txn)
        session.add(approval)
        session.flush()  # populate FKs / catch constraint errors before the audit row
        _audit(
            session,
            approval_id=approval.id,
            transaction_id=transaction_id,
            correlation_id=correlation_id,
            event_type="APPROVAL_CREATED",
            actor_type="system",
            actor_id="gateway",
            payload={
                "reason_codes": reason_codes,
                "policy_hits": policy_hits,
                "risk_level": risk_level,
                "creator_identity_id": creator_identity_id,
            },
        )
        return ApprovalCreationResult(approval=approval, transaction=txn)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def get_approval(engine: Engine, approval_id: str) -> ApprovalRow | None:
    with Session(engine) as session:
        return session.get(ApprovalRow, approval_id)


def get_approval_by_transaction(engine: Engine, transaction_id: str) -> ApprovalRow | None:
    with Session(engine) as session:
        return session.query(ApprovalRow).filter_by(transaction_id=transaction_id).one_or_none()


def get_transaction(engine: Engine, id_: str) -> TransactionRow | None:
    with Session(engine) as session:
        if id_.startswith("txn_"):
            return session.get(TransactionRow, id_)
        if id_.startswith("req_"):
            return session.query(TransactionRow).filter_by(request_id=id_).one_or_none()
        return None


def list_approvals(
    engine: Engine, *, statuses: list[str] | None, limit: int, cursor: str | None
) -> tuple[list[ApprovalRow], str | None]:
    """API-008: cursor pagination (never offset — "the queue mutates during
    review"). MVP-scale implementation: orders the full matching set in
    Python rather than a keyset-indexed SQL query; fine at this table's
    expected size, and easy to replace with a real keyset query later
    without changing this function's contract."""
    with Session(engine) as session:
        query = session.query(ApprovalRow)
        if statuses:
            query = query.filter(ApprovalRow.state.in_(statuses))
        rows = sorted(query.all(), key=lambda r: (r.created_at, r.id), reverse=True)

    start = 0
    if cursor:
        for i, r in enumerate(rows):
            if r.id == cursor:
                start = i + 1
                break
    page = rows[start : start + limit]
    next_cursor = page[-1].id if start + limit < len(rows) else None
    return page, next_cursor


# ---------------------------------------------------------------------------
# Expiry (APR-006, APR-007, APR-008)
# ---------------------------------------------------------------------------


def sweep_expired(engine: Engine, now: datetime | None = None) -> int:
    """APR-007: transitions elapsed PENDING/APPROVED rows to EXPIRED. Called
    lazily at the top of every approval-reading/deciding request handler
    (main.py) rather than only from a separate timer thread — APR-008 is
    enforced either way, since decide_approval() re-checks expiry itself
    even if a sweep was missed."""
    now = now or _now()
    count = 0
    with immediate_transaction(engine) as session:
        candidates = (
            session.query(ApprovalRow)
            .filter(ApprovalRow.state.in_(["PENDING", "APPROVED"]))
            .filter(ApprovalRow.expires_at <= now)
            .all()
        )
        for approval in candidates:
            from_state = approval.state
            _transition(approval, "EXPIRED")
            session.add(approval)
            txn = session.get(TransactionRow, approval.transaction_id)
            if txn is not None:
                txn.status = "EXPIRED"
                session.add(txn)
            _audit(
                session,
                approval_id=approval.id,
                transaction_id=approval.transaction_id,
                correlation_id=approval.transaction_id,
                event_type="APPROVAL_EXPIRED_SWEEP",
                actor_type="system",
                actor_id="sweeper",
                payload={"from_state": from_state, "to_state": "EXPIRED"},
            )
            count += 1
    return count


# ---------------------------------------------------------------------------
# Decision (APR-001, APR-003, APR-004, APR-008, APR-009, APR-010)
# ---------------------------------------------------------------------------


class DecisionOutcome(StrEnum):
    APPLIED = "applied"
    REPLAYED = "replayed"


@dataclass(frozen=True)
class DecideResult:
    outcome: DecisionOutcome
    approval: ApprovalRow
    decision_row: ApprovalDecisionRow


def decide_approval(
    engine: Engine,
    approval_id: str,
    *,
    decision: str,
    note: str | None,
    reviewer_identity: Identity,
    idempotency_key: str,
    correlation_id: str,
) -> DecideResult:
    now = _now()
    with immediate_transaction(engine) as session:
        existing = (
            session.query(ApprovalDecisionRow)
            .filter_by(idempotency_key=idempotency_key)
            .one_or_none()
        )
        if existing is not None:
            # APR-010: identical key + identical body -> return the original
            # result without re-applying; identical key + different body ->
            # 409 IDEMPOTENCY_CONFLICT.
            if (
                existing.approval_id == approval_id
                and existing.decision == decision
                and (existing.note or None) == (note or None)
            ):
                approval = session.get(ApprovalRow, approval_id)
                assert approval is not None  # the row that created `existing` still exists
                return DecideResult(DecisionOutcome.REPLAYED, approval, existing)
            raise FirewallError(
                ErrorCode.IDEMPOTENCY_CONFLICT,
                "Idempotency-Key was already used with a different request body.",
            )

        approval = session.get(ApprovalRow, approval_id)
        if approval is None:
            raise FirewallError(ErrorCode.APPROVAL_NOT_FOUND, "Unknown approval.")

        # APR-007/008: expiry enforced at decision time even if the sweeper
        # has not run yet.
        if approval.state == "PENDING" and approval.expires_at <= now:
            _transition(approval, "EXPIRED")
            session.add(approval)
            txn = session.get(TransactionRow, approval.transaction_id)
            if txn is not None:
                txn.status = "EXPIRED"
                session.add(txn)
            _audit(
                session,
                approval_id=approval.id,
                transaction_id=approval.transaction_id,
                correlation_id=correlation_id,
                event_type="APPROVAL_EXPIRED_ON_DECISION",
                actor_type="system",
                actor_id="gateway",
                payload={"from_state": "PENDING", "to_state": "EXPIRED"},
            )
            raise FirewallError(ErrorCode.APPROVAL_EXPIRED, "This approval has expired.")

        if approval.state == "EXPIRED":
            # APR-008: "A decision on an expired approval MUST fail closed
            # with 409 APPROVAL_EXPIRED" — regardless of whether *this* call
            # or an earlier sweep/poll is what actually flipped the row.
            raise FirewallError(ErrorCode.APPROVAL_EXPIRED, "This approval has expired.")

        if approval.state != "PENDING":
            raise FirewallError(
                ErrorCode.INVALID_APPROVAL_STATE,
                f"Approval is in state {approval.state}, not PENDING.",
            )

        # APR-009: the identity that created the transaction MUST NOT be
        # able to approve it, even if it also holds a reviewer key.
        if reviewer_identity.identity_id == approval.creator_identity_id:
            raise FirewallError(
                ErrorCode.SELF_APPROVAL_FORBIDDEN,
                "The identity that created this request cannot decide its own approval.",
            )

        if decision == "DENY" and not (note and note.strip()):
            raise FirewallError(
                ErrorCode.INVALID_REQUEST,
                "A non-empty `note` is required when denying an approval.",
                status=422,
            )
        if decision not in ("APPROVE", "DENY"):
            raise FirewallError(
                ErrorCode.INVALID_REQUEST, "`decision` must be APPROVE or DENY.", status=400
            )

        from_state = approval.state
        to_state = "APPROVED" if decision == "APPROVE" else "DENIED"
        _transition(approval, to_state)
        session.add(approval)

        decision_row = ApprovalDecisionRow(
            id=new_id("dec"),
            approval_id=approval_id,
            decision=decision,
            reviewer_id=reviewer_identity.identity_id,
            note=note,
            idempotency_key=idempotency_key,
            from_state=from_state,
            to_state=to_state,
            created_at=now,
        )
        session.add(decision_row)

        txn = session.get(TransactionRow, approval.transaction_id)
        if txn is not None:
            txn.status = to_state
            session.add(txn)

        _audit(
            session,
            approval_id=approval.id,
            transaction_id=approval.transaction_id,
            correlation_id=correlation_id,
            event_type="APPROVAL_DECIDED",
            actor_type="reviewer",
            actor_id=reviewer_identity.identity_id,
            payload={
                "decision": decision,
                "from_state": from_state,
                "to_state": to_state,
                "idempotency_key": idempotency_key,
                "note_present": bool(note),
            },
        )
        return DecideResult(DecisionOutcome.APPLIED, approval, decision_row)


# ---------------------------------------------------------------------------
# Resume worker (APR-011, APR-013, APR-014)
# ---------------------------------------------------------------------------


class ResumeOutcome(StrEnum):
    COMPLETED = "completed"
    DENIED_ARGUMENTS_CHANGED = "denied_arguments_changed"
    DENIED_OUTPUT_GUARD = "denied_output_guard"  # ADR 0005
    NOT_ELIGIBLE = "not_eligible"  # already resumed/expired/etc — safe no-op


async def resume_approved(
    engine: Engine,
    approval_id: str,
    *,
    provider: Provider,
    retain_response_content: bool,
    policy: Policy,
    salt: str,
    detector_timeout_ms: int = 250,
) -> ResumeOutcome:
    """APR-011: the APPROVED -> RESUMING claim is a single atomic
    conditional write; whichever caller wins the BEGIN IMMEDIATE lock is the
    only one that will ever call the provider for this approval. Everything
    after the claim (recomputing the hash, the provider call) happens
    outside that write lock — I/O has no place inside a lock this MVP's
    single SQLite writer already serializes on."""
    now = _now()
    with immediate_transaction(engine) as session:
        approval = session.get(ApprovalRow, approval_id)
        if approval is None or approval.state != "APPROVED":
            return ResumeOutcome.NOT_ELIGIBLE
        if approval.expires_at <= now:
            _transition(approval, "EXPIRED")
            session.add(approval)
            txn = session.get(TransactionRow, approval.transaction_id)
            if txn is not None:
                txn.status = "EXPIRED"
                session.add(txn)
            _audit(
                session,
                approval_id=approval.id,
                transaction_id=approval.transaction_id,
                correlation_id=approval.transaction_id,
                event_type="APPROVAL_EXPIRED_BEFORE_RESUME",
                actor_type="system",
                actor_id="resume_worker",
                payload={"from_state": "APPROVED", "to_state": "EXPIRED"},
            )
            return ResumeOutcome.NOT_ELIGIBLE

        from_state = approval.state
        _transition(approval, "RESUMING")
        approval.resume_attempts += 1
        session.add(approval)
        _audit(
            session,
            approval_id=approval.id,
            transaction_id=approval.transaction_id,
            correlation_id=approval.transaction_id,
            event_type="RESUME_CLAIMED",
            actor_type="system",
            actor_id="resume_worker",
            payload={
                "from_state": from_state,
                "to_state": "RESUMING",
                "attempt": approval.resume_attempts,
            },
        )
        transaction_id = approval.transaction_id
        transformed_payload = dict(approval.transformed_payload)
        stored_hash = approval.material_args_hash

    # APR-013: re-verify outside the write lock — nothing here mutates state.
    recomputed_hash = compute_material_args_hash(
        transformed_payload.get("messages", []), transformed_payload.get("tools")
    )
    if recomputed_hash != stored_hash:
        with immediate_transaction(engine) as session:
            approval = session.get(ApprovalRow, approval_id)
            assert approval is not None
            _transition(approval, "DENIED")
            session.add(approval)
            session.add(
                ApprovalDecisionRow(
                    id=new_id("dec"),
                    approval_id=approval_id,
                    decision="DENY",
                    reviewer_id="system",
                    note="ARGUMENTS_CHANGED",
                    idempotency_key=new_id("idm"),
                    from_state="RESUMING",
                    to_state="DENIED",
                    created_at=_now(),
                )
            )
            txn = session.get(TransactionRow, transaction_id)
            if txn is not None:
                txn.status = "DENIED"
                session.add(txn)
            _audit(
                session,
                approval_id=approval_id,
                transaction_id=transaction_id,
                correlation_id=transaction_id,
                event_type="RESUME_ARGUMENTS_CHANGED",
                actor_type="system",
                actor_id="resume_worker",
                payload={"from_state": "RESUMING", "to_state": "DENIED"},
            )
        return ResumeOutcome.DENIED_ARGUMENTS_CHANGED

    upstream_response = await provider.complete(transformed_payload)

    # SYS-014 / ADR 0004 §5 / ADR 0005: the exact same output guard function
    # app/main.py's immediate-ALLOW path calls, run here before COMPLETED —
    # an approved transaction is not exempt from egress inspection. Outside
    # the write lock, consistent with the upstream call itself.
    resumed_messages = transformed_payload.get("messages", [])
    choices = upstream_response.get("choices") or []
    response_content = ""
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            response_content = message.get("content") or ""
    guard_result = await run_output_guard(
        response_content,
        system_prompt_text_from_messages(resumed_messages),
        policy,
        salt=salt,
        detector_timeout_ms=detector_timeout_ms,
        upstream_response=upstream_response,
    )

    if guard_result.decision.verdict == "DENY":
        with immediate_transaction(engine) as session:
            approval = session.get(ApprovalRow, approval_id)
            assert approval is not None
            _transition(approval, "DENIED")
            session.add(approval)
            session.add(
                ApprovalDecisionRow(
                    id=new_id("dec"),
                    approval_id=approval_id,
                    decision="DENY",
                    reviewer_id="system",
                    note="OUTPUT_GUARD_DENIED",
                    idempotency_key=new_id("idm"),
                    from_state="RESUMING",
                    to_state="DENIED",
                    created_at=_now(),
                )
            )
            txn = session.get(TransactionRow, transaction_id)
            if txn is not None:
                txn.status = "DENIED"
                session.add(txn)
            _audit(
                session,
                approval_id=approval_id,
                transaction_id=transaction_id,
                correlation_id=transaction_id,
                event_type="RESUME_OUTPUT_GUARD_DENIED",
                actor_type="system",
                actor_id="resume_worker",
                payload={
                    "from_state": "RESUMING",
                    "to_state": "DENIED",
                    "reason_codes": list(guard_result.decision.reason_codes),
                },
            )
        return ResumeOutcome.DENIED_OUTPUT_GUARD

    # ALLOW (optionally REDACT-transformed): replace the response's content
    # with the output guard's sanitized version before it is ever persisted
    # or delivered — TRN-006/API-009's "never echo the offending value"
    # applies to the stored completion_result too, not only the wire body.
    sanitized_response = json.loads(json.dumps(upstream_response))  # cheap deep copy
    if choices and isinstance(sanitized_response.get("choices", [None])[0], dict):
        message = sanitized_response["choices"][0].get("message")
        if isinstance(message, dict) and "content" in message:
            message["content"] = guard_result.sanitized_content

    with immediate_transaction(engine) as session:
        approval = session.get(ApprovalRow, approval_id)
        assert approval is not None
        _transition(approval, "COMPLETED")
        approval.completion_result = sanitized_response
        session.add(approval)
        txn = session.get(TransactionRow, transaction_id)
        completed_at = _now()
        if txn is not None:
            txn.status = "COMPLETED"
            txn.completed_at = completed_at
            if retain_response_content:
                txn.response_content = sanitized_response
            session.add(txn)
        _audit(
            session,
            approval_id=approval_id,
            transaction_id=transaction_id,
            correlation_id=transaction_id,
            event_type="RESUME_COMPLETED",
            actor_type="system",
            actor_id="resume_worker",
            payload={
                "from_state": "RESUMING",
                "to_state": "COMPLETED",
                "output_transformation": guard_result.decision.transformation,
            },
        )
    return ResumeOutcome.COMPLETED


# ---------------------------------------------------------------------------
# Startup recovery (APR-014)
# ---------------------------------------------------------------------------


def reconcile_resuming_on_startup(engine: Engine, max_resume_attempts: int) -> int:
    """APR-014: "On startup, the system MUST reconcile every row in
    RESUMING: if the resume attempt count is below MAX_RESUME_ATTEMPTS,
    return it to APPROVED for retry; otherwise move it to FAILED." Returns
    the number of rows reconciled."""
    now = _now()
    count = 0
    with immediate_transaction(engine) as session:
        stuck = session.query(ApprovalRow).filter_by(state="RESUMING").all()
        for approval in stuck:
            if approval.resume_attempts < max_resume_attempts:
                to_state = "APPROVED"
                approval.state = to_state
                approval.updated_at = now
            else:
                # FAILED is not itself one of ALLOWED_TRANSITIONS's drawn
                # edges from RESUMING (SPEC.md §9.2 draws RESUMING only to
                # COMPLETED/DENIED/APPROVED) — APR-014 nonetheless requires
                # it once retries are exhausted, so it is applied directly
                # here rather than through _transition(), and is the one
                # documented exception to the drawn diagram (ADR 0004 §6).
                to_state = "FAILED"
                approval.state = to_state
                approval.updated_at = now
            session.add(approval)
            txn = session.get(TransactionRow, approval.transaction_id)
            if txn is not None:
                txn.status = to_state
                session.add(txn)
            _audit(
                session,
                approval_id=approval.id,
                transaction_id=approval.transaction_id,
                correlation_id=approval.transaction_id,
                event_type="STARTUP_RECONCILE",
                actor_type="system",
                actor_id="startup",
                payload={
                    "from_state": "RESUMING",
                    "to_state": to_state,
                    "resume_attempts": approval.resume_attempts,
                },
            )
            count += 1
    return count
