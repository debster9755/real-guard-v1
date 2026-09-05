"""Generic decision audit events. SPEC.md §2.15, §12.4 (PRV-009), §10
`audit_events`. Phase 6 (WS-12) — see
docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md.

PRV-009: "Every decision MUST produce exactly one audit event of type
`decision`. Not zero, not two." ADR 0004 already writes several
`APPROVAL_*`-typed audit events for the `NEED_APPROVAL` lifecycle, chained
per `approval_id` (its own §4 decision) — those satisfy the approval
workflow's own evidence trail but are a *different* event type from the one
PRV-009 asks for, and are never written at all for the immediate `ALLOW`/
`DENY` paths. `record_decision_event()` below is the one call every verdict
branch in `app/main.py` makes, regardless of which verdict it reached,
giving every transaction exactly one `event_type="decision"` row.

Chaining: DAT-005 requires a hash chain "forming a per-stream chain"
without naming the stream. ADR 0004 chose `approval_id` for the approval
lifecycle; a plain `ALLOW`/`DENY` has no `approval_id` at all, so this
function chains per `transaction_id` instead — a second, independent
tamper-evident stream alongside the approval-lifecycle one, not a
replacement for it. A `NEED_APPROVAL` transaction ends up with both: one
`decision` event on its `transaction_id` stream, and one or more
`APPROVAL_*` events on its `approval_id` stream.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine

from app.db import AuditEventRow, immediate_transaction
from app.ids import new_id

_GENESIS_HASH = "sha256:" + hashlib.sha256(b"").hexdigest()


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def record_decision_event(
    engine: Engine,
    *,
    transaction_id: str,
    correlation_id: str,
    actor_id: str,
    verdict: str,
    risk_level: str,
    transformation: str,
    reason_codes: list[str],
    policy_hits: list[str],
    policy_version: str,
    mode: str,
    degraded: bool,
) -> None:
    """PRV-009: exactly one `event_type="decision"` row per transaction.
    PRV-007/PRV-008: `payload` carries only allowlisted, non-content
    fields — verdict, risk level, transformation, reason/policy-hit ids,
    policy version, mode, degraded — never request or response content."""
    payload = {
        "verdict": verdict,
        "risk_level": risk_level,
        "transformation": transformation,
        "reason_codes": sorted(reason_codes),
        "policy_hits": sorted(policy_hits),
        "policy_version": policy_version,
        "mode": mode,
        "degraded": degraded,
    }
    with immediate_transaction(engine) as session:
        prev = (
            session.query(AuditEventRow)
            .filter_by(transaction_id=transaction_id, approval_id=None)
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
                approval_id=None,
                correlation_id=correlation_id,
                event_type="decision",
                actor_type="service",
                actor_id=actor_id,
                payload=payload,
                prev_hash=prev_hash,
                event_hash=event_hash,
                created_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
