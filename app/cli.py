"""`python -m app.cli export-audit`. SPEC.md §12.4 (PRV-006). Phase 6 (WS-12)
— see docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md.

PRV-006: "The system MUST provide `python -m app.cli export-audit --since
... --until ... --format jsonl`, emitting one JSON object per line with a
stable schema, honouring the active retention mode."

"Honouring the active retention mode": `audit_events.payload` is
constructed, at every write site (app/audit.py, app/approvals.py's
`_audit()`), from PRV-007-allowlisted fields only — verdicts, risk levels,
reason/policy-hit ids, state transitions — and never from a
`CONTENT_RETENTION`-classified column (`transactions.request_content`,
`approvals.preview_content`, etc). Exporting `audit_events` verbatim is
therefore safe under every retention mode without this command needing its
own redaction pass; `CONTENT_RETENTION` governs what the *rest* of the
database stores, not what this table ever contained in the first place.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.config import load_settings
from app.db import AuditEventRow, make_engine


def _parse_timestamp(value: str) -> datetime:
    """Accepts API-005's RFC 3339 `Z`-suffixed form (what every other part of
    this system emits) as well as a bare ISO 8601 string."""
    stripped = value.strip()
    if stripped.endswith("Z"):
        stripped = stripped[:-1]
    return datetime.fromisoformat(stripped)


def export_audit_events(
    engine: Engine, *, since: datetime | None = None, until: datetime | None = None
) -> list[dict[str, Any]]:
    """Returns audit events ordered oldest-first, ready to be written one
    JSON object per line — the actual query and shape `export-audit` uses,
    factored out so a test can call it directly without a subprocess."""
    with Session(engine) as session:
        query = select(AuditEventRow).order_by(
            AuditEventRow.created_at.asc(), AuditEventRow.id.asc()
        )
        if since is not None:
            query = query.where(AuditEventRow.created_at >= since)
        if until is not None:
            query = query.where(AuditEventRow.created_at <= until)
        rows = session.execute(query).scalars().all()

    return [
        {
            "id": row.id,
            "transaction_id": row.transaction_id,
            "approval_id": row.approval_id,
            "correlation_id": row.correlation_id,
            "event_type": row.event_type,
            "actor_type": row.actor_type,
            "actor_id": row.actor_id,
            "payload": row.payload,
            "prev_hash": row.prev_hash,
            "event_hash": row.event_hash,
            "created_at": row.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for row in rows
    ]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subparsers = parser.add_subparsers(dest="command", required=True)

    export = subparsers.add_parser("export-audit", help="Export audit_events as JSONL (PRV-006).")
    export.add_argument("--since", type=_parse_timestamp, default=None)
    export.add_argument("--until", type=_parse_timestamp, default=None)
    export.add_argument("--format", choices=["jsonl"], default="jsonl")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "export-audit":
        settings = load_settings()
        engine = make_engine(settings.DATABASE_URL)
        for event in export_audit_events(engine, since=args.since, until=args.until):
            sys.stdout.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        return 0

    return 1  # unreachable: argparse's `required=True` refuses an unknown command


if __name__ == "__main__":
    raise SystemExit(main())
