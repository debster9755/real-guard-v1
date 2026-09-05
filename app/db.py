"""Persistence layer. SPEC.md §10 (DAT-001..006), §2.20.

ADR 0004 scoped the first cut of this module to exactly what the approval
workflow needed to be real rather than a stub: `transactions` (written only
for requests that reach `NEED_APPROVAL` — ADR 0004 §2), `approvals`,
`approval_decisions`, and `audit_events`. Phase 6 (ADR 0008, WS-13) adds
`rate_limit_state` — the one remaining SPEC.md §10 table that phase's exit
gate actually requires. `detector_findings`, `policy_hits` (as a table —
still carried as JSON on `approvals`), `idempotency_records`, and
`encrypted_payloads` remain deferred: no automated check in PLAN.md's Phase
6 section requires them, and nothing here forecloses adding them later,
since SQLAlchemy models and Alembic migrations are additive.

SQLite in WAL mode (D7). Alembic migration scaffolding is deferred (ADR
0004 §2) — this MVP has no prior deployment to migrate from, so
`Base.metadata.create_all()` is sufficient until a real upgrade path is
needed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Engine,
    Index,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class TransactionRow(Base):
    """SPEC.md §10 `transactions`, scoped per ADR 0004 §2: a row is written
    only when the verdict is NEED_APPROVAL. ALLOW/DENY paths remain exactly
    as tested in Phase 2 — no DB dependency was introduced there."""

    __tablename__ = "transactions"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # txn_
    correlation_id: Mapped[str] = mapped_column(String)
    identity_id: Mapped[str] = mapped_column(String)
    request_id: Mapped[str] = mapped_column(String, unique=True)  # req_
    final_verdict: Mapped[str] = mapped_column(String)
    risk_level: Mapped[str] = mapped_column(String)
    transformation: Mapped[str] = mapped_column(String)
    policy_version: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)  # mirrors the approval's state
    material_args_hash: Mapped[str] = mapped_column(String)
    # DAT-003: SENSITIVE, nullable, written only when CONTENT_RETENTION
    # permits it (app/approvals.py create_approval()/resume_approved()).
    request_content: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    response_content: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ApprovalRow(Base):
    """SPEC.md §10 `approvals`, §9 state machine.

    `creator_identity_id` and `completion_result` are additive fields beyond
    SPEC's explicit column list (ADR 0004 §3): the former is required to
    enforce APR-009 (self-approval forbidden); the latter is required so the
    poll endpoint can deliver the completed result at all when
    CONTENT_RETENTION=metadata (the default) — see ADR 0004 §3 for why this
    is kept independent of the audit-retention columns on `transactions`.
    """

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # apr_
    transaction_id: Mapped[str] = mapped_column(String, unique=True)
    state: Mapped[str] = mapped_column(String)
    risk_level: Mapped[str] = mapped_column(String)
    reason_codes: Mapped[list[str]] = mapped_column(JSON)
    policy_hits: Mapped[list[str]] = mapped_column(JSON)
    preview_content: Mapped[dict[str, Any]] = mapped_column(JSON)  # transformed only, APR-012
    transformed_payload: Mapped[dict[str, Any]] = mapped_column(JSON)  # TRN-009 resume payload
    material_args_hash: Mapped[str] = mapped_column(String)
    creator_identity_id: Mapped[str] = mapped_column(String)
    resume_attempts: Mapped[int] = mapped_column(Integer, default=0)
    completion_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class ApprovalDecisionRow(Base):
    """SPEC.md §10 `approval_decisions`. DAT-004: append-only — no UPDATE or
    DELETE path exists anywhere in app/approvals.py."""

    __tablename__ = "approval_decisions"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # dec_
    approval_id: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)  # APPROVE / DENY
    reviewer_id: Mapped[str] = mapped_column(String)
    note: Mapped[str | None] = mapped_column(String, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String, unique=True)
    from_state: Mapped[str] = mapped_column(String)
    to_state: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class AuditEventRow(Base):
    """SPEC.md §10 `audit_events`. DAT-005: append-only, tamper-evident hash
    chain — chained per `approval_id` (ADR 0004 §4 explains the choice)."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # evt_
    transaction_id: Mapped[str | None] = mapped_column(String, nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String, nullable=True)
    correlation_id: Mapped[str] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String)
    actor_type: Mapped[str] = mapped_column(String)
    actor_id: Mapped[str] = mapped_column(String)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String)
    event_hash: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime)


class RateLimitStateRow(Base):
    """SPEC.md §10 `rate_limit_state`. Phase 6 / ADR 0008 (WS-13).

    A fixed-window counter, not a true sliding log: `window_start` is the
    aligned start of the current window (`floor(now / window_seconds) *
    window_seconds`) and `request_count` is the number of requests admitted
    in that window for that identity. This is the shape SPEC.md's own
    column list dictates (`window_start`, `request_count` — a sliding-log
    implementation would instead need one row per request, which the
    schema does not provide for), even though WS-13's prose calls the
    limiter "sliding-window" — ADR 0008 documents this literal reading.

    `(identity_id, window_start)` unique — one row per identity per window,
    updated in place by `app/ratelimit.py` under the same `BEGIN IMMEDIATE`
    discipline `app/db.py.immediate_transaction()` already gives the
    approval workflow (APR-004's reasoning applies identically here: two
    concurrent requests for the same identity must never both read the
    same pre-increment count)."""

    __tablename__ = "rate_limit_state"

    id: Mapped[str] = mapped_column(String, primary_key=True)  # rlm_
    identity_id: Mapped[str] = mapped_column(String)
    window_start: Mapped[datetime] = mapped_column(DateTime)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime)

    __table_args__ = (
        UniqueConstraint("identity_id", "window_start", name="uq_rate_limit_identity_window"),
        Index("ix_rate_limit_window_start", "window_start"),
    )


def _enable_wal(dbapi_connection: Any, _connection_record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """`sqlite:///./data/realguard.db` fails to connect if `./data/` does not
    exist yet — a fresh checkout has no `data/` directory. In-memory URLs
    (`sqlite:///:memory:`, `sqlite://`) have no filesystem path to create."""
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        return
    path_part = database_url[len(prefix) :]
    if path_part in ("", ":memory:"):
        return
    Path(path_part).resolve().parent.mkdir(parents=True, exist_ok=True)


def make_engine(database_url: str) -> Engine:
    _ensure_sqlite_parent_dir(database_url)
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    if database_url.startswith("sqlite"):
        event.listen(engine, "connect", _enable_wal)
    Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def immediate_transaction(engine: Engine) -> Iterator[Session]:
    """APR-004: every approval state transition MUST be a single atomic
    write guarded by the expected current state, executed under `BEGIN
    IMMEDIATE` — SQLite's single-writer lock, taken up front rather than
    optimistically, so two concurrent decisions on the same approval can
    never both believe they read a PENDING row (APR-011's exactly-once
    resume claim depends on the same primitive).
    """
    connection = engine.connect()
    raw = connection.connection
    try:
        cursor = raw.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.close()
        session = Session(bind=connection, expire_on_commit=False)
        try:
            yield session
            session.commit()
            raw.commit()
        except BaseException:
            session.rollback()
            raw.rollback()
            raise
        finally:
            session.close()
    finally:
        connection.close()
