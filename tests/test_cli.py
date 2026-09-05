"""`python -m app.cli export-audit` tests. SPEC.md §12.4 (PRV-006). Phase 6
(WS-12) — PLAN.md's "export round-trip test."
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.audit import record_decision_event
from app.cli import export_audit_events, main
from app.db import make_engine


def _engine(tmp_path: Path) -> Any:
    return make_engine(f"sqlite:///{tmp_path / 'cli_test.db'}")


def _write_sample_events(engine: Any) -> None:
    record_decision_event(
        engine,
        transaction_id="txn_aaa",
        correlation_id="cor_aaa",
        actor_id="svc_test",
        verdict="ALLOW",
        risk_level="NONE",
        transformation="NONE",
        reason_codes=[],
        policy_hits=[],
        policy_version="sha256:test",
        mode="mock",
        degraded=False,
    )
    record_decision_event(
        engine,
        transaction_id="txn_bbb",
        correlation_id="cor_bbb",
        actor_id="svc_test",
        verdict="DENY",
        risk_level="HIGH",
        transformation="NONE",
        reason_codes=["PROMPT_INJECTION"],
        policy_hits=["deny_prompt_injection"],
        policy_version="sha256:test",
        mode="mock",
        degraded=False,
    )


def test_export_audit_events_returns_a_stable_schema_with_no_content_field(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path)
    _write_sample_events(engine)

    events = export_audit_events(engine)
    assert len(events) == 2
    for event in events:
        assert set(event.keys()) == {
            "id",
            "transaction_id",
            "approval_id",
            "correlation_id",
            "event_type",
            "actor_type",
            "actor_id",
            "payload",
            "prev_hash",
            "event_hash",
            "created_at",
        }
        assert event["event_type"] == "decision"
        # PRV-008: no raw content field exists on this row at all.
        assert "request_content" not in event
        assert "response_content" not in event


def test_export_respects_since_and_until(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    _write_sample_events(engine)

    far_future = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1)
    assert export_audit_events(engine, since=far_future) == []

    far_past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
    assert len(export_audit_events(engine, until=far_past)) == 0
    assert len(export_audit_events(engine, since=far_past)) == 2


def test_export_events_are_hash_chained(tmp_path: Path) -> None:
    """DAT-005: the two `decision` events above are on independent
    transaction_id streams (app/audit.py), each its own single-link chain
    rooted at the genesis hash."""
    engine = _engine(tmp_path)
    _write_sample_events(engine)
    events = export_audit_events(engine)
    genesis = "sha256:" + __import__("hashlib").sha256(b"").hexdigest()
    for event in events:
        assert event["prev_hash"] == genesis
        assert event["event_hash"] != genesis


def test_cli_main_writes_jsonl_to_stdout(
    tmp_path: Path, capsys: Any, monkeypatch: Any
) -> None:
    """`main()` builds its own engine from `load_settings().DATABASE_URL`
    (app/cli.py) rather than taking one as an argument, so this test must
    point that env var at the exact same tmp_path SQLite file `_engine`
    writes to — otherwise `main()` falls back to Settings' real default
    (`sqlite:///./data/realguard.db`) and this test silently exercises a
    completely different, developer-machine-local database instead of the
    two rows it just wrote (ADR 0013: found on the project's first-ever
    fresh checkout, in CI, where no such leftover file exists)."""
    db_url = f"sqlite:///{tmp_path / 'cli_test.db'}"
    monkeypatch.setenv("DATABASE_URL", db_url)
    engine = _engine(tmp_path)
    _write_sample_events(engine)

    rc = main(["export-audit", "--format", "jsonl"])
    assert rc == 0
    out = capsys.readouterr().out
    lines = [line_ for line_ in out.splitlines() if line_.strip()]
    assert len(lines) >= 2
    for line_ in lines:
        json.loads(line_)  # every line is a standalone, valid JSON object


def test_cli_export_audit_round_trip_via_subprocess(tmp_path: Path, monkeypatch: Any) -> None:
    """A genuine `python -m app.cli export-audit` subprocess invocation —
    the actual documented command (PRV-006), not just the Python function
    behind it."""
    db_path = tmp_path / "subprocess_test.db"
    engine = make_engine(f"sqlite:///{db_path}")
    _write_sample_events(engine)

    result = subprocess.run(  # noqa: S603 — fixed argv, no shell, no user input
        [sys.executable, "-m", "app.cli", "export-audit", "--format", "jsonl"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
        env={**__import__("os").environ, "DATABASE_URL": f"sqlite:///{db_path}"},
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    lines = [line_ for line_ in result.stdout.splitlines() if line_.strip()]
    assert len(lines) == 2
    parsed = [json.loads(line_) for line_ in lines]
    assert {e["transaction_id"] for e in parsed} == {"txn_aaa", "txn_bbb"}
