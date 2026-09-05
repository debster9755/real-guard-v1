"""Structured JSON logging. SPEC.md §12.2/§12.3 (PRV-007, PRV-008), OBS-004.
Phase 6 (WS-12) — see
docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md.

OBS-004: "Logs MUST be JSON on stdout, one object per line, at LOG_LEVEL,
filtered through the PRV-007 allowlist." PRV-007: "the allowlist is
enforced by code rather than by convention." `_ALLOWLIST_FIELDS` below is
copied verbatim from SPEC.md §12.2's field list; `AllowlistJsonFormatter`
drops any `extra=` field a log call supplies that isn't in it — a future
call site that adds `extra={"raw_content": ...}` by mistake gets that field
silently dropped from the emitted line, not raised as an error (a logging
call must never itself become a new way to crash a request), but
`tests/test_audit_privacy.py` exercises the golden corpus's PII/secret
cases at DEBUG and asserts no original value survives into captured
output regardless.

This module governs stdout log *lines*; it has no relationship to
`audit_events` (app/audit.py, app/approvals.py) or `/metrics`
(app/metrics.py) — those are separate PRV-007/PRV-008-respecting outputs.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

# SPEC.md §12.2, verbatim.
_ALLOWLIST_FIELDS: frozenset[str] = frozenset(
    {
        "transaction_id",
        "correlation_id",
        "request_id",
        "approval_id",
        "identity_key_id",
        "reviewer_id",
        "verdict",
        "risk_level",
        "transformation",
        "reason_codes",
        "policy_hits",
        "policy_version",
        "detector_id",
        "detector_version",
        "category",
        "score",
        "confidence",
        "match_count",
        "plane",
        "duration_ms",
        "status_code",
        "error_code",
        "mode",
        "degraded",
        "state_from",
        "state_to",
        "content_hash",
    }
)

# LogRecord attributes present on every record regardless of `extra=`, which
# are therefore never mistaken for an allowlist violation.
_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys())


class AllowlistJsonFormatter(logging.Formatter):
    """One JSON object per line: `timestamp`, `level`, `event` (the log
    message — PRV-008 requires every call site to keep raw content out of
    the message text itself; this formatter cannot see inside a string),
    plus any `extra=` field that is in `_ALLOWLIST_FIELDS`. Anything else
    passed via `extra=` is dropped, not raised — PRV-007's "enforced by
    code" without turning a logging call into a new failure mode."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_ATTRS:
                continue
            if key in _ALLOWLIST_FIELDS:
                payload[key] = value
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging(level: str) -> None:
    """Attaches one stdout handler to the `realguard` logger, replacing any
    handler a prior call attached — idempotent across the repeated
    `AppState()` construction `tests/conftest.py`'s `client_factory` does
    within one test session. `propagate` is deliberately left at its
    default (`True`): pytest's `caplog` fixture captures via the root
    logger, and existing tests (e.g. `test_gateway.py`'s mock-mode-warning
    assertion) rely on records reaching it. In a real deployment nothing
    else attaches a root handler, so this handler's stdout line is the only
    one that gets written."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(AllowlistJsonFormatter())

    logger = logging.getLogger("realguard")
    logger.handlers = [handler]
    logger.setLevel(level)
