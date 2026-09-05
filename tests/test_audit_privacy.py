"""TST-013 / PRV-004 (SPEC.md §12.3, §17.1): "A test MUST run every PII and
secret corpus case with logging at DEBUG and assert that no original value
appears anywhere in captured output." Phase 6 (WS-12) — the "audit-privacy
grep test" PLAN.md's Phase 6 automated checks name explicitly.

Runs every `PII_INPUT`/`SECRET_INPUT`/`OUTPUT_LEAKAGE`/`LEAK_OUTPUT` golden-
corpus case (18 of the 54) at `LOG_LEVEL=DEBUG`, captures the process's
real stdout (app/logging_config.py's `AllowlistJsonFormatter` writes there —
this test does not use `caplog`, since the allowlist filtering it exists to
prove only actually runs on that formatter, not on pytest's own capture
handler), and asserts that neither the literal request content nor any of
`TST-021`'s known seeded raw values ever appears in it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_CORPUS_PATH = Path(__file__).parent / "data" / "golden_corpus.jsonl"
_PRIVACY_CATEGORIES = {"PII_INPUT", "SECRET_INPUT", "OUTPUT_LEAKAGE", "LEAK_OUTPUT"}

# TST-021: the mock provider's seeded raw values for output-plane cases —
# never present in the *request* payload verbatim (only the trigger token
# is), so they must be checked for separately.
_SEEDED_RAW_VALUES = (
    "123-45-6789",
    "dana.reyes@example.com",
    "sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c",
    "RG-CANARY-7F3A9C",
)


def _load_privacy_cases() -> list[dict[str, object]]:
    cases = []
    for line in _CORPUS_PATH.read_text().splitlines():
        case = json.loads(line)
        if case["category"] in _PRIVACY_CATEGORIES:
            cases.append(case)
    return cases


_CASES = _load_privacy_cases()


def test_corpus_has_the_expected_privacy_case_count() -> None:
    # 6 PII_INPUT + 4 SECRET_INPUT + 4 OUTPUT_LEAKAGE + 4 LEAK_OUTPUT = 18
    # (PLAN.md §9.3's distribution) — a meta-check that this test is
    # actually exercising the cases TST-013 names, not an empty list.
    assert len(_CASES) == 18


def test_no_original_pii_or_secret_value_appears_in_debug_logs(
    client_factory: Callable[..., TestClient],
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = client_factory(LOG_LEVEL="DEBUG")

    for case in _CASES:
        client.post("/v1/chat/completions", json=case["payload"])

    captured = capsys.readouterr().out

    for case in _CASES:
        message = case["payload"]["messages"][0]  # type: ignore[index]
        content = message["content"]  # type: ignore[index]
        assert content not in captured, (
            f"{case['case_id']}: original request content leaked into DEBUG logs"
        )

    for raw_value in _SEEDED_RAW_VALUES:
        assert raw_value not in captured, f"seeded raw value {raw_value!r} leaked into DEBUG logs"
