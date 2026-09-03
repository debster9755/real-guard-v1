"""The golden-corpus runner. SPEC.md §17.3/17.4 (TST-023), PLAN.md §9.2.

Phase 2 scope (ADR 0003): exercises the six input-plane buckets — BENIGN,
DIRECT_INJECTION, INDIRECT_INJECTION, ENCODED_INJECTION, PII_INPUT,
SECRET_INPUT (42 of 54 cases). TOOL_ABUSE, OUTPUT_LEAKAGE and LEAK_OUTPUT
(12 cases) are explicitly skipped with a reason, not silently absent — the
54-case *file* stays the single source of truth (validated whole by
scripts/validate_contracts.py and test_policy.py), while this runner is
honest about what it currently exercises end to end.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.pipeline import build_input_detectors, run_input_pipeline
from app.policy import load_policy

_CORPUS_PATH = Path(__file__).parent / "data" / "golden_corpus.jsonl"

_IN_SCOPE_CATEGORIES = {
    "BENIGN",
    "DIRECT_INJECTION",
    "INDIRECT_INJECTION",
    "ENCODED_INJECTION",
    "PII_INPUT",
    "SECRET_INPUT",
}
_DEFERRED_CATEGORIES = {"TOOL_ABUSE", "OUTPUT_LEAKAGE", "LEAK_OUTPUT"}


def _load_corpus() -> list[dict]:
    with open(_CORPUS_PATH) as f:
        return [json.loads(line) for line in f]


_ALL_CASES = _load_corpus()
_POLICY = load_policy("policies/default_policy.yaml")
_DETECTORS = build_input_detectors(_POLICY)


def _case_id(case: dict) -> str:
    return str(case["case_id"])


@pytest.mark.parametrize("case", _ALL_CASES, ids=_case_id)
async def test_golden_corpus_case(case: dict) -> None:
    if case["category"] in _DEFERRED_CATEGORIES:
        pytest.skip(f"{case['category']} — Phase 3/4, see ADR 0003")

    result = await run_input_pipeline(
        case["payload"]["messages"], _POLICY, _DETECTORS, salt="corpus-test-salt"
    )
    decision = result.decision

    assert decision.verdict == case["expected_verdict"], (
        f"{case['case_id']}: verdict {decision.verdict} != {case['expected_verdict']}"
    )
    assert decision.transformation == case["expected_transformation"], (
        f"{case['case_id']}: transformation {decision.transformation} != "
        f"{case['expected_transformation']}"
    )

    got_reasons = set(decision.reason_codes)
    exp_reasons = set(case["expected_reason_codes"])
    assert got_reasons == exp_reasons, (
        f"{case['case_id']}: reason_codes {got_reasons} != {exp_reasons}"
    )

    got_hits = {h.rule_id for h in decision.policy_hits if h.verdict == decision.verdict}
    exp_hits = set(case["expected_policy_hits"])
    assert got_hits == exp_hits, f"{case['case_id']}: policy_hits {got_hits} != {exp_hits}"


def test_corpus_meta_exactly_54_cases_in_scope_and_deferred() -> None:
    """TST-023 lives in scripts/validate_contracts.py and test_policy.py
    already; this is a narrower Phase-2-specific check that the in-scope /
    deferred split accounts for every case with no gaps or overlaps."""
    in_scope = [c for c in _ALL_CASES if c["category"] in _IN_SCOPE_CATEGORIES]
    deferred = [c for c in _ALL_CASES if c["category"] in _DEFERRED_CATEGORIES]
    assert len(in_scope) == 42, f"expected 42 in-scope cases, got {len(in_scope)}"
    assert len(deferred) == 12, f"expected 12 deferred cases, got {len(deferred)}"
    assert len(in_scope) + len(deferred) == 54
