"""The golden-corpus runner. SPEC.md §17.3/17.4 (TST-023), PLAN.md §9.2.

Phase 2 (ADR 0003) exercised the six input-plane buckets end to end:
BENIGN, DIRECT_INJECTION, INDIRECT_INJECTION, ENCODED_INJECTION, PII_INPUT,
SECRET_INPUT (42 of 54 cases) — those cases resolve entirely on the input
plane (`app/pipeline.run_input_pipeline`), so they still exercise exactly
that function, unchanged.

Phase 3 (ADR 0005) adds the remaining 12 cases:

- `TOOL_ABUSE` (4 cases, direction INPUT) resolves entirely on the input
  plane too — a DENY/NEED_APPROVAL from a tool-call rule never reaches an
  upstream call (SYS-002/APR-002) — so these also go through
  `run_input_pipeline` directly, now with `tools=` populated.
- `OUTPUT_LEAKAGE`/`LEAK_OUTPUT` (8 cases, direction OUTPUT) need the full
  request lifecycle: the input pipeline ALLOWs, the deterministic
  MockProvider is actually called (these cases exist specifically to drive
  its TST-021/022 trigger tokens), and the response goes through
  `app/outputguard.run_output_guard` — `_run_full_pipeline` below composes
  exactly those three calls, mirroring app/main.py's own composition
  (ADR 0004 §5 / ADR 0005: one shared output-guard function, not a
  test-only reimplementation of it).

No case is silently skipped any more — the 54-case *file* and the *runner*
now agree exactly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from app.decision import Decision, combine_decisions
from app.outputguard import run_output_guard, system_prompt_text_from_messages
from app.pipeline import build_input_detectors, run_input_pipeline
from app.policy import load_policy
from app.providers.mock import MockProvider
from app.transform import apply_transformation_to_messages

_CORPUS_PATH = Path(__file__).parent / "data" / "golden_corpus.jsonl"

_IN_SCOPE_CATEGORIES = {
    "BENIGN",
    "DIRECT_INJECTION",
    "INDIRECT_INJECTION",
    "ENCODED_INJECTION",
    "PII_INPUT",
    "SECRET_INPUT",
    "TOOL_ABUSE",
}
_OUTPUT_CATEGORIES = {"OUTPUT_LEAKAGE", "LEAK_OUTPUT"}


def _load_corpus() -> list[dict[str, Any]]:
    with open(_CORPUS_PATH) as f:
        return [json.loads(line) for line in f]


_ALL_CASES = _load_corpus()
_POLICY = load_policy("policies/default_policy.yaml")
_DETECTORS = build_input_detectors(_POLICY)
_SALT = "corpus-test-salt"


def _case_id(case: dict[str, Any]) -> str:
    return str(case["case_id"])


async def _run_full_pipeline(case: dict[str, Any]) -> Decision:
    """Input pipeline -> (if ALLOW) MockProvider -> output guard ->
    combine_decisions — the same three-call composition app/main.py's
    ALLOW branch uses, built here directly rather than through HTTP/
    TestClient so the corpus runner stays a fast, dependency-free unit
    test of the pipeline functions themselves."""
    messages = case["payload"]["messages"]
    tools = case["payload"].get("tools")

    input_result = await run_input_pipeline(messages, _POLICY, _DETECTORS, salt=_SALT, tools=tools)
    input_decision = input_result.decision
    if input_decision.verdict != "ALLOW":
        # SYS-002/APR-002: a DENY or NEED_APPROVAL input verdict never
        # reaches an upstream call, so there is no response to guard.
        return input_decision

    forward_messages = apply_transformation_to_messages(messages, input_decision.transformation)
    forward_body: dict[str, Any] = {"messages": forward_messages}
    if tools is not None:
        forward_body["tools"] = tools
    upstream_response = await MockProvider().complete(forward_body)

    response_content = ""
    choices = upstream_response.get("choices") or []
    if choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            response_content = message.get("content") or ""

    guard_result = await run_output_guard(
        response_content,
        system_prompt_text_from_messages(forward_messages),
        _POLICY,
        salt=_SALT,
        upstream_response=upstream_response,
    )
    return combine_decisions((input_decision, guard_result.decision))


@pytest.mark.parametrize("case", _ALL_CASES, ids=_case_id)
async def test_golden_corpus_case(case: dict[str, Any]) -> None:
    if case["category"] in _OUTPUT_CATEGORIES:
        decision = await _run_full_pipeline(case)
    else:
        result = await run_input_pipeline(
            case["payload"]["messages"],
            _POLICY,
            _DETECTORS,
            salt=_SALT,
            tools=case["payload"].get("tools"),
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


def test_corpus_meta_exactly_54_cases_fully_in_scope() -> None:
    """TST-023 lives in scripts/validate_contracts.py and test_policy.py
    already; this is a narrower check that every one of the 54 cases is now
    exercised by test_golden_corpus_case above — no category is skipped
    (ADR 0005 closes the gap ADR 0003 opened for Phase 2)."""
    in_scope = [
        c for c in _ALL_CASES if c["category"] in (_IN_SCOPE_CATEGORIES | _OUTPUT_CATEGORIES)
    ]
    assert len(in_scope) == 54, f"expected all 54 cases in scope, got {len(in_scope)}"
    assert len(_ALL_CASES) == 54
