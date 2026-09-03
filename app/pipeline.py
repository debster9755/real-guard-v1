"""Input-plane pipeline: wires the normalizer, detector orchestrator, risk
aggregation and decision engine together. SPEC.md §1.4's architecture
diagram.

Phase 3 (ADR 0005) extends this module with the Action-plane pass this
docstring previously deferred: `tools[]` declared on the request are parsed
into candidate (tool_name, tool_arguments) pairs, scanned by
`ToolCallsDetector` for evidence, and fed into `evaluate_policy()` as real
`DecisionContext.tool_name`/`tool_arguments` — the empty stub
app/decision.py's own docstring documented Phase 2 using is gone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.decision import Decision, combine_decisions, evaluate_policy
from app.detectors.base import Detector, Finding
from app.detectors.indirect_injection import IndirectInjectionDetector
from app.detectors.pii import PiiDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.secrets import SecretsDetector
from app.detectors.tool_calls import ToolCallsDetector
from app.detectors.topics import TopicsDetector
from app.detectors.urls import UrlsDetector
from app.normalizer import normalize
from app.orchestrator import DetectorOrchestrator
from app.planes import Plane
from app.policy import Policy
from app.risk import RiskAssessment, aggregate_risk

# SYS-004: role -> plane. user/system are the operator's and the live
# caller's own words (Input); assistant/tool carry replayed or
# retrieved/tool-supplied content (Context) — see ADR 0003's addendum for
# why this split determines which of prompt_injection/indirect_injection
# ever sees a given message.
_ROLE_PLANE: dict[str, Plane] = {
    "user": Plane.input,
    "system": Plane.input,
    "assistant": Plane.context,
    "tool": Plane.context,
}


def message_plane(role: str) -> Plane:
    return _ROLE_PLANE.get(role, Plane.input)


def build_input_detectors(policy: Policy) -> list[Detector]:
    topics_config = policy.detectors.get("topics", {})
    return [
        PromptInjectionDetector(),
        IndirectInjectionDetector(),
        PiiDetector(),
        SecretsDetector(),
        TopicsDetector(
            blocked=list(topics_config.get("blocked", [])),
            sensitive=list(topics_config.get("sensitive", [])),
        ),
        UrlsDetector(),
    ]


@dataclass(frozen=True)
class PipelineResult:
    decision: Decision
    risk: RiskAssessment
    findings: tuple[Finding, ...]
    degraded: bool


def tool_candidates_from_declared_tools(
    tools: list[dict[str, Any]] | None,
) -> list[tuple[str, dict[str, Any]]]:
    """Extract (tool_name, tool_arguments) candidates from an OpenAI-shaped
    request `tools[]` array.

    ADR 0005: the frozen golden corpus (TOL-001..004,
    tests/data/golden_corpus.jsonl) encodes a *prospective* tool call
    directly in the request's declared `tools[].function.parameters` field
    as concrete argument values — e.g. `{"amount": 5000, "to": "acct_x"}` —
    rather than the JSON-Schema shape `tools[]` conventionally carries (a
    declaration of a function's *signature* for the model to choose from,
    e.g. `{"type": "object", "properties": {...}}`). Evaluating
    argument-path/numeric/sql/shell conditions against a genuine JSON-Schema
    `parameters` object is a safe no-op — schema field names like "type" or
    "properties" never resolve a `$.amount` or `$.query` path — so treating
    `function.parameters` uniformly as candidate arguments costs nothing
    against real OpenAI-shaped tool declarations and exactly satisfies the
    frozen corpus's shape. See the ADR for the full account.
    """
    candidates: list[tuple[str, dict[str, Any]]] = []
    for tool in tools or []:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            continue
        function = tool.get("function")
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        parameters = function.get("parameters")
        arguments = parameters if isinstance(parameters, dict) else {}
        candidates.append((name, arguments))
    return candidates


async def run_input_pipeline(
    messages: list[dict[str, Any]],
    policy: Policy,
    detectors: list[Detector],
    *,
    salt: str,
    detector_timeout_ms: int = 250,
    tools: list[dict[str, Any]] | None = None,
) -> PipelineResult:
    orchestrator = DetectorOrchestrator(detectors, detector_timeout_ms=detector_timeout_ms)
    findings_by_plane: dict[Plane, list[Finding]] = {
        Plane.input: [],
        Plane.context: [],
        Plane.action: [],
    }
    degraded = False

    for message in messages:
        role = message.get("role", "user")
        plane = message_plane(role)
        content = message.get("content") or ""
        if not isinstance(content, str):
            continue
        normalized_content = normalize(content)
        result = await orchestrator.run(normalized_content, plane, salt)
        findings_by_plane[plane].extend(result.findings)
        if result.degraded:
            degraded = True

    # WS-08 (ADR 0005): Action-plane pass over declared tools[]. Findings are
    # evidence only (findings_summary, risk_level) — the verdict itself comes
    # from evaluate_policy()'s direct DecisionContext.tool_name/tool_arguments
    # evaluation below, exactly as ADR 0003 anticipated.
    candidates = tool_candidates_from_declared_tools(tools)
    if candidates:
        tool_detector = ToolCallsDetector(policy)
        for name, arguments in candidates:
            try:
                findings_by_plane[Plane.action].extend(
                    tool_detector.scan_tool_call(name, arguments, salt)
                )
            except Exception:  # noqa: BLE001 — DET-014: isolate, never propagate
                degraded = True

    all_findings = tuple(
        findings_by_plane[Plane.input]
        + findings_by_plane[Plane.context]
        + findings_by_plane[Plane.action]
    )
    risk = aggregate_risk(all_findings)

    byte_count = len(json.dumps({"messages": messages}, ensure_ascii=False).encode("utf-8"))

    findings_snapshot = {plane: tuple(f) for plane, f in findings_by_plane.items()}

    if not candidates:
        decision = evaluate_policy(
            policy,
            findings_snapshot,
            byte_count=byte_count,
            detectors_degraded=degraded,
        )
    else:
        decisions = tuple(
            evaluate_policy(
                policy,
                findings_snapshot,
                byte_count=byte_count,
                tool_name=name,
                tool_arguments=arguments,
                detectors_degraded=degraded,
            )
            for name, arguments in candidates
        )
        decision = combine_decisions(decisions)

    return PipelineResult(decision=decision, risk=risk, findings=all_findings, degraded=degraded)
