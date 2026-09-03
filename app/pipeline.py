"""Input-plane pipeline: wires the normalizer, detector orchestrator, risk
aggregation and decision engine together. SPEC.md §1.4's architecture
diagram, Phase 2 scope only (ADR 0003) — output guard and tool-call
inspection are Phase 3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.decision import Decision, evaluate_policy
from app.detectors.base import Detector, Finding
from app.detectors.indirect_injection import IndirectInjectionDetector
from app.detectors.pii import PiiDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.secrets import SecretsDetector
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


async def run_input_pipeline(
    messages: list[dict[str, Any]],
    policy: Policy,
    detectors: list[Detector],
    *,
    salt: str,
    detector_timeout_ms: int = 250,
) -> PipelineResult:
    orchestrator = DetectorOrchestrator(detectors, detector_timeout_ms=detector_timeout_ms)
    findings_by_plane: dict[Plane, list[Finding]] = {Plane.input: [], Plane.context: []}
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

    all_findings = tuple(findings_by_plane[Plane.input] + findings_by_plane[Plane.context])
    risk = aggregate_risk(all_findings)

    byte_count = len(json.dumps({"messages": messages}, ensure_ascii=False).encode("utf-8"))

    decision = evaluate_policy(
        policy,
        {plane: tuple(f) for plane, f in findings_by_plane.items()},
        byte_count=byte_count,
        detectors_degraded=degraded,
    )
    return PipelineResult(decision=decision, risk=risk, findings=all_findings, degraded=degraded)
