"""Output guard. SPEC.md §2.11 (output guard), §6.4 (`system_prompt_leak`),
SYS-006, SYS-014.

The single function both the immediate-ALLOW path (app/main.py, after the
upstream call) and the approval-resume path (app/approvals.py's
`resume_approved()`, after its own upstream call) invoke — ADR 0004 §5's
forward commitment made exactly this promise before this module existed:
"When Phase 3's output guard lands, it runs identically on both paths via
one shared function — no change to the state machine." `run_output_guard()`
is that function; see docs/adr/0005-phase3-output-guard-and-tool-call-inspection.md
for the account of every judgment call in it.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Any

from app.decision import Decision, evaluate_policy
from app.detectors.base import Detector, Finding
from app.detectors.pii import PiiDetector
from app.detectors.secrets import SecretsDetector
from app.detectors.system_prompt_leak import SystemPromptLeakDetector
from app.detectors.tool_calls import ToolCallsDetector
from app.normalizer import normalize
from app.orchestrator import DetectorOrchestrator
from app.planes import Plane
from app.policy import Policy
from app.risk import RiskAssessment, aggregate_risk
from app.transform import apply_transformations


def build_output_detectors(policy: Policy) -> list[Detector]:
    """PII_DETECTED/SECRET_DETECTED's inbound detectors, reused unmodified
    on the Response plane — both already emit OUTPUT_PII/OUTPUT_SECRET when
    `plane == Plane.response` (app/detectors/pii.py, app/detectors/
    secrets.py), built in Phase 2 specifically "ready for this phase" per
    the Phase 3 task brief."""
    return [PiiDetector(), SecretsDetector()]


def build_system_prompt_leak_detector(policy: Policy) -> SystemPromptLeakDetector:
    cfg = policy.detectors.get("system_prompt_leak", {})
    return SystemPromptLeakDetector(canaries=list(cfg.get("canaries", [])))


def system_prompt_text_from_messages(messages: list[dict[str, Any]]) -> str:
    """The system prompt actually forwarded upstream — callers pass the
    *post-input-transformation* messages (what the model actually saw), not
    the client's raw original, so a leak comparison can never produce a
    false negative because input-plane REDACT already changed the system
    message's text before the model ever received it."""
    for m in messages:
        if isinstance(m, dict) and m.get("role") == "system":
            content = m.get("content")
            if isinstance(content, str):
                return content
    return ""


def _first_response_tool_call(upstream_response: dict[str, Any]) -> tuple[str, str] | None:
    """Returns (tool_name, raw_arguments_json_string) for the first tool
    call in the response's first choice, or None — SPEC.md §2.12's
    "outbound tool_calls[]" half of the tool-call guard's inputs. Only the
    first is inspected: no golden-corpus case or realistic mock-provider
    response emits more than one, and DET-016/017's rules are the same
    regardless of position."""
    choices = upstream_response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    tool_calls = message.get("tool_calls")
    if not isinstance(tool_calls, list) or not tool_calls or not isinstance(tool_calls[0], dict):
        return None
    function = tool_calls[0].get("function")
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    arguments = function.get("arguments")
    if not isinstance(name, str) or not isinstance(arguments, str):
        return None
    return name, arguments


@dataclass(frozen=True)
class OutputGuardResult:
    decision: Decision
    risk: RiskAssessment
    findings: tuple[Finding, ...]
    sanitized_content: str
    degraded: bool


async def run_output_guard(
    response_content: str,
    system_prompt_text: str,
    policy: Policy,
    *,
    salt: str,
    detector_timeout_ms: int = 250,
    upstream_response: dict[str, Any] | None = None,
) -> OutputGuardResult:
    """SPEC.md §2.11: runs Response-plane detectors (`pii`, `secrets`,
    `system_prompt_leak`) against `response_content`, and — when
    `upstream_response` is given and carries an egress `tool_calls[]`
    (SPEC.md §2.12) — Action-plane tool-call rules against the first one.

    Always returns a decision that is `ALLOW` (optionally `REDACT`
    -transformed) or `DENY`, never `NEED_APPROVAL` — PLAN.md §16's resolved
    decision R16: "Holding a generated response for review has no resume
    semantics, since the upstream call has already happened." See the ADR
    for what happens when an egress tool-call rule *would* have produced
    NEED_APPROVAL.

    SYS-014: this function is the one place output-plane inspection is
    implemented. app/main.py's immediate-ALLOW path and
    app/approvals.py's resume_approved() both call it with the same
    arguments shape — an approved transaction is not exempt from egress
    inspection, and the two paths cannot silently diverge because there is
    only one function (ADR 0004 §5).
    """
    output_detectors = build_output_detectors(policy)
    system_prompt_detector = build_system_prompt_leak_detector(policy)

    normalized = normalize(response_content)
    orchestrator = DetectorOrchestrator(output_detectors, detector_timeout_ms=detector_timeout_ms)
    orch_result = await orchestrator.run(normalized, Plane.response, salt)
    findings: list[Finding] = list(orch_result.findings)
    degraded = orch_result.degraded

    try:
        findings.extend(system_prompt_detector.scan_response(normalized, system_prompt_text, salt))
    except Exception:  # noqa: BLE001 — DET-014: isolate, never propagate
        degraded = True

    tool_name: str | None = None
    tool_arguments: dict[str, Any] = {}
    if upstream_response is not None:
        candidate = _first_response_tool_call(upstream_response)
        if candidate is not None:
            name, raw_arguments = candidate
            tool_detector = ToolCallsDetector(policy)
            try:
                findings.extend(
                    tool_detector.scan_tool_call(name, None, salt, raw_arguments=raw_arguments)
                )
                # Only feed structured tool_name/tool_arguments into
                # evaluate_policy() when the arguments actually parsed —
                # DET-018's SCHEMA_VIOLATION finding above already records a
                # parse failure; there is nothing further to evaluate.
                parsed = json.loads(raw_arguments)
                if isinstance(parsed, dict):
                    tool_name = name
                    tool_arguments = parsed
            except (ValueError, TypeError):
                pass  # unparseable arguments: SCHEMA_VIOLATION finding already recorded above
            except Exception:  # noqa: BLE001 — DET-014: isolate, never propagate
                degraded = True

    risk = aggregate_risk(tuple(findings))

    tool_call_detector_id = ToolCallsDetector.detector_id
    findings_by_plane = {
        Plane.response: tuple(f for f in findings if f.detector_id != tool_call_detector_id),
        Plane.action: tuple(f for f in findings if f.detector_id == tool_call_detector_id),
    }
    decision = evaluate_policy(
        policy,
        findings_by_plane,
        tool_name=tool_name,
        tool_arguments=tool_arguments,
        detectors_degraded=degraded,
    )

    if decision.verdict == "NEED_APPROVAL":
        # R16 / ADR 0005: the output plane has only ALLOW/DENY. A rule such
        # as high_value_transfer matching an egress tool_calls[] proposal
        # would otherwise ask for NEED_APPROVAL here, which has no resume
        # semantics once the upstream call has already happened. Clamp to
        # the conservative option (DENY) — never silently downgrade to
        # ALLOW, and never invent hold-for-review semantics SPEC.md doesn't
        # specify for this plane.
        decision = dataclasses.replace(decision, verdict="DENY", transformation="NONE")

    sanitized = response_content
    if decision.verdict == "ALLOW" and decision.transformation != "NONE":
        sanitized, _record = apply_transformations(response_content, {decision.transformation})

    return OutputGuardResult(
        decision=decision,
        risk=risk,
        findings=tuple(findings),
        sanitized_content=sanitized,
        degraded=degraded,
    )
