"""`tool_calls` detector. SPEC.md §6.4, §6.5 (DET-016..018), §2.12.

Categories: SENSITIVE_ACTION, DESTRUCTIVE_ACTION, TOOL_NOT_ALLOWLISTED.

Design note — evidence vs. verdict. This detector produces *evidence*
(Findings, for `findings_summary`/risk_level/observability). It does not by
itself drive the verdict for tool-call rules — that is a deliberate
consequence of how policies/default_policy.yaml's action-plane rules are
already written: `high_value_transfer`, `deny_destructive_sql`,
`deny_shell_deletion` and `agent_tool_allowlist` all match directly against
`DecisionContext.tool_name`/`tool_arguments` via app/decision.py's condition
evaluator (`tool_name_in`, `argument_path`, `sql_verb_in`,
`sql_unbounded_mutation`, `shell_pattern_in`) — none of them reference a
finding `category` at all. app/decision.py's own docstring anticipated
exactly this split: "Phase 3 populates real tool-call context alongside the
tool_calls detector, without needing this evaluator rebuilt." This detector
independently re-derives the same conclusions as evidence, reading its
allowlist/threshold/verb/pattern knowledge from the *loaded policy itself*
at construction time (mirroring app/detectors/topics.py's pattern of taking
config from `policy.detectors.<id>` — except `tool_calls`'s policy-schema
entry is just `{enabled, timeout_ms}`, with no room for an allowlist or a
numeric threshold without a schema change). Reading the real rule
definitions (`agent_tool_allowlist.when.tool_not_in`,
`high_value_transfer.when.all[].argument_path`/`numeric_gte`,
`deny_destructive_sql.when.any[].sql_verb_in`,
`deny_shell_deletion.when.shell_pattern_in`) instead means this detector's
evidence can never silently drift from what the policy actually enforces.
See docs/adr/0005-phase3-output-guard-and-tool-call-inspection.md for the
full account.

Design note — signature. The base `Detector.scan(content, plane, salt)`
signature is text-oriented (SPEC.md's illustrative sketch); a tool call's
arguments are already-structured JSON, not text to normalize. Following the
precedent app/detectors/schema.py set for exactly this situation, `scan()`
is a protocol-conformant no-op and the real entry point is
`scan_tool_call()`, called directly by app/pipeline.py (request-declared
`tools[]`, pre-upstream) and app/outputguard.py (response `tool_calls[]`,
post-upstream).

DET-018: unparseable arguments MUST produce a SCHEMA_VIOLATION finding
rather than being silently skipped.
"""

from __future__ import annotations

import json
from typing import Any

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane
from app.policy import Policy

DETECTOR_ID = "tool_calls"
DETECTOR_VERSION = "1.0.0"

# Mirrors app/decision.py's _SHELL_PATTERNS exactly (DET-017's fixed,
# named shell-analysis vocabulary — not policy-configurable, so there is
# nothing to read out of the loaded policy for this one).
_SHELL_PATTERNS: dict[str, tuple[str, ...]] = {
    "recursive_force_remove": ("rm -rf", "rm -fr", "rmdir /s"),
    "device_write": ("of=/dev/", "> /dev/sd"),
    "fork_bomb": (":(){:|:&};:",),
    "piped_download_execute": ("curl ", "| sh", "| bash", "wget "),
    "privilege_escalation": ("sudo ", "chmod +s", "setuid"),
}


def _rule_by_id(policy: Policy, rule_id: str) -> dict[str, Any] | None:
    for rule in policy.rules:
        if rule["id"] == rule_id:
            return rule
    return None


def _flatten_conditions(condition: dict[str, Any]) -> list[dict[str, Any]]:
    out = [condition]
    for combinator in ("all", "any"):
        for sub in condition.get(combinator, []):
            out.extend(_flatten_conditions(sub))
    return out


class ToolCallsDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.action})

    def __init__(self, policy: Policy) -> None:
        self._allowlist = self._extract_allowlist(policy)
        self._high_value_tools, self._high_value_threshold = self._extract_high_value(policy)
        self._sql_verbs = self._extract_sql_verbs(policy)
        self._shell_pattern_names = self._extract_shell_patterns(policy)

    @staticmethod
    def _extract_allowlist(policy: Policy) -> frozenset[str] | None:
        rule = _rule_by_id(policy, "agent_tool_allowlist")
        if rule is None or "when" not in rule:
            return None
        for cond in _flatten_conditions(rule["when"]):
            if "tool_not_in" in cond:
                return frozenset(cond["tool_not_in"])
        return None

    @staticmethod
    def _extract_high_value(policy: Policy) -> tuple[frozenset[str], float | None]:
        rule = _rule_by_id(policy, "high_value_transfer")
        if rule is None or "when" not in rule:
            return frozenset(), None
        tools: frozenset[str] = frozenset()
        threshold: float | None = None
        for cond in _flatten_conditions(rule["when"]):
            if "tool_name_in" in cond:
                tools = frozenset(cond["tool_name_in"])
            if "numeric_gte" in cond:
                threshold = float(cond["numeric_gte"])
        return tools, threshold

    @staticmethod
    def _extract_sql_verbs(policy: Policy) -> frozenset[str]:
        rule = _rule_by_id(policy, "deny_destructive_sql")
        if rule is None or "when" not in rule:
            return frozenset()
        verbs: set[str] = set()
        for cond in _flatten_conditions(rule["when"]):
            if "sql_verb_in" in cond:
                verbs |= {v.upper() for v in cond["sql_verb_in"]}
        return frozenset(verbs)

    @staticmethod
    def _extract_shell_patterns(policy: Policy) -> frozenset[str]:
        rule = _rule_by_id(policy, "deny_shell_deletion")
        if rule is None or "when" not in rule:
            return frozenset()
        names: set[str] = set()
        for cond in _flatten_conditions(rule["when"]):
            if "shell_pattern_in" in cond:
                names |= set(cond["shell_pattern_in"])
        return frozenset(names)

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        # Protocol-conformant placeholder — see module docstring. The real
        # work needs parsed tool-call structure; use scan_tool_call() directly.
        return []

    def scan_tool_call(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any] | None,
        salt: str,
        *,
        raw_arguments: str | None = None,
    ) -> list[Finding]:
        """DET-016/017/018. `tool_arguments` is already-parsed JSON (the
        request `tools[]` shape this project's frozen corpus uses — see the
        ADR). `raw_arguments`, when given, is the unparsed JSON *string*
        SPEC.md's `tool_calls[].function.arguments` actually is; a parse
        failure there is itself evidence (SCHEMA_VIOLATION) rather than a
        silent skip (DET-018)."""
        findings: list[Finding] = []

        if raw_arguments is not None:
            try:
                parsed = json.loads(raw_arguments)
            except (json.JSONDecodeError, TypeError):
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        detector_version=DETECTOR_VERSION,
                        category=Category.SCHEMA_VIOLATION,
                        score=0.6,
                        confidence=Confidence.MEDIUM,
                        evidence=(
                            Evidence(
                                start=0,
                                end=0,
                                pattern_id="unparseable_tool_arguments_v1",
                                excerpt_hash=salted_excerpt_hash(raw_arguments, salt),
                            ),
                        ),
                        safe_metadata={"tool_name": tool_name},
                    )
                )
                return findings  # DET-018: can't inspect further; not JSON at all
            tool_arguments = parsed if isinstance(parsed, dict) else {}

        args: dict[str, Any] = tool_arguments or {}

        if self._allowlist is not None and tool_name not in self._allowlist:
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.TOOL_NOT_ALLOWLISTED,
                    score=0.9,
                    confidence=Confidence.HIGH,
                    safe_metadata={"tool_name": tool_name},
                )
            )

        amount = args.get("amount")
        if (
            self._high_value_threshold is not None
            and tool_name in self._high_value_tools
            and isinstance(amount, int | float)
            and not isinstance(amount, bool)
            and amount >= self._high_value_threshold
        ):
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.SENSITIVE_ACTION,
                    score=0.85,
                    confidence=Confidence.HIGH,
                    safe_metadata={"tool_name": tool_name, "amount": float(amount)},
                )
            )

        query = args.get("query")
        if isinstance(query, str) and query.strip():
            first_word = query.strip().split(None, 1)[0].upper()
            upper = query.upper()
            is_unbounded_mutation = (
                any(upper.strip().startswith(v) for v in ("DELETE", "UPDATE"))
                and "WHERE" not in upper
            )
            if first_word in self._sql_verbs or is_unbounded_mutation:
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        detector_version=DETECTOR_VERSION,
                        category=Category.DESTRUCTIVE_ACTION,
                        score=0.95,
                        confidence=Confidence.HIGH,
                        safe_metadata={"tool_name": tool_name, "sql_verb": first_word},
                    )
                )

        command = args.get("command")
        if isinstance(command, str) and self._matches_shell_pattern(command):
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.DESTRUCTIVE_ACTION,
                    score=0.95,
                    confidence=Confidence.HIGH,
                    safe_metadata={"tool_name": tool_name},
                )
            )

        return findings

    def _matches_shell_pattern(self, command: str) -> bool:
        lowered = command.lower()
        for name in self._shell_pattern_names:
            for needle in _SHELL_PATTERNS.get(name, ()):
                if needle.lower() in lowered:
                    return True
        return False
