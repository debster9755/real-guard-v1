"""Policy engine / decision evaluation. SPEC.md §2.6, §5 (POL-001..013).

A pure function of (findings, byte_count, policy) -> Decision. Never runs
detectors, never mutates content, never reads the clock in a way that
affects the verdict (POL-001 determinism).

Condition evaluation supports every shape in policies/policy.schema.json's
`condition` $def. Phase 2 only exercises category/score_gte/score_lt/bytes_gt
(the six in-scope-detector rules — ADR 0003); tool_name_in/tool_not_in/
argument_path-based conditions are evaluated against an empty tool context
for now and so never match — Phase 3 populates real tool-call context
alongside the tool_calls detector, without needing this evaluator rebuilt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.detectors.base import Category, Finding
from app.planes import Plane
from app.policy import Policy

# POL-002: precedence is absolute, never overridable.
_VERDICT_RANK = {"DENY": 2, "NEED_APPROVAL": 1, "ALLOW": 0}

# TRN-003: fixed application order — used here only to pick a single
# representative `transformation` label when multiple rules independently
# specify one; the golden corpus never exercises more than one type at a
# time, but the ordering keeps behaviour well-defined if that changes.
_TRANSFORMATION_ORDER = ["TRUNCATE", "SANITIZE", "REWRITE", "REDACT", "MASK"]


@dataclass(frozen=True)
class DecisionContext:
    """Everything one rule's `when` condition might reference. Phase 2
    populates findings and byte_count; tool_name/tool_arguments stay empty
    until Phase 3's tool_calls detector exists (ADR 0003)."""

    findings: tuple[Finding, ...] = field(default_factory=tuple)
    byte_count: int = 0
    tool_name: str | None = None
    tool_arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyHit:
    rule_id: str
    verdict: str
    transformation: str
    matched_categories: tuple[str, ...]
    rule_version: str


@dataclass(frozen=True)
class Decision:
    verdict: str
    transformation: str
    reason_codes: tuple[str, ...]
    policy_hits: tuple[PolicyHit, ...]
    policy_version: str
    degraded: bool = False


def _category_scores(findings: tuple[Finding, ...]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for f in findings:
        if f.category == Category.DETECTOR_TIMEOUT:
            continue
        scores[f.category.value] = max(scores.get(f.category.value, 0.0), f.score)
    return scores


def _resolve_json_path(obj: dict[str, Any], path: str) -> Any:
    """Minimal `$.field` / `$.a.b` resolver — sufficient for the argument
    paths policies/default_policy.yaml actually uses ($.amount, $.query,
    $.command). Not a general JSONPath implementation."""
    if not path.startswith("$."):
        return None
    node: Any = obj
    for part in path[2:].split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _eval_condition(condition: dict[str, Any], ctx: DecisionContext) -> bool:
    if "all" in condition:
        return all(_eval_condition(c, ctx) for c in condition["all"])
    if "any" in condition:
        return any(_eval_condition(c, ctx) for c in condition["any"])

    if "category" in condition:
        scores = _category_scores(ctx.findings)
        score = scores.get(condition["category"])
        if score is None:
            return False
        if "score_gte" in condition and score < float(condition["score_gte"]):
            return False
        below_score_lt: bool = "score_lt" not in condition or score < float(condition["score_lt"])
        return below_score_lt

    if "bytes_gt" in condition:
        return ctx.byte_count > int(condition["bytes_gt"])

    if "tool_name_in" in condition:
        return ctx.tool_name is not None and ctx.tool_name in condition["tool_name_in"]

    if "tool_not_in" in condition:
        return ctx.tool_name is not None and ctx.tool_name not in condition["tool_not_in"]

    if "argument_path" in condition:
        value = _resolve_json_path(ctx.tool_arguments, condition["argument_path"])
        if value is None:
            return False
        if "numeric_gte" in condition:
            return isinstance(value, int | float) and value >= condition["numeric_gte"]
        if "numeric_lt" in condition:
            return isinstance(value, int | float) and value < condition["numeric_lt"]
        if "sql_verb_in" in condition and isinstance(value, str):
            verbs = {v.upper() for v in condition["sql_verb_in"]}
            first_word = value.strip().split(None, 1)[0].upper() if value.strip() else ""
            return first_word in verbs
        if "sql_unbounded_mutation" in condition and isinstance(value, str):
            upper = value.upper()
            is_mutation = any(upper.strip().startswith(v) for v in ("DELETE", "UPDATE"))
            return is_mutation and "WHERE" not in upper
        if "shell_pattern_in" in condition and isinstance(value, str):
            return _matches_shell_pattern(value, condition["shell_pattern_in"])
        return False

    return False


_SHELL_PATTERNS = {
    "recursive_force_remove": ("rm -rf", "rm -fr", "rmdir /s"),
    "device_write": ("of=/dev/", "> /dev/sd"),
    "fork_bomb": (":(){:|:&};:",),
    "piped_download_execute": ("curl ", "| sh", "| bash", "wget "),
    "privilege_escalation": ("sudo ", "chmod +s", "setuid"),
}


def _matches_shell_pattern(command: str, pattern_names: list[str]) -> bool:
    lowered = command.lower()
    for name in pattern_names:
        for needle in _SHELL_PATTERNS.get(name, ()):
            if needle.lower() in lowered:
                return True
    return False


def _rule_categories(condition: dict[str, Any]) -> set[str]:
    cats: set[str] = set()
    if "category" in condition:
        cats.add(condition["category"])
    for combinator in ("all", "any"):
        for sub in condition.get(combinator, []):
            cats |= _rule_categories(sub)
    return cats


def evaluate_policy(
    policy: Policy,
    findings_by_plane: dict[Plane, tuple[Finding, ...]],
    *,
    byte_count: int = 0,
    tool_name: str | None = None,
    tool_arguments: dict[str, Any] | None = None,
    detectors_degraded: bool = False,
) -> Decision:
    """POL-001: a pure function — identical inputs always produce an
    identical Decision. POL-003: every matching rule is recorded, even
    after a DENY is determined (no short-circuiting)."""
    hits: list[PolicyHit] = []

    for rule in policy.rules:
        if "rate_limit" in rule:
            continue  # WS-13 (Phase 6) — not evaluated by the decision engine

        condition = rule.get("when")
        if condition is None:
            continue

        rule_planes = [Plane(p) for p in rule["plane"]]
        matched = False
        matched_categories: set[str] = set()
        possible_categories = _rule_categories(condition)

        for plane in rule_planes:
            plane_findings = findings_by_plane.get(plane, ())
            ctx = DecisionContext(
                findings=plane_findings,
                byte_count=byte_count,
                tool_name=tool_name,
                tool_arguments=tool_arguments or {},
            )
            if _eval_condition(condition, ctx):
                matched = True
                found_cats = {f.category.value for f in plane_findings}
                matched_categories |= possible_categories & found_cats

        if matched:
            hits.append(
                PolicyHit(
                    rule_id=rule["id"],
                    verdict=rule["verdict"],
                    transformation=rule.get("transformation", "NONE"),
                    matched_categories=tuple(sorted(matched_categories)),
                    rule_version=policy.policy_version,
                )
            )

    # POL-002: absolute precedence, DENY > NEED_APPROVAL > ALLOW.
    final_verdict = "ALLOW"
    for hit in hits:
        if _VERDICT_RANK[hit.verdict] > _VERDICT_RANK[final_verdict]:
            final_verdict = hit.verdict

    # POL-004/POL-005: hard_deny / mandatory_approval are already expressed
    # purely through each rule's own `verdict` in this policy format (a
    # hard_deny rule's verdict is always DENY; POL-002's precedence already
    # gives DENY unconditional priority over any other hit, satisfying
    # POL-004 without a separate code path. Same reasoning for
    # mandatory_approval against ALLOW.)

    winning_hits = [h for h in hits if h.verdict == final_verdict]
    reason_codes = tuple(sorted({_reason_code_for_rule(policy, h.rule_id) for h in winning_hits}))
    # POL-003 restated: policy_hits records EVERY matching rule, not just the
    # winning verdict's — evidence isn't hidden by precedence.
    all_policy_hits = tuple(hits)

    transformation = "NONE"
    if final_verdict != "DENY":
        applicable = {h.transformation for h in winning_hits if h.transformation != "NONE"}
        for t in _TRANSFORMATION_ORDER:
            if t in applicable:
                transformation = t  # last-applied-wins per TRN-003 ordering

    return Decision(
        verdict=final_verdict,
        transformation=transformation,
        reason_codes=reason_codes,
        policy_hits=all_policy_hits,
        policy_version=policy.policy_version,
        degraded=detectors_degraded,
    )


def _reason_code_for_rule(policy: Policy, rule_id: str) -> str:
    for rule in policy.rules:
        if rule["id"] == rule_id:
            return str(rule["reason_code"])
    return "SCHEMA_VIOLATION"  # unreachable in practice; policy schema requires reason_code
