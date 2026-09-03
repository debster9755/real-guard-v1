"""WS-02 policy loader tests. SPEC.md §7 (POL-014, POL-015, POL-020)."""

from __future__ import annotations

import copy

import pytest
import yaml
from app.policy import PolicyLoadError, compute_policy_version, load_policy, validate_policy_dict


@pytest.fixture
def valid_policy_dict() -> dict:
    with open("policies/default_policy.yaml") as f:
        return yaml.safe_load(f)


def test_default_policy_loads(repo_root: str) -> None:
    policy = load_policy("policies/default_policy.yaml")
    assert policy.policy_version.startswith("sha256:")
    assert len(policy.rules) == 21


def test_policy_version_stable_across_reloads() -> None:
    """WS-02 acceptance criterion."""
    p1 = load_policy("policies/default_policy.yaml")
    p2 = load_policy("policies/default_policy.yaml")
    assert p1.policy_version == p2.policy_version


def test_policy_version_changes_on_content_change(valid_policy_dict: dict) -> None:
    v1 = compute_policy_version(valid_policy_dict)
    mutated = copy.deepcopy(valid_policy_dict)
    mutated["rules"][0]["reason_code"] = "PII_DETECTED"  # arbitrary content change
    v2 = compute_policy_version(mutated)
    assert v1 != v2


def test_policy_version_stable_regardless_of_key_order(valid_policy_dict: dict) -> None:
    """Canonicalization (sort_keys) means dict key order doesn't affect the hash."""
    reordered = dict(reversed(list(valid_policy_dict.items())))
    assert compute_policy_version(valid_policy_dict) == compute_policy_version(reordered)


def test_missing_policy_file_raises() -> None:
    with pytest.raises(PolicyLoadError, match="not found"):
        load_policy("policies/does_not_exist.yaml")


def test_unknown_top_level_key_rejected_pol020(valid_policy_dict: dict) -> None:
    bad = copy.deepcopy(valid_policy_dict)
    bad["not_a_real_key"] = True
    errors = validate_policy_dict(bad)
    assert errors, "POL-020: unknown top-level key must fail schema validation"


def test_unknown_rule_key_rejected_pol020(valid_policy_dict: dict) -> None:
    bad = copy.deepcopy(valid_policy_dict)
    bad["rules"][0]["not_a_real_rule_field"] = 1
    errors = validate_policy_dict(bad)
    assert errors, "POL-020: unknown rule-level key must fail schema validation"


def test_rule_without_plane_rejected_pol017(valid_policy_dict: dict) -> None:
    bad = copy.deepcopy(valid_policy_dict)
    del bad["rules"][0]["plane"]
    errors = validate_policy_dict(bad)
    assert errors, "POL-017: plane is mandatory on every rule"


def test_every_rule_has_a_reason_code_pol019(valid_policy_dict: dict) -> None:
    for rule in valid_policy_dict["rules"]:
        assert "reason_code" in rule, f"rule {rule['id']} missing reason_code (POL-019)"


def test_every_reason_code_taxonomy_category_has_a_rule() -> None:
    """Phase-0 ADR 0001 addendum: BLOCKED_TOPIC/SENSITIVE_TOPIC gap closed —
    regression-test that every input/context/response category a detector
    can emit has *some* policy consequence."""
    policy = load_policy("policies/default_policy.yaml")
    categories_with_rules = set()
    for rule in policy.rules:
        when = rule.get("when", {})
        _collect_categories(when, categories_with_rules)

    required = {
        "PROMPT_INJECTION",
        "JAILBREAK",
        "INDIRECT_INJECTION",
        "ENCODED_PAYLOAD",
        "PII_DETECTED",
        "SECRET_DETECTED",
        "BLOCKED_TOPIC",
        "SENSITIVE_TOPIC",
        "OUTPUT_PII",
        "OUTPUT_SECRET",
        "CANARY_LEAK",
        "SYSTEM_PROMPT_LEAK",
    }
    missing = required - categories_with_rules
    assert not missing, f"categories with no policy rule: {missing}"


def _collect_categories(condition: dict, out: set[str]) -> None:
    if "category" in condition:
        out.add(condition["category"])
    for combinator in ("all", "any"):
        for sub in condition.get(combinator, []):
            _collect_categories(sub, out)


def test_malformed_yaml_raises(tmp_path) -> None:  # noqa: ANN001
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("rules: [unclosed, flow, sequence")  # unterminated '['
    with pytest.raises(PolicyLoadError, match="not valid YAML"):
        load_policy(str(bad_file))
