#!/usr/bin/env python3
"""Phase 0 contract-freeze validation, re-runnable at any later phase.

Checks (PLAN.md §6 Phase 0 automated checks, plus TST-023):
  1. policies/policy.schema.json and tests/data/corpus.schema.json are each a
     valid JSON Schema (Draft 2020-12).
  2. policies/default_policy.yaml validates against policy.schema.json.
  3. policies/default_policy.yaml rejects unknown keys (POL-020 regression).
  4. tests/data/golden_corpus.jsonl has exactly 54 lines, each valid against
     corpus.schema.json, with the §9.3 / §17.4 bucket distribution (TST-023).
  5. Every case's expected_policy_hits reference real rule ids in
     default_policy.yaml.
  6. openapi.json is present, contains SPEC.md §4.1's 8 canonical paths, and
     has exactly 18 paths in total — the 8 canonical, plus the 3 dashboard-
     session-support routes (login/logout/CSRF-decide) ADR 0006 added in
     Phase 4 and ADR 0010 formally reconciled in Phase 8 (docs/adr/0010),
     plus the 7 `/console/api/*` routes ADR 0014 added for the console SPA.
     Whether openapi.json itself matches the live application byte-for-byte
     is a separate check: `python scripts/generate_openapi.py --check`.

Exit code 0 on success, 1 on any failure. Intended to become a CI job in
Phase 1 (WS-01) — see .github/workflows/ci.yml once authored.
"""

import copy
import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)
        print(f"FAIL: {message}")
    else:
        print(f"OK:   {message}")


def main() -> int:
    # 1 & 2. Policy schema is valid; default policy validates against it.
    policy_schema = json.loads((ROOT / "policies/policy.schema.json").read_text())
    try:
        Draft202012Validator.check_schema(policy_schema)
        check(True, "policies/policy.schema.json is a valid JSON Schema")
    except Exception as e:
        check(False, f"policies/policy.schema.json is NOT a valid JSON Schema: {e}")
        return report()

    policy = yaml.safe_load((ROOT / "policies/default_policy.yaml").read_text())
    pv = Draft202012Validator(policy_schema)
    errors = list(pv.iter_errors(policy))
    check(
        not errors,
        f"default_policy.yaml validates against policy.schema.json ({len(errors)} errors)",
    )
    for e in errors:
        print("   ", list(e.path), e.message)

    # 3. POL-020 regression: unknown keys must be rejected.
    bad = copy.deepcopy(policy)
    bad["not_a_real_key"] = True
    check(bool(list(pv.iter_errors(bad))), "POL-020: unknown top-level policy key is rejected")

    rule_ids = [r["id"] for r in policy["rules"]]
    check(len(rule_ids) == len(set(rule_ids)), "policy rule ids are unique")

    # 4. Corpus schema valid; corpus has exactly 54 cases in the right distribution.
    corpus_schema = json.loads((ROOT / "tests/data/corpus.schema.json").read_text())
    Draft202012Validator.check_schema(corpus_schema)
    check(True, "tests/data/corpus.schema.json is a valid JSON Schema")

    lines = (ROOT / "tests/data/golden_corpus.jsonl").read_text().splitlines()
    check(len(lines) == 54, f"golden_corpus.jsonl has exactly 54 cases (found {len(lines)})")

    cv = Draft202012Validator(corpus_schema)
    expected_distribution = {
        "BENIGN": 12,
        "DIRECT_INJECTION": 10,
        "ENCODED_INJECTION": 6,
        "INDIRECT_INJECTION": 4,
        "PII_INPUT": 6,
        "SECRET_INPUT": 4,
        "OUTPUT_LEAKAGE": 4,
        "LEAK_OUTPUT": 4,
        "TOOL_ABUSE": 4,
    }
    distribution: dict[str, int] = {}
    seen_ids: set[str] = set()
    schema_ok = True
    hits_ok = True
    for i, line in enumerate(lines, 1):
        case = json.loads(line)
        errs = list(cv.iter_errors(case))
        if errs:
            schema_ok = False
            print(f"   line {i} ({case.get('case_id')}) schema errors:")
            for e in errs:
                print("     ", list(e.path), e.message)
        cid = case["case_id"]
        if cid in seen_ids:
            schema_ok = False
            print(f"   duplicate case_id: {cid}")
        seen_ids.add(cid)
        distribution[case["category"]] = distribution.get(case["category"], 0) + 1
        for hit in case["expected_policy_hits"]:
            if hit not in rule_ids:
                hits_ok = False
                print(f"   {cid}: policy hit '{hit}' is not a real rule id")

    check(schema_ok, "every corpus case validates against corpus.schema.json, ids unique")
    check(
        distribution == expected_distribution,
        f"corpus bucket distribution matches PLAN.md §9.3 (got {distribution})",
    )
    check(
        hits_ok,
        "every expected_policy_hits entry references a real rule id in default_policy.yaml",
    )

    # 5. openapi.json — SPEC.md §4.1's 8 canonical endpoints, plus the 3
    # dashboard-session-support routes ADR 0006/ADR 0010 document, plus the
    # 7 console-support routes ADR 0014 documents. The point of this check
    # is that new API surface is *deliberate*: a route added without being
    # named here fails the build, exactly as the console routes did on
    # their first run.
    openapi = json.loads((ROOT / "openapi.json").read_text())
    canonical_paths = {
        "/v1/chat/completions",
        "/v1/firewall/approvals",
        "/v1/firewall/requests/{transaction_or_request_id}",
        "/v1/firewall/approvals/{approval_id}/decision",
        "/dashboard",
        "/healthz",
        "/readyz",
        "/metrics",
    }
    dashboard_support_paths = {
        "/dashboard/login",
        "/dashboard/logout",
        "/dashboard/approvals/{approval_id}/decide",
    }
    # ADR 0014: the /console SPA's JSON surface. Like the dashboard-support
    # routes above, these are a *second transport* for operations SPEC.md
    # already specifies, not new API contract — none of them can do anything
    # `/v1/firewall/*` and `app/approvals.py` could not already do.
    console_support_paths = {
        "/console/api/login",
        "/console/api/logout",
        "/console/api/session",
        "/console/api/approvals",
        "/console/api/decisions",
        "/console/api/approvals/{approval_id}/decide",
        "/console/api/stats",
    }
    actual_paths = set(openapi["paths"])
    missing_canonical = canonical_paths - actual_paths
    check(
        not missing_canonical,
        "openapi.json declares all 8 SPEC.md §4.1 canonical paths "
        f"(missing: {missing_canonical or 'none'})",
    )
    unexpected = (
        actual_paths - canonical_paths - dashboard_support_paths - console_support_paths
    )
    check(
        not unexpected,
        f"openapi.json has no undocumented paths beyond the 8 canonical + 3 "
        f"dashboard-support + 7 console-support ones "
        f"(unexpected: {unexpected or 'none'})",
    )
    check(
        len(actual_paths) == 18,
        f"openapi.json declares exactly 18 paths total: 8 canonical + 3 "
        f"dashboard-support + 7 console-support (found {len(actual_paths)})",
    )

    return report()


def report() -> int:
    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED")
        return 1
    print("ALL CONTRACT CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
