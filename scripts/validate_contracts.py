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
  6. openapi.json is present and has exactly 8 paths (API-001, ADR 0001).

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

    # 5. openapi.json — 8 canonical endpoints.
    openapi = json.loads((ROOT / "openapi.json").read_text())
    n_paths = len(openapi["paths"])
    check(n_paths == 8, f"openapi.json declares exactly 8 paths (found {n_paths})")

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
