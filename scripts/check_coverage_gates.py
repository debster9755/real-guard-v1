#!/usr/bin/env python3
"""Coverage gate. PLAN.md §10.2 G14: "Test coverage on `app/`: >= 85% line,
>= 75% branch. Blocking." WS-14's own acceptance criterion names "a coverage
gate" as a deliverable that did not otherwise exist anywhere in this
repository before Phase 7 (no `fail_under` in `pyproject.toml`'s
`[tool.coverage.report]`, no equivalent CI step) — see docs/adr/0009 for the
reconciliation this script represents.

`coverage.py`'s own `--fail-under` (and `[tool.coverage.report] fail_under`)
enforces a single *blended* statement+branch percentage, not the two
separate line/branch thresholds G14 actually specifies — so it cannot
express this gate on its own. This script instead reads the Cobertura XML
`coverage.xml` that `pytest --cov=app --cov-report=xml` already produces
(CI's own existing step — see .github/workflows/ci.yml), which reports
`line-rate` and `branch-rate` as separate top-level attributes, and checks
each against its own G14 threshold.

Usage: run pytest with `--cov-report=xml` first, then:
    python scripts/check_coverage_gates.py [path/to/coverage.xml]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_MIN_LINE_RATE = 0.85  # G14
_MIN_BRANCH_RATE = 0.75  # G14


def check_gates(coverage_xml_path: Path) -> int:
    if not coverage_xml_path.exists():
        print(
            f"FAIL: {coverage_xml_path} does not exist. Run "
            "`pytest --cov=app --cov-report=xml` first.",
            file=sys.stderr,
        )
        return 1

    root = ET.parse(coverage_xml_path).getroot()  # noqa: S314 — our own just-generated coverage.xml, not untrusted input
    line_rate = float(root.attrib["line-rate"])
    branch_rate = float(root.attrib["branch-rate"])

    failures: list[str] = []
    if line_rate < _MIN_LINE_RATE:
        failures.append(f"line coverage {line_rate:.1%} < required {_MIN_LINE_RATE:.0%} (G14)")
    else:
        print(f"OK:   line coverage {line_rate:.1%} >= {_MIN_LINE_RATE:.0%} (G14)")

    if branch_rate < _MIN_BRANCH_RATE:
        failures.append(
            f"branch coverage {branch_rate:.1%} < required {_MIN_BRANCH_RATE:.0%} (G14)"
        )
    else:
        print(f"OK:   branch coverage {branch_rate:.1%} >= {_MIN_BRANCH_RATE:.0%} (G14)")

    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1

    print("G14 COVERAGE GATE PASSED")
    return 0


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "coverage.xml"
    return check_gates(path)


if __name__ == "__main__":
    sys.exit(main())
