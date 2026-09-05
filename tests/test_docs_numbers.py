"""DOC-010: the README's measured-results section MUST contain only
numbers present in docs/benchmarks.md, enforced by a CI check
(PLAN.md §12's anti-drift automation item 2: "extracts numeric claims from
the README's results section and asserts each appears in
docs/benchmarks.md").

This extracts every standalone numeric token from README.md's "Measured
results" section (between its own `## Measured results` heading and the
next `## ` heading) and asserts each one appears verbatim as a substring
somewhere in docs/benchmarks.md — the same source-of-truth file
`scripts/benchmark.py` generates. A number that appears in the README's
results section but not in docs/benchmarks.md would mean the README
invented or recomputed a figure, which this project's own rules forbid.

Deliberately scoped to the "Measured results" section only, not the whole
README: other sections legitimately cite numbers that have nothing to do
with the benchmark run (e.g. "54-case corpus", "25 metrics", "8 canonical
endpoints", requirement IDs like "SEC-008") and asserting *those* trace to
docs/benchmarks.md would be a category error, not a drift check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
BENCHMARKS_PATH = ROOT / "docs" / "benchmarks.md"

_SECTION_RE = re.compile(
    r"^## Measured results\s*\n(?P<body>.*?)(?=\n## |\Z)",
    re.DOTALL | re.MULTILINE,
)

# A "number" for this check: a decimal figure (optionally signed, optionally
# with thousands separators or a percent/ms/req-s unit stripped by the
# surrounding word-boundary), long enough to be a real measurement rather
# than noise. Bare small integers (single digits, section numbers like the
# "G1"/"G4" gate labels) are excluded on purpose — they're identifiers and
# prose, not measurements, and would false-positive against page numbers,
# heading labels, and requirement IDs.
_NUMBER_RE = re.compile(r"(?<![\w.$])\d[\d,]*\.\d+(?![\w])")


def _extract_measured_results_section(readme_text: str) -> str:
    m = _SECTION_RE.search(readme_text)
    assert m, "README.md has no '## Measured results' section"
    return m.group("body")


def _extract_numbers(text: str) -> set[str]:
    return {tok.replace(",", "") for tok in _NUMBER_RE.findall(text)}


@pytest.mark.docs
class TestReadmeNumbersTraceToBenchmarks:
    def test_measured_results_section_exists(self) -> None:
        text = README_PATH.read_text()
        section = _extract_measured_results_section(text)
        assert section.strip(), "Measured results section is empty"

    def test_benchmarks_file_exists(self) -> None:
        assert BENCHMARKS_PATH.exists(), "docs/benchmarks.md is missing"

    def test_states_hardware_date_and_commit_sha(self) -> None:
        """DOC-010: the measured-results section MUST state the hardware,
        the date and the commit SHA."""
        section = _extract_measured_results_section(README_PATH.read_text())
        lowered = section.lower()
        assert "hardware" in lowered or "apple" in lowered or "m2" in lowered
        assert "commit" in lowered
        assert re.search(r"\d{4}-\d{2}-\d{2}", section), "no ISO date found"

    def test_every_decimal_figure_traces_to_benchmarks_md(self) -> None:
        readme_section = _extract_measured_results_section(README_PATH.read_text())
        benchmarks_text = BENCHMARKS_PATH.read_text()

        readme_numbers = _extract_numbers(readme_section)
        assert readme_numbers, "no decimal figures found in the Measured results section"

        missing = sorted(n for n in readme_numbers if n not in benchmarks_text)
        assert not missing, (
            "README 'Measured results' cites number(s) absent from "
            f"docs/benchmarks.md (DOC-010 violation): {missing}"
        )
