"""DOC-011: the README MUST state that detection is heuristic, that false
positives and negatives occur, and that this is one layer of defence in
depth. It MUST NOT use "prevents", "guarantees", "blocks all", or
"eliminates" (SPEC.md §18, `test_readme_forbidden_claims_absent` in
SPEC.md §20's traceability table).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"

_FORBIDDEN_PHRASES = ["prevents", "guarantees", "blocks all", "eliminates"]
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _blank_inline_code(text: str) -> str:
    # A forbidden word inside a code span (e.g. quoting a variable or
    # literal string that happens to contain one of these words) is not an
    # overclaiming prose statement — none currently occur, but the same
    # backtick-blanking approach as the placeholder grep keeps this check
    # honest about what counts as prose.
    return _INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)


@pytest.mark.docs
class TestReadmeDoesNotOverclaim:
    def test_no_forbidden_overclaiming_phrase(self) -> None:
        text = _blank_inline_code(README_PATH.read_text()).lower()
        hits = [phrase for phrase in _FORBIDDEN_PHRASES if phrase in text]
        assert not hits, f"README uses forbidden overclaiming language: {hits}"

    def test_states_heuristic_detection_and_false_positive_negative_caveat(self) -> None:
        text = README_PATH.read_text().lower()
        assert "heuristic" in text
        assert "false positive" in text
        assert "false negative" in text or "false negatives" in text
        assert "defence in depth" in text or "defense in depth" in text
