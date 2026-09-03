"""`topics` detector. SPEC.md §6.4: "Keyword and phrase lists | Word-boundary
matched; case- and diacritic-insensitive."

Unlike the other detectors, the word lists aren't hardcoded — they come from
the loaded policy's `detectors.topics.blocked`/`sensitive` config (see
policies/default_policy.yaml, ADR 0001 addendum). This detector is
constructed with those lists rather than reading them per-call, keeping
`scan()` itself a pure function of (content, plane, salt) — DET-002's "no
mutable state across calls" is about state that *changes* between calls,
not fixed configuration supplied at construction.
"""

from __future__ import annotations

import re
import unicodedata

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "topics"
DETECTOR_VERSION = "1.0.0"


def _strip_diacritics(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def _fold(text: str) -> str:
    return _strip_diacritics(text).lower()


def _compile_phrase(phrase: str) -> re.Pattern[str]:
    folded = _fold(phrase)
    escaped = re.escape(folded)
    # Treat internal whitespace as flexible (one-or-more) so minor
    # formatting differences in the input still match a configured phrase.
    escaped = escaped.replace(r"\ ", r"\s+")
    return re.compile(rf"\b{escaped}\b")


class TopicsDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input, Plane.context})

    def __init__(self, blocked: list[str], sensitive: list[str]) -> None:
        self._blocked = tuple((p, _compile_phrase(p)) for p in blocked)
        self._sensitive = tuple((p, _compile_phrase(p)) for p in sensitive)

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        folded_text = _fold(content.normalized)
        findings: list[Finding] = []
        for phrase, pattern in self._blocked:
            m = pattern.search(folded_text)
            if m:
                findings.append(self._finding(Category.BLOCKED_TOPIC, phrase, m, salt))
        for phrase, pattern in self._sensitive:
            m = pattern.search(folded_text)
            if m:
                findings.append(self._finding(Category.SENSITIVE_TOPIC, phrase, m, salt))
        return findings

    def _finding(self, category: Category, phrase: str, m: re.Match[str], salt: str) -> Finding:
        return Finding(
            detector_id=DETECTOR_ID,
            detector_version=DETECTOR_VERSION,
            category=category,
            score=0.9,
            confidence=Confidence.MEDIUM,  # keyword matching is inherently broad
            evidence=(
                Evidence(
                    start=m.start(),
                    end=m.end(),
                    pattern_id=f"topic:{phrase}",
                    excerpt_hash=salted_excerpt_hash(m.group(0), salt),
                ),
            ),
            safe_metadata={"match_count": 1},
        )
