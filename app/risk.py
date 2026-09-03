"""Risk aggregation. SPEC.md §2.5 (POL-006, POL-012).

A pure reduction of findings to per-category maximum scores and an overall
risk_level — evidence for policy and for human readers, never itself an
authorization (POL-012).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.detectors.base import Category, Finding


class RiskLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# POL-006: documented, deterministic score -> risk_level mapping. DETECTOR_TIMEOUT
# findings carry score 0.0 and are an operational signal, not a content risk —
# excluded from the max before this mapping applies.
def _score_to_level(score: float) -> RiskLevel:
    if score <= 0.0:
        return RiskLevel.NONE
    if score < 0.4:
        return RiskLevel.LOW
    if score < 0.7:
        return RiskLevel.MEDIUM
    if score < 0.9:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


@dataclass(frozen=True)
class RiskAssessment:
    category_scores: dict[Category, float] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.NONE


def aggregate_risk(findings: tuple[Finding, ...]) -> RiskAssessment:
    """§2.5: cannot fail; an empty finding list yields risk_level: NONE."""
    category_scores: dict[Category, float] = {}
    for f in findings:
        if f.category == Category.DETECTOR_TIMEOUT:
            continue
        category_scores[f.category] = max(category_scores.get(f.category, 0.0), f.score)
    max_score = max(category_scores.values(), default=0.0)
    return RiskAssessment(category_scores=category_scores, risk_level=_score_to_level(max_score))
