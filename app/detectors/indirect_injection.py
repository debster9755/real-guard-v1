"""`indirect_injection` detector. SPEC.md §6.4: "Same families [as
prompt_injection], Context plane only — weighted higher: retrieved content
should never instruct."

ADR 0003: owns the Context plane exclusively (prompt_injection is Input-only),
so a context-plane injection produces exactly one category —
INDIRECT_INJECTION — rather than double-tagging with PROMPT_INJECTION too.
"""

from __future__ import annotations

from app.detectors.base import Category, Confidence, Finding
from app.detectors.prompt_injection import _JB_PATTERNS, _PI_PATTERNS, _scan_patterns
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "indirect_injection"
DETECTOR_VERSION = "1.0.0"


class IndirectInjectionDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.context})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        texts = content.all_texts()
        # Reuse both pattern families (an injection attempt in retrieved
        # content doesn't announce whether it's "instruction override" or
        # "jailbreak" flavoured) but relabel every match as one category:
        # content arriving via this plane is untrusted regardless of which
        # family it matches, and the corpus (IND-001..004) expects a single
        # INDIRECT_INJECTION reason code either way.
        raw = _scan_patterns(texts, _PI_PATTERNS, Category.INDIRECT_INJECTION, salt)
        raw += _scan_patterns(texts, _JB_PATTERNS, Category.INDIRECT_INJECTION, salt)

        findings: list[Finding] = []
        seen_pattern_ids: set[str] = set()
        for f in raw:
            pattern_id = f.evidence[0].pattern_id if f.evidence else ""
            if pattern_id in seen_pattern_ids:
                continue
            seen_pattern_ids.add(pattern_id)
            # "Weighted higher" per SPEC: re-tagged findings carry a
            # detector_id/version of this module and a score floor
            # reflecting that context content instructing at all is worse
            # than the same phrasing from a direct user message.
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.INDIRECT_INJECTION,
                    score=max(f.score, 0.85),
                    confidence=Confidence.HIGH,
                    evidence=f.evidence,
                    safe_metadata=f.safe_metadata,
                )
            )
        return findings
