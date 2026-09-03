"""`system_prompt_leak` detector. SPEC.md §6.4 (DET-011), §2.11 (output guard).

Categories: SYSTEM_PROMPT_LEAK, CANARY_LEAK — both Response-plane only
(ADR 0003 assigned this detector to Phase 3, "pairs with the output guard").

DET-011: a canary token appearing in a response is high-confidence proof of
leakage and MUST produce confidence HIGH.

Design note — the extra `system_prompt_text` input: SPEC.md §6.4 says this
detector "compares the response against the request's system messages," but
the base `Detector.scan(content, plane, salt)` protocol has no slot for a
second piece of content to compare against. `app/detectors/schema.py`
already established the precedent for this exact situation (structural
validation needs the raw `message` dict, not just `NormalizedContent`): a
detector may expose a protocol-conformant `scan()` that returns `[]` (so it
is still safe to register with `DetectorOrchestrator` if ever needed) plus a
real method with a wider signature that the caller invokes directly. This
detector follows that precedent with `scan_response()`.
"""

from __future__ import annotations

import difflib

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent, normalize_text
from app.planes import Plane

DETECTOR_ID = "system_prompt_leak"
DETECTOR_VERSION = "1.0.0"

# A response that reproduces the system prompt this closely is leaking it,
# whether verbatim or lightly paraphrased — matches deny_system_prompt_leak's
# `score_gte: 0.8` in policies/default_policy.yaml exactly, so the detector's
# score and the policy's threshold are read from the same intent even though
# they live in different files (the detector emits a raw similarity ratio;
# the policy rule decides what to do with it — PLAN.md principle 2).
_HIGH_SIMILARITY_CONFIDENCE_FLOOR = 0.9

# Below this, two strings sharing a handful of common words/characters is
# just noise, not evidence — DET-002/POL-012 don't forbid a detector from
# having its own sensitivity floor, and emitting a SYSTEM_PROMPT_LEAK finding
# (which risk aggregation folds into risk_level) for every response that
# happens to share a stopword with the system prompt would make risk_level
# meaningless on ordinary ALLOW traffic. difflib's SequenceMatcher.ratio()
# on two *unrelated* English sentences of similar length routinely lands
# around 0.2-0.4 purely from shared short words and punctuation (measured
# directly, not assumed) — 0.6 is comfortably above that noise band and
# still comfortably below deny_system_prompt_leak's 0.8 verdict threshold,
# so it never masks a real detection — it only suppresses evidence nobody
# would act on.
_MIN_REPORTABLE_SIMILARITY = 0.6


def _similarity(a: str, b: str) -> float:
    """difflib's SequenceMatcher ratio: deterministic, pure (no I/O), and
    good enough to catch verbatim/near-verbatim reproduction without pulling
    in an embedding model — consistent with PLAN.md's "smallest stack that
    satisfies the contract" and DET-002's "no I/O" constraint."""
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


class SystemPromptLeakDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.response})

    def __init__(self, canaries: list[str]) -> None:
        self._canaries = tuple(c for c in canaries if c)

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        # Protocol-conformant placeholder — see module docstring. The real
        # work needs `system_prompt_text` too; use scan_response() directly.
        return []

    def scan_response(
        self, content: NormalizedContent, system_prompt_text: str, salt: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # DET-011: canary match — checked against the normalized text and
        # every bounded decoded variant (SYS-012), so a canary smuggled
        # through a base64/hex/percent-encoded block in the response is
        # still caught (tests/data/golden_corpus.jsonl LEK-004's intent).
        for canary in self._canaries:
            folded_canary = normalize_text(canary)
            for text, depth in content.all_texts():
                idx = text.find(folded_canary)
                if idx == -1:
                    continue
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        detector_version=DETECTOR_VERSION,
                        category=Category.CANARY_LEAK,
                        score=1.0,
                        confidence=Confidence.HIGH,  # DET-011
                        evidence=(
                            Evidence(
                                start=idx,
                                end=idx + len(folded_canary),
                                pattern_id="canary_token_v1",
                                excerpt_hash=salted_excerpt_hash(folded_canary, salt),
                            ),
                        ),
                        safe_metadata={"decoded_depth": depth},
                    )
                )
                break  # one finding per canary is sufficient evidence

        # Similarity against the system prompt actually forwarded upstream.
        if system_prompt_text.strip():
            folded_system = normalize_text(system_prompt_text)
            ratio = _similarity(content.normalized, folded_system)
            if ratio >= _MIN_REPORTABLE_SIMILARITY:
                confidence = (
                    Confidence.HIGH
                    if ratio >= _HIGH_SIMILARITY_CONFIDENCE_FLOOR
                    else Confidence.MEDIUM
                )
                findings.append(
                    Finding(
                        detector_id=DETECTOR_ID,
                        detector_version=DETECTOR_VERSION,
                        category=Category.SYSTEM_PROMPT_LEAK,
                        score=ratio,
                        confidence=confidence,
                        evidence=(
                            Evidence(
                                start=0,
                                end=len(content.normalized),
                                pattern_id="system_prompt_similarity_v1",
                                excerpt_hash=salted_excerpt_hash(content.normalized, salt),
                            ),
                        ),
                        safe_metadata={"similarity_ratio": round(ratio, 4)},
                    )
                )

        return findings
