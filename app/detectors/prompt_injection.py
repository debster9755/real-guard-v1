"""`prompt_injection` detector. SPEC.md §6.4.

Categories: PROMPT_INJECTION, JAILBREAK. Families: instruction override,
role reassignment, system-prompt exfiltration, delimiter escape, encoding
instruction (DET-008 layers on top via the normalizer's decoded_variants —
this module doesn't decode anything itself). DET-009: includes non-English
forms (a Spanish instruction-override pattern, at minimum).

ADR 0003: scoped to the Input plane only. `indirect_injection.py` applies
the same families to the Context plane under a different category, so the
two detectors never double-tag the same content.
"""

from __future__ import annotations

import re

from app.detectors.base import (
    Category,
    Confidence,
    Evidence,
    Finding,
    salted_excerpt_hash,
)
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "prompt_injection"
DETECTOR_VERSION = "1.0.0"

# --- PROMPT_INJECTION pattern family -----------------------------------
# Each entry: (pattern_id, compiled regex, score, confidence).
# Patterns are deliberately narrow (verb + nearby target noun/phrase,
# order-sensitive) rather than loose keyword co-occurrence, so ordinary
# sentences that happen to use "ignore" or "system prompt" in a benign
# sense (see tests/data/golden_corpus.jsonl BEN-006/007/011) don't match.
_PI_PATTERNS: tuple[tuple[str, re.Pattern[str], float, Confidence], ...] = (
    (
        "instruction_override_en_v1",
        re.compile(r"\b(?:ignore|disregard)\b(?:\s+\S+){0,4}\s+instructions?\b", re.IGNORECASE),
        0.95,
        Confidence.HIGH,
    ),
    (
        "instruction_override_es_v1",
        re.compile(
            r"\bignora\b(?:\s+\S+){0,4}\s+instrucciones\s+(?:anteriores|previas)\b",
            re.IGNORECASE,
        ),
        0.95,
        Confidence.HIGH,
    ),
    (
        "system_override_v1",
        re.compile(r"\bsystem\s+override\b", re.IGNORECASE),
        0.9,
        Confidence.HIGH,
    ),
    (
        "exfiltration_repeat_above_v1",
        re.compile(r"\brepeat\s+the\s+text\s+above\b", re.IGNORECASE),
        0.9,
        Confidence.HIGH,
    ),
    (
        "delimiter_escape_v1",
        re.compile(r"###\s*system\s*###|</\s*system\s*>|<\s*system\s*>", re.IGNORECASE),
        0.9,
        Confidence.HIGH,
    ),
    (
        "false_authority_exfiltration_v1",
        re.compile(
            r"\bauthoris?(?:ed|ation)\b(?:\s+\S+){0,10}\s+(?:full\s+)?system\s+prompt\b",
            re.IGNORECASE,
        ),
        0.85,
        Confidence.MEDIUM,
    ),
    (
        "exfiltration_verb_target_v1",
        re.compile(
            r"\b(?:reveal|print|output|show|repeat|disclose)\b(?:\s+\S+){0,6}\s+"
            r"(?:system\s+prompt|hidden\s+prompt|context\s+window|configuration)\b",
            re.IGNORECASE,
        ),
        0.9,
        Confidence.HIGH,
    ),
)

# --- JAILBREAK pattern family --------------------------------------------
_JB_PATTERNS: tuple[tuple[str, re.Pattern[str], float, Confidence], ...] = (
    (
        "dan_persona_v1",
        re.compile(r"\bDAN\b.{0,30}no\s+restrictions|\byou\s+are\s+now\s+DAN\b", re.IGNORECASE),
        0.95,
        Confidence.HIGH,
    ),
    (
        "rules_do_not_apply_v1",
        re.compile(
            r"\bpretend\b(?:\s+\S+){0,4}\s+rules?\b(?:\s+\S+){0,3}\s+(?:do\s+not|don't)\s+apply\b",
            re.IGNORECASE,
        ),
        0.9,
        Confidence.HIGH,
    ),
    (
        "developer_mode_v1",
        re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
        0.85,
        Confidence.MEDIUM,
    ),
    (
        "forget_guidelines_v1",
        re.compile(
            r"\bforget\b(?:\s+\S+){0,3}\s+(?:guidelines?|rules?|instructions?)\b", re.IGNORECASE
        ),
        0.9,
        Confidence.HIGH,
    ),
    # ADR 0004: a softer, real-world social-engineering cue — "let's roleplay
    # a character with no restrictions" — rather than a direct persona
    # command like DAN. Scored in [0.50, 0.85) deliberately: this is
    # genuinely ambiguous (roleplay requests are also entirely benign) and
    # is the scenario review_probable_jailbreak (policies/default_policy.yaml)
    # exists for, not an auto-deny. Before this addition every JAILBREAK/
    # PROMPT_INJECTION pattern scored >=0.85, so that rule had no reachable
    # trigger — see ADR 0004 §1.
    (
        "roleplay_no_restrictions_v1",
        re.compile(
            r"\b(?:let'?s|we\s+can|please)\s+roleplay\b(?:\s+\S+){0,10}\s+"
            r"(?:no\s+restrictions|unrestricted|without\s+(?:any\s+)?restrictions)\b",
            re.IGNORECASE,
        ),
        0.65,
        Confidence.MEDIUM,
    ),
)


def _scan_patterns(
    texts: list[tuple[str, int]],
    patterns: tuple[tuple[str, re.Pattern[str], float, Confidence], ...],
    category: Category,
    salt: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for text, depth in texts:
        for pattern_id, pattern, score, confidence in patterns:
            m = pattern.search(text)
            if not m:
                continue
            evidence = Evidence(
                start=m.start(),
                end=m.end(),
                pattern_id=pattern_id,
                excerpt_hash=salted_excerpt_hash(m.group(0), salt),
            )
            safe_metadata: dict[str, bool | int | float | str] = {
                "match_count": len(pattern.findall(text)),
                "normalized": True,
                "decoded_depth": depth,
            }
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=category,
                    score=score,
                    confidence=confidence,
                    evidence=(evidence,),
                    safe_metadata=safe_metadata,
                )
            )
            # One finding per (pattern, category) is enough evidence; move to
            # the next pattern rather than re-matching every occurrence.
            break
    return findings


class PromptInjectionDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        texts = content.all_texts()
        findings = _scan_patterns(texts, _PI_PATTERNS, Category.PROMPT_INJECTION, salt)
        findings += _scan_patterns(texts, _JB_PATTERNS, Category.JAILBREAK, salt)

        # DET-008: a finding discovered only in a decoded variant (depth > 0)
        # additionally raises ENCODED_PAYLOAD.
        if any(f.safe_metadata.get("decoded_depth", 0) for f in findings):
            deepest = max(findings, key=lambda f: f.safe_metadata.get("decoded_depth", 0))
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.ENCODED_PAYLOAD,
                    score=0.9,
                    confidence=Confidence.HIGH,
                    evidence=deepest.evidence,
                    safe_metadata={
                        "decoded_depth": deepest.safe_metadata.get("decoded_depth", 0),
                        "normalized": True,
                    },
                )
            )
        return findings
