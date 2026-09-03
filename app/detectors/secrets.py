"""`secrets` detector. SPEC.md §6.4.

Categories: SECRET_DETECTED (inbound), OUTPUT_SECRET (response — Phase 3
reuses this detector on the response plane). Types: AWS access keys,
`sk-`/`gsk_`/`ghp_`-prefixed provider keys, PEM private-key blocks, JWTs.

A generic Shannon-entropy "any long random-looking string" detector is
deliberately not implemented: it would fire on base64-encoded injection
payloads (see tests/data/golden_corpus.jsonl ENC-001) and other legitimate
high-entropy content, and the corpus doesn't require it — the four named
formats below cover every SCR-* case with named, auditable patterns instead.
"""

from __future__ import annotations

import re

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "secrets"
DETECTOR_VERSION = "1.0.0"

_AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PROVIDER_KEY_RE = re.compile(r"\b(?:sk-live-|sk-test-|sk-|gsk_|ghp_)[A-Za-z0-9_-]{16,}\b")
_PEM_BLOCK_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def _finding(
    category: Category,
    pattern_id: str,
    secret_type: str,
    match: str,
    start: int,
    end: int,
    salt: str,
) -> Finding:
    return Finding(
        detector_id=DETECTOR_ID,
        detector_version=DETECTOR_VERSION,
        category=category,
        score=0.95,
        confidence=Confidence.HIGH,
        evidence=(
            Evidence(
                start=start,
                end=end,
                pattern_id=pattern_id,
                excerpt_hash=salted_excerpt_hash(match, salt),
            ),
        ),
        safe_metadata={"secret_type": secret_type, "match_count": 1},
    )


def _scan_text(text: str, category: Category, salt: str) -> list[Finding]:
    findings: list[Finding] = []

    for m in _AWS_ACCESS_KEY_RE.finditer(text):
        findings.append(
            _finding(
                category,
                "aws_access_key_v1",
                "aws_access_key",
                m.group(0),
                m.start(),
                m.end(),
                salt,
            )
        )

    for m in _PROVIDER_KEY_RE.finditer(text):
        findings.append(
            _finding(
                category,
                "provider_api_key_v1",
                "provider_api_key",
                m.group(0),
                m.start(),
                m.end(),
                salt,
            )
        )

    for m in _PEM_BLOCK_RE.finditer(text):
        findings.append(
            _finding(
                category,
                "pem_private_key_v1",
                "pem_private_key",
                m.group(0),
                m.start(),
                m.end(),
                salt,
            )
        )

    for m in _JWT_RE.finditer(text):
        findings.append(_finding(category, "jwt_v1", "jwt", m.group(0), m.start(), m.end(), salt))

    return findings


class SecretsDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input, Plane.context, Plane.response})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        category = Category.OUTPUT_SECRET if plane == Plane.response else Category.SECRET_DETECTED
        return _scan_text(content.normalized, category, salt)
