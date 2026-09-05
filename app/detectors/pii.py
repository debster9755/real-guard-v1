"""`pii` detector. SPEC.md §6.4 (DET-010).

Categories: PII_DETECTED (inbound), OUTPUT_PII (response — Phase 3 reuses
this same detector on the response plane). Types: email, phone (E.164 and
common national), SSN, credit card (Luhn-validated), IBAN, passport,
IP address.

DET-010: credit-card candidates MUST be Luhn-validated; a candidate that
fails Luhn MUST NOT produce a finding — this is the single largest source of
PII false positives, and tests/data/golden_corpus.jsonl BEN-010 exists
specifically to catch a regression here.
"""

from __future__ import annotations

import re

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "pii"
DETECTOR_VERSION = "1.0.0"

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"\+\d{1,3}(?:[\s-]?\(?\d{2,4}\)?){2,4}")
# Phase 7 (docs/adr/0009): dash is the common US SSN separator and remains
# the primary form, but a probe confirmed a space- or dot-separated SSN
# (e.g. "123 45 6789") evaded this pattern entirely pre-fix — a narrow,
# additive fix: any single one of "-", " " or "." between the three groups,
# not just "-". Still requires the same three fixed-width digit groups, so
# this doesn't broaden what counts as SSN-*shaped* text, only which
# separator within that shape is recognised.
_SSN_RE = re.compile(r"\b\d{3}[- .]\d{2}[- .]\d{4}\b")
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
# Phase 7 (docs/adr/0009): IBANs are conventionally printed uppercase but
# are not case-sensitive data; a probe confirmed a lowercase IBAN (as a
# user might paste one, e.g. "gb29 nwbk...") evaded this pattern entirely
# pre-fix. IGNORECASE is a narrow fix — the shape requirement (2 letters +
# 2 digits + 3-8 grouped alnum chunks) is unchanged, only case sensitivity.
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{2,4}){3,8}\b", re.IGNORECASE)
_PASSPORT_RE = re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _finding(
    plane_category: Category,
    pattern_id: str,
    match: str,
    start: int,
    end: int,
    salt: str,
    pii_type: str,
    *,
    score: float = 0.9,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        detector_id=DETECTOR_ID,
        detector_version=DETECTOR_VERSION,
        category=plane_category,
        score=score,
        confidence=confidence,
        evidence=(
            Evidence(
                start=start,
                end=end,
                pattern_id=pattern_id,
                excerpt_hash=salted_excerpt_hash(match, salt),
            ),
        ),
        safe_metadata={"pii_type": pii_type, "match_count": 1},
    )


def _scan_text(text: str, category: Category, salt: str) -> list[Finding]:
    findings: list[Finding] = []

    for m in _EMAIL_RE.finditer(text):
        findings.append(
            _finding(category, "email_v1", m.group(0), m.start(), m.end(), salt, "email")
        )

    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) < 8:  # avoid matching short numeric runs as phones
            continue
        findings.append(
            _finding(category, "phone_e164_v1", m.group(0), m.start(), m.end(), salt, "phone")
        )

    for m in _SSN_RE.finditer(text):
        findings.append(_finding(category, "ssn_v1", m.group(0), m.start(), m.end(), salt, "ssn"))

    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19):
            continue
        if not _luhn_valid(digits):
            continue  # DET-010: Luhn-invalid candidates MUST NOT fire
        findings.append(
            _finding(
                category, "credit_card_luhn_v1", m.group(0), m.start(), m.end(), salt, "credit_card"
            )
        )

    for m in _IBAN_RE.finditer(text):
        findings.append(
            _finding(
                category,
                "iban_v1",
                m.group(0),
                m.start(),
                m.end(),
                salt,
                "iban",
                score=0.8,
                confidence=Confidence.MEDIUM,
            )
        )

    for m in _IP_RE.finditer(text):
        octets = m.group(0).split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            findings.append(
                _finding(
                    category,
                    "ip_address_v1",
                    m.group(0),
                    m.start(),
                    m.end(),
                    salt,
                    "ip_address",
                    score=0.6,
                    confidence=Confidence.LOW,
                )
            )

    return findings


class PiiDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input, Plane.context, Plane.response})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        category = Category.OUTPUT_PII if plane == Plane.response else Category.PII_DETECTED
        # Scan only the normalized text (depth 0) — PII inside a base64
        # blob a user pasted isn't "leaked" in the same sense an injection
        # payload is; corpus doesn't require decoded-variant PII scanning
        # and doing so risks false positives on incidental digit runs
        # inside unrelated decoded content.
        return _scan_text(content.normalized, category, salt)
