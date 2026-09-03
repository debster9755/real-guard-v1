"""`schema` detector. SPEC.md §6.4: "Structural validation | Message shapes,
tool-argument JSON." Category: SCHEMA_VIOLATION.

Phase 2 scope (ADR 0003): message-shape validation only. Tool-argument JSON
validation is DET-018's job, implemented alongside the tool_calls detector
in Phase 3 — it belongs there because it needs the parsed tool-call
structure this module doesn't otherwise touch.

This detector operates on the raw message dict, not on NormalizedContent's
text — structural shape is a property of the message, not of its content —
so its `scan` signature intentionally takes an extra `messages` argument
alongside the base Detector protocol's (content, plane, salt). It's still
called through the same orchestrator path; see app/orchestrator.py.
"""

from __future__ import annotations

from typing import Any

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "schema"
DETECTOR_VERSION = "1.0.0"

_VALID_ROLES = {"system", "user", "assistant", "tool"}


class SchemaDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input, Plane.context})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        # Text-only scan finds nothing to validate; use scan_message for the
        # structural check the orchestrator actually invokes per message.
        return []

    def scan_message(self, message: dict[str, Any], salt: str) -> list[Finding]:
        findings: list[Finding] = []
        role = message.get("role")
        if role not in _VALID_ROLES:
            findings.append(self._violation(f"invalid role: {role!r}", "invalid_role_v1", salt))
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            findings.append(
                self._violation(
                    f"content must be a string or null, got {type(content).__name__}",
                    "invalid_content_type_v1",
                    salt,
                )
            )
        return findings

    def _violation(self, detail: str, pattern_id: str, salt: str) -> Finding:
        return Finding(
            detector_id=DETECTOR_ID,
            detector_version=DETECTOR_VERSION,
            category=Category.SCHEMA_VIOLATION,
            score=0.5,
            confidence=Confidence.LOW,
            evidence=(
                Evidence(
                    start=0,
                    end=0,
                    pattern_id=pattern_id,
                    excerpt_hash=salted_excerpt_hash(detail, salt),
                ),
            ),
            safe_metadata={"detail_class": pattern_id},
        )
