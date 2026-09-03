"""Detector contract. SPEC.md §6.1 (DET-001, DET-002), §6.2 (DET-003..006).

Every detector is a pure function of its inputs (DET-001/002): no I/O, no
mutable state across calls, no clock reads, no content in logs. The
`scan(content, plane, salt)` signature extends SPEC's illustrative
`scan(content, plane)` sketch with a `salt` parameter — required to compute
the salted evidence hash DET-004 demands, while keeping the function pure
(the salt is an explicit input, not hidden state).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from app.normalizer import NormalizedContent
from app.planes import Plane


class Confidence(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Category(StrEnum):
    """The subset of the SPEC.md §5.7 reason-code taxonomy that detectors
    (as opposed to the policy engine itself) actually emit as finding
    categories."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    ENCODED_PAYLOAD = "ENCODED_PAYLOAD"
    PII_DETECTED = "PII_DETECTED"
    SECRET_DETECTED = "SECRET_DETECTED"  # noqa: S105 — a taxonomy label, not a credential
    BLOCKED_TOPIC = "BLOCKED_TOPIC"
    SENSITIVE_TOPIC = "SENSITIVE_TOPIC"
    OUTPUT_PII = "OUTPUT_PII"
    OUTPUT_SECRET = "OUTPUT_SECRET"  # noqa: S105 — a taxonomy label, not a credential
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    CANARY_LEAK = "CANARY_LEAK"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    SENSITIVE_ACTION = "SENSITIVE_ACTION"
    DESTRUCTIVE_ACTION = "DESTRUCTIVE_ACTION"
    TOOL_NOT_ALLOWLISTED = "TOOL_NOT_ALLOWLISTED"
    DETECTOR_TIMEOUT = "DETECTOR_TIMEOUT"  # POL-007: the orchestrator emits this as a Finding


@dataclass(frozen=True)
class Evidence:
    """DET-004: offsets + pattern id + a salted hash of the matched span.
    Never the matched text itself, unless CONTENT_RETENTION=full — and even
    then, that's a policy for a *caller* to apply on top of this; the
    detector itself never carries raw text in evidence."""

    start: int
    end: int
    pattern_id: str
    excerpt_hash: str  # "sha256:<hex>"


@dataclass(frozen=True)
class Finding:
    detector_id: str
    detector_version: str
    category: Category
    score: float  # DET-005: in [0.0, 1.0]
    confidence: Confidence
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    safe_metadata: dict[str, bool | int | float | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise ValueError(f"score must be in [0.0, 1.0], got {self.score}")


def salted_excerpt_hash(text: str, salt: str) -> str:
    """DET-004's "salted hash of the matched span," as sha256(salt || text)."""
    digest = hashlib.sha256((salt + text).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class Detector(Protocol):
    """DET-001. `scan` MUST be a pure function: same content+plane+salt in,
    same findings out, every time."""

    detector_id: str
    detector_version: str
    supported_planes: frozenset[Plane]

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]: ...
