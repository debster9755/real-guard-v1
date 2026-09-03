"""Transformation pipeline. SPEC.md §8 (TRN-001..009).

Phase 2 scope (ADR 0003): REDACT only — the only transformation any
in-scope corpus case (PII_INPUT, SECRET_INPUT) requires. MASK/SANITIZE/
REWRITE/TRUNCATE are specified (TRN-002) but have no Phase-2 caller; they
arrive with the output guard and tool-call rules in Phase 3.

Design note on offsets: detector findings carry offsets into *normalized*
text (NFKC + homoglyph-folded + whitespace-collapsed), which is not
generally position- or even length-preserving against the *original* text
that must actually be forwarded upstream (TRN-006 also forbids emitting
original values anywhere, which offset-translation machinery would risk
getting subtly wrong). Rather than build lossy Unicode offset-translation,
this module re-scans the *original* text directly with the same PII/secret
patterns to get offsets valid against what's actually being transformed —
duplicating a regex pass, not duplicating detection logic (the patterns are
imported, not re-implemented).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.detectors.pii import (
    _CARD_CANDIDATE_RE,
    _EMAIL_RE,
    _IBAN_RE,
    _PHONE_RE,
    _SSN_RE,
    _luhn_valid,
)
from app.detectors.secrets import _AWS_ACCESS_KEY_RE, _JWT_RE, _PEM_BLOCK_RE, _PROVIDER_KEY_RE

# TRN-003: fixed pipeline order.
TRANSFORMATION_ORDER = ("TRUNCATE", "SANITIZE", "REWRITE", "REDACT", "MASK")

# Priority for TRN-004 overlap merging: higher wins when two spans overlap.
_SENSITIVITY_RANK = {
    "PEM_PRIVATE_KEY": 6,
    "AWS_ACCESS_KEY": 5,
    "PROVIDER_API_KEY": 5,
    "JWT": 5,
    "SSN": 4,
    "CREDIT_CARD": 4,
    "IBAN": 3,
    "EMAIL": 2,
    "PHONE": 2,
}


@dataclass(frozen=True)
class RedactionSpan:
    start: int
    end: int
    label: str


@dataclass(frozen=True)
class TransformationRecord:
    """TRN-005: transformation, span count, categories affected, per-span
    offsets/lengths. Deliberately carries no original values."""

    transformation: str
    span_count: int
    labels: tuple[str, ...]
    spans: tuple[tuple[int, int], ...]  # (offset, length) pairs


class TransformationError(Exception):
    """TRN-007: a caller MUST treat this as fail-closed — DENY with
    TRANSFORMATION_FAILED — never forward partially-transformed content."""


def _find_redaction_spans(text: str) -> list[RedactionSpan]:
    spans: list[RedactionSpan] = []

    for m in _EMAIL_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "EMAIL"))
    for m in _PHONE_RE.finditer(text):
        digits = "".join(c for c in m.group(0) if c.isdigit())
        if len(digits) >= 8:
            spans.append(RedactionSpan(m.start(), m.end(), "PHONE"))
    for m in _SSN_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "SSN"))
    for m in _CARD_CANDIDATE_RE.finditer(text):
        digits = m.group(0).replace(" ", "").replace("-", "")
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            spans.append(RedactionSpan(m.start(), m.end(), "CREDIT_CARD"))
    for m in _IBAN_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "IBAN"))
    for m in _AWS_ACCESS_KEY_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "AWS_ACCESS_KEY"))
    for m in _PROVIDER_KEY_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "PROVIDER_API_KEY"))
    for m in _PEM_BLOCK_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "PEM_PRIVATE_KEY"))
    for m in _JWT_RE.finditer(text):
        spans.append(RedactionSpan(m.start(), m.end(), "JWT"))

    return _merge_overlapping(spans)


def _merge_overlapping(spans: list[RedactionSpan]) -> list[RedactionSpan]:
    """TRN-004: overlapping spans merge into one, taking the
    highest-sensitivity contributing finding's label."""
    if not spans:
        return []
    ordered = sorted(spans, key=lambda s: s.start)
    merged: list[RedactionSpan] = [ordered[0]]
    for span in ordered[1:]:
        last = merged[-1]
        if span.start < last.end:  # overlap
            winner = (
                span
                if _SENSITIVITY_RANK.get(span.label, 0) > _SENSITIVITY_RANK.get(last.label, 0)
                else last
            )
            merged[-1] = RedactionSpan(
                min(last.start, span.start), max(last.end, span.end), winner.label
            )
        else:
            merged.append(span)
    return merged


def apply_redact(text: str) -> tuple[str, TransformationRecord]:
    """Returns (transformed_text, record). Raises TransformationError only
    on a genuine internal failure (TRN-007) — an empty result is a valid,
    successful "nothing to redact" outcome, not a failure."""
    try:
        spans = _find_redaction_spans(text)
        if not spans:
            return text, TransformationRecord("NONE", 0, (), ())

        result = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            placeholder = f"[REDACTED:{span.label}]"
            result = result[: span.start] + placeholder + result[span.end :]

        record = TransformationRecord(
            transformation="REDACT",
            span_count=len(spans),
            labels=tuple(sorted({s.label for s in spans})),
            spans=tuple((s.start, s.end - s.start) for s in spans),
        )
        return result, record
    except Exception as e:  # noqa: BLE001 — TRN-007: fail closed, never partially transform
        raise TransformationError(f"redaction failed: {type(e).__name__}") from e


def apply_transformations(
    text: str, transformation_types: set[str]
) -> tuple[str, TransformationRecord]:
    """Applies whichever of `transformation_types` are requested, in
    TRN-003's fixed order. Phase 2 only ever passes {"REDACT"} or {} — the
    loop structure is here so Phase 3 can add MASK/SANITIZE/REWRITE/TRUNCATE
    callers without changing this function's contract.
    """
    result = text
    last_record = TransformationRecord("NONE", 0, (), ())
    for t in TRANSFORMATION_ORDER:
        if t not in transformation_types:
            continue
        if t == "REDACT":
            result, last_record = apply_redact(result)
        # MASK/SANITIZE/REWRITE/TRUNCATE: no Phase-2 caller (ADR 0003).
    return result, last_record


def apply_transformation_to_messages(
    messages: list[dict[str, Any]], transformation: str
) -> list[dict[str, Any]]:
    """Applies `transformation` to every string message `content`, leaving
    everything else untouched. Shared by the immediate-ALLOW path
    (app/main.py) and approval creation (app/approvals.py — ADR 0004): the
    same transformed content that gets forwarded upstream synchronously on
    ALLOW is what the approval's `transformed_payload` resumes with once a
    reviewer approves, and what its `preview_content` shows them (APR-012,
    TRN-008) — one code path, so the two can never silently drift apart.
    """
    if transformation == "NONE":
        return messages
    transformed: list[dict[str, Any]] = []
    for m in messages:
        if isinstance(m.get("content"), str):
            new_content, _record = apply_transformations(m["content"], {transformation})
            transformed.append({**m, "content": new_content})
        else:
            transformed.append(m)
    return transformed
