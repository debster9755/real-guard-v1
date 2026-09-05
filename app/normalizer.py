"""Request normalizer. SPEC.md §2.2 (SYS-011, SYS-012), §6.3 (DET-007, DET-008).

Detection-only: this module MUST NOT mutate the payload that is eventually
forwarded upstream (§2.2 prohibited responsibilities) — its output feeds
detectors, never the wire. The transformation pipeline (app/transform.py) is
the only component permitted to alter forwarded content.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# DET-007: characters stripped before detection.
# Phase 7 (docs/adr/0009) additions, found by the adversarial-evasion pass:
# WORD JOINER (U+2060) and three of the four invisible math operators
# (U+2061 FUNCTION APPLICATION, U+2062 INVISIBLE TIMES, U+2063 INVISIBLE
# SEPARATOR — U+2064 INVISIBLE PLUS is included too, for the same reason)
# and SOFT HYPHEN (U+00AD) all evaded detection pre-fix exactly like the
# zero-width characters already stripped here: invisible-by-default,
# insertable mid-word, and outside the previous _ZERO_WIDTH/_BIDI_CONTROLS
# sets. A confirmed real gap, fixed narrowly rather than left residual —
# see the Phase 7 completion report for the before/after probe.
_ZERO_WIDTH = "​‌‍‎‏﻿⁠⁡⁢⁣⁤­"
_BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩"
# Variation selectors (U+FE00-FE0F) are invisible modifiers for a preceding
# base character (their usual job is picking an emoji-vs-text glyph); one
# inserted after an ordinary ASCII letter renders invisibly and, like the
# characters above, evaded detection pre-fix. Stripped as a full 16-code-
# point range rather than named individually.
_VARIATION_SELECTORS = "".join(chr(cp) for cp in range(0xFE00, 0xFE10))
_STRIP_CHARS = _ZERO_WIDTH + _BIDI_CONTROLS + _VARIATION_SELECTORS

# A small, explicit confusables table — common Cyrillic/Greek lookalikes
# folded to their ASCII look-alike. Not exhaustive (a full Unicode
# confusables table is a V1.1-scale undertaking); DET-009 already accepts
# that no detector is complete against every encoding, and normalization
# is one layer, not a guarantee. Phase 7 (docs/adr/0009) added lowercase
# Cyrillic "т"/Greek "τ" (both visually near-identical to Latin "t" —
# only their uppercase forms were folded before) and Cyrillic "ѕ" (visually
# identical to Latin "s"), each confirmed to evade the prompt_injection
# detector pre-fix via a direct probe against "instrucтions"/"instrucτions".
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "т": "t", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "і": "i", "І": "I",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "υ": "y", "τ": "t", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}  # fmt: skip

_WHITESPACE_RE = re.compile(r"\s+")

_MAX_DECODE_DEPTH_DEFAULT = 3
_MIN_PRINTABLE_RATIO = 0.85

_BASE64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_CANDIDATE_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# Realistic percent-encoded text mixes literal characters with %XX escapes
# (e.g. "Ignore%20all%20previous%20instructions"), not a pure run of
# consecutive escapes — so the candidate span is any run of URL-safe
# characters *or* escapes, filtered afterward by escape count.
_PERCENT_CANDIDATE_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9_.~-]){10,}")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_MIN_PERCENT_ESCAPES = 3


def _strip_chars(text: str, chars: str) -> str:
    return "".join(c for c in text if c not in chars)


def _fold_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(c, c) for c in text)


def _collapse_whitespace(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", text).strip()


def normalize_text(text: str) -> str:
    """The pure, idempotent normalization function (SYS-011). NFKC ->
    strip zero-width/bidi -> fold homoglyphs -> collapse whitespace.

    Each step is individually idempotent (NFKC on already-NFKC text is a
    no-op; stripping characters already stripped is a no-op; folding
    characters that only ever map to themselves-or-ASCII is a no-op the
    second time since ASCII isn't a dict key; collapsing already-single
    whitespace is a no-op) so the composition is idempotent too — verified
    by a Hypothesis property test, not just asserted here.
    """
    t = unicodedata.normalize("NFKC", text)
    t = _strip_chars(t, _STRIP_CHARS)
    t = _fold_homoglyphs(t)
    t = _collapse_whitespace(t)
    return t


def _looks_like_text(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return (printable / len(s)) >= _MIN_PRINTABLE_RATIO


def _try_decode_base64(candidate: str) -> str | None:
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        raw = base64.b64decode(padded, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _looks_like_text(text) else None


def _try_decode_hex(candidate: str) -> str | None:
    try:
        raw = bytes.fromhex(candidate)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _looks_like_text(text) else None


def _try_decode_percent(candidate: str) -> str | None:
    if len(_PERCENT_ESCAPE_RE.findall(candidate)) < _MIN_PERCENT_ESCAPES:
        return None  # too few escapes to be worth treating as an encoded payload
    try:
        text = unquote(candidate, errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if text == candidate:  # nothing actually decoded
        return None
    return text if _looks_like_text(text) else None


_DECODERS: tuple[tuple[str, re.Pattern[str], object], ...] = (
    ("base64", _BASE64_CANDIDATE_RE, _try_decode_base64),
    ("hex", _HEX_CANDIDATE_RE, _try_decode_hex),
    ("percent", _PERCENT_CANDIDATE_RE, _try_decode_percent),
)


@dataclass(frozen=True)
class DecodedVariant:
    text: str
    depth: int
    encoding: str  # "base64" | "hex" | "percent"


@dataclass(frozen=True)
class NormalizedContent:
    """SYS-012: decoded_variants is bounded to max_decode_depth layers."""

    original: str
    normalized: str
    decoded_variants: tuple[DecodedVariant, ...] = field(default_factory=tuple)
    had_decode_error: bool = False

    def all_texts(self) -> list[tuple[str, int]]:
        """(text, decoded_depth) pairs a detector should scan: the
        normalized text at depth 0, plus every decoded variant."""
        result: list[tuple[str, int]] = [(self.normalized, 0)]
        result.extend((v.text, v.depth) for v in self.decoded_variants)
        return result


def _decode_variants(text: str, max_depth: int) -> tuple[list[DecodedVariant], bool]:
    variants: list[DecodedVariant] = []
    seen: set[str] = {text}
    frontier = [text]
    had_error = False

    for depth in range(1, max_depth + 1):
        next_frontier: list[str] = []
        for candidate_text in frontier:
            for encoding, pattern, decoder in _DECODERS:
                for m in pattern.finditer(candidate_text):
                    raw_candidate = m.group(0)
                    try:
                        decoded = decoder(raw_candidate)  # type: ignore[operator]
                    except Exception:  # noqa: BLE001 — normalizer MUST NOT raise (§2.2)
                        had_error = True
                        continue
                    if decoded and decoded not in seen:
                        seen.add(decoded)
                        normalized_decoded = normalize_text(decoded)
                        variants.append(
                            DecodedVariant(text=normalized_decoded, depth=depth, encoding=encoding)
                        )
                        next_frontier.append(normalized_decoded)
        if not next_frontier:
            break
        frontier = next_frontier

    return variants, had_error


def normalize(text: str, *, max_decode_depth: int = _MAX_DECODE_DEPTH_DEFAULT) -> NormalizedContent:
    """Full normalization: detection-time text plus bounded decoded
    variants. MUST NOT raise (§2.2 failure behaviour) — any internal error
    is swallowed and surfaced as had_decode_error instead.
    """
    had_error = False
    try:
        normalized = normalize_text(text)
    except Exception:  # noqa: BLE001 — normalizer MUST NOT raise
        normalized = text
        had_error = True

    try:
        variants, decode_had_error = _decode_variants(normalized, max_decode_depth)
    except Exception:  # noqa: BLE001 — defensive; MUST NOT raise
        variants, decode_had_error = [], True

    return NormalizedContent(
        original=text,
        normalized=normalized,
        decoded_variants=tuple(variants),
        had_decode_error=had_error or decode_had_error,
    )
