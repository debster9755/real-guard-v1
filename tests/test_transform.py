"""WS-05 transformation pipeline tests. SPEC.md §8 (TRN-001..009)."""

from __future__ import annotations

from app.transform import RedactionSpan, _merge_overlapping, apply_redact, apply_transformations


def test_redact_email() -> None:
    text = "Contact alice@example.com for details."
    redacted, record = apply_redact(text)
    assert "alice@example.com" not in redacted
    assert "[REDACTED:EMAIL]" in redacted
    assert record.transformation == "REDACT"
    assert record.labels == ("EMAIL",)


def test_redact_no_match_returns_none_transformation() -> None:
    text = "Nothing sensitive here."
    redacted, record = apply_redact(text)
    assert redacted == text
    assert record.transformation == "NONE"
    assert record.span_count == 0


def test_redact_luhn_invalid_card_not_redacted() -> None:
    """DET-010's rule applies to the transformation pipeline too — a
    Luhn-invalid candidate must not be redacted (nothing to redact)."""
    text = "Card 4111 1111 1111 1112 was declined."
    redacted, record = apply_redact(text)
    assert redacted == text
    assert record.span_count == 0


def test_record_never_contains_original_value_trn006() -> None:
    text = "SSN 123-45-6789 on file."
    _redacted, record = apply_redact(text)
    record_repr = repr(record)
    assert "123-45-6789" not in record_repr


def test_overlapping_spans_merge_trn004() -> None:
    spans = [RedactionSpan(0, 10, "EMAIL"), RedactionSpan(5, 15, "PHONE")]
    merged = _merge_overlapping(spans)
    assert len(merged) == 1
    assert merged[0].start == 0
    assert merged[0].end == 15


def test_non_overlapping_spans_stay_separate() -> None:
    spans = [RedactionSpan(0, 5, "EMAIL"), RedactionSpan(10, 15, "PHONE")]
    merged = _merge_overlapping(spans)
    assert len(merged) == 2


def test_higher_sensitivity_wins_on_overlap() -> None:
    spans = [RedactionSpan(0, 10, "EMAIL"), RedactionSpan(5, 15, "PEM_PRIVATE_KEY")]
    merged = _merge_overlapping(spans)
    assert merged[0].label == "PEM_PRIVATE_KEY"


def test_apply_transformations_empty_set_is_noop() -> None:
    text = "alice@example.com"
    result, record = apply_transformations(text, set())
    assert result == text
    assert record.transformation == "NONE"


def test_apply_transformations_redact() -> None:
    text = "alice@example.com"
    result, _record = apply_transformations(text, {"REDACT"})
    assert "[REDACTED:EMAIL]" in result


def test_multiple_pii_types_all_redacted() -> None:
    text = "Email me at a@b.com or call +1 415 555 0199."
    redacted, record = apply_redact(text)
    assert "a@b.com" not in redacted
    assert "415" not in redacted or "[REDACTED:PHONE]" in redacted
    assert set(record.labels) == {"EMAIL", "PHONE"}
