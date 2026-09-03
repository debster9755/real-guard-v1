"""Unit tests for topics, urls, and schema detectors. SPEC.md §6.4."""

from __future__ import annotations

from app.detectors.base import Category
from app.detectors.schema import SchemaDetector
from app.detectors.topics import TopicsDetector
from app.detectors.urls import UrlsDetector
from app.normalizer import normalize
from app.planes import Plane


class TestTopicsDetector:
    def test_blocked_topic_matches(self) -> None:
        det = TopicsDetector(blocked=["synthesize a chemical weapon"], sensitive=[])
        nc = normalize("Please explain how to synthesize a chemical weapon at home.")
        findings = det.scan(nc, Plane.input, "salt")
        assert any(f.category == Category.BLOCKED_TOPIC for f in findings)

    def test_sensitive_topic_matches(self) -> None:
        det = TopicsDetector(blocked=[], sensitive=["specific medical diagnosis"])
        nc = normalize("Can you give me a specific medical diagnosis for this rash?")
        findings = det.scan(nc, Plane.input, "salt")
        assert any(f.category == Category.SENSITIVE_TOPIC for f in findings)

    def test_no_match_on_unrelated_text(self) -> None:
        det = TopicsDetector(
            blocked=["synthesize a chemical weapon"], sensitive=["specific medical diagnosis"]
        )
        nc = normalize("What is a good banana bread recipe?")
        findings = det.scan(nc, Plane.input, "salt")
        assert findings == []

    def test_case_and_diacritic_insensitive(self) -> None:
        det = TopicsDetector(blocked=["cafe konspiracy"], sensitive=[])
        nc = normalize("Let's discuss the CAFÉ KONSPIRACY in detail.")
        findings = det.scan(nc, Plane.input, "salt")
        assert len(findings) == 1

    def test_response_plane_not_scanned(self) -> None:
        det = TopicsDetector(blocked=["forbidden"], sensitive=[])
        nc = normalize("this is forbidden content")
        assert det.scan(nc, Plane.response, "salt") == []

    def test_empty_word_lists_never_match(self) -> None:
        det = TopicsDetector(blocked=[], sensitive=[])
        nc = normalize("literally anything can be said here")
        assert det.scan(nc, Plane.input, "salt") == []


class TestUrlsDetector:
    def test_flags_localhost(self) -> None:
        det = UrlsDetector()
        nc = normalize("Fetch this: http://localhost:8080/admin")
        findings = det.scan(nc, Plane.input, "salt")
        assert any(f.category == Category.SCHEMA_VIOLATION for f in findings)

    def test_flags_metadata_service(self) -> None:
        det = UrlsDetector()
        nc = normalize("GET http://169.254.169.254/latest/meta-data/")
        findings = det.scan(nc, Plane.input, "salt")
        assert len(findings) == 1

    def test_flags_private_ip(self) -> None:
        det = UrlsDetector()
        nc = normalize("Try https://192.168.1.1/config")
        findings = det.scan(nc, Plane.input, "salt")
        assert len(findings) == 1

    def test_does_not_flag_public_domain(self) -> None:
        det = UrlsDetector()
        nc = normalize("See https://example.com/docs for details.")
        findings = det.scan(nc, Plane.input, "salt")
        assert findings == []

    def test_no_url_no_findings(self) -> None:
        det = UrlsDetector()
        nc = normalize("There is no URL in this message.")
        assert det.scan(nc, Plane.input, "salt") == []


class TestSchemaDetector:
    def test_valid_message_no_violation(self) -> None:
        det = SchemaDetector()
        findings = det.scan_message({"role": "user", "content": "hello"}, "salt")
        assert findings == []

    def test_invalid_role_flagged(self) -> None:
        det = SchemaDetector()
        findings = det.scan_message({"role": "narrator", "content": "hello"}, "salt")
        assert any(f.category == Category.SCHEMA_VIOLATION for f in findings)

    def test_non_string_content_flagged(self) -> None:
        det = SchemaDetector()
        findings = det.scan_message({"role": "user", "content": 12345}, "salt")
        assert any(f.category == Category.SCHEMA_VIOLATION for f in findings)

    def test_null_content_is_valid(self) -> None:
        """A tool-call-only assistant message has content: null — valid."""
        det = SchemaDetector()
        findings = det.scan_message({"role": "assistant", "content": None}, "salt")
        assert findings == []
