"""Unit tests for the Phase 3 detectors: `system_prompt_leak` and
`tool_calls`. SPEC.md §6.4, §6.5 (DET-011, DET-016..018)."""

from __future__ import annotations

from app.detectors.base import Category, Confidence
from app.detectors.system_prompt_leak import SystemPromptLeakDetector
from app.detectors.tool_calls import ToolCallsDetector
from app.normalizer import normalize
from app.planes import Plane
from app.policy import load_policy

_POLICY = load_policy("policies/default_policy.yaml")


class TestSystemPromptLeakDetector:
    def test_canary_match_is_high_confidence(self) -> None:
        det = SystemPromptLeakDetector(canaries=["RG-CANARY-7F3A9C"])
        nc = normalize("My instructions begin: RG-CANARY-7F3A9C")
        findings = det.scan_response(nc, "", "salt")
        canary_findings = [f for f in findings if f.category == Category.CANARY_LEAK]
        assert len(canary_findings) == 1
        assert canary_findings[0].score == 1.0
        assert canary_findings[0].confidence == Confidence.HIGH  # DET-011

    def test_no_canary_configured_no_match(self) -> None:
        det = SystemPromptLeakDetector(canaries=[])
        nc = normalize("My instructions begin: RG-CANARY-7F3A9C")
        findings = det.scan_response(nc, "", "salt")
        assert not any(f.category == Category.CANARY_LEAK for f in findings)

    def test_verbatim_system_prompt_echo_is_high_similarity(self) -> None:
        det = SystemPromptLeakDetector(canaries=[])
        system_prompt = "You are an internal ops assistant with access to the customer database."
        nc = normalize(system_prompt)
        findings = det.scan_response(nc, system_prompt, "salt")
        leak_findings = [f for f in findings if f.category == Category.SYSTEM_PROMPT_LEAK]
        assert len(leak_findings) == 1
        assert leak_findings[0].score == 1.0
        assert leak_findings[0].confidence == Confidence.HIGH

    def test_unrelated_response_does_not_leak(self) -> None:
        det = SystemPromptLeakDetector(canaries=["RG-CANARY-7F3A9C"])
        system_prompt = "You are an internal ops assistant with access to the customer database."
        nc = normalize("Here is a banana bread recipe: cream the butter and sugar.")
        findings = det.scan_response(nc, system_prompt, "salt")
        assert findings == []

    def test_empty_system_prompt_produces_no_similarity_finding(self) -> None:
        det = SystemPromptLeakDetector(canaries=[])
        nc = normalize("Some ordinary response text.")
        findings = det.scan_response(nc, "", "salt")
        assert findings == []

    def test_scan_is_protocol_conformant_noop(self) -> None:
        """DET-001/DET-002: `scan()` must exist and be callable through the
        standard Detector protocol, even though real work happens in
        scan_response() (see the module docstring for why)."""
        det = SystemPromptLeakDetector(canaries=["RG-CANARY-7F3A9C"])
        nc = normalize("RG-CANARY-7F3A9C")
        assert det.scan(nc, Plane.response, "salt") == []
        assert det.supported_planes == frozenset({Plane.response})


class TestToolCallsDetector:
    def test_allowlisted_tool_no_finding(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("search_docs", {"query": "hello"}, "salt")
        assert not any(f.category == Category.TOOL_NOT_ALLOWLISTED for f in findings)

    def test_non_allowlisted_tool_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("exfiltrate_data", {"target": "external"}, "salt")
        assert any(f.category == Category.TOOL_NOT_ALLOWLISTED for f in findings)

    def test_high_value_transfer_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("wire_transfer", {"amount": 5000, "to": "acct_x"}, "salt")
        sensitive = [f for f in findings if f.category == Category.SENSITIVE_ACTION]
        assert len(sensitive) == 1
        assert sensitive[0].confidence == Confidence.HIGH

    def test_low_value_transfer_not_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("wire_transfer", {"amount": 10, "to": "acct_x"}, "salt")
        assert not any(f.category == Category.SENSITIVE_ACTION for f in findings)

    def test_destructive_sql_drop_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("run_sql", {"query": "DROP TABLE customers;"}, "salt")
        assert any(f.category == Category.DESTRUCTIVE_ACTION for f in findings)

    def test_unbounded_delete_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("run_sql", {"query": "DELETE FROM customers"}, "salt")
        assert any(f.category == Category.DESTRUCTIVE_ACTION for f in findings)

    def test_bounded_delete_not_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call(
            "run_sql", {"query": "DELETE FROM customers WHERE id = 1"}, "salt"
        )
        assert not any(f.category == Category.DESTRUCTIVE_ACTION for f in findings)

    def test_shell_recursive_delete_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("run_shell", {"command": "rm -rf /var/data"}, "salt")
        assert any(f.category == Category.DESTRUCTIVE_ACTION for f in findings)

    def test_benign_shell_command_not_flagged(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("run_shell", {"command": "ls -la"}, "salt")
        assert not any(f.category == Category.DESTRUCTIVE_ACTION for f in findings)

    def test_malformed_json_arguments_produce_schema_violation(self) -> None:
        """DET-018: unparseable arguments are evidence, not a silent skip."""
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call(
            "wire_transfer", None, "salt", raw_arguments="{not valid json"
        )
        assert len(findings) == 1
        assert findings[0].category == Category.SCHEMA_VIOLATION

    def test_valid_raw_arguments_parsed_and_evaluated(self) -> None:
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call(
            "wire_transfer", None, "salt", raw_arguments='{"amount": 5000, "to": "acct_x"}'
        )
        assert any(f.category == Category.SENSITIVE_ACTION for f in findings)

    def test_deeply_nested_argument_payload_does_not_raise(self) -> None:
        """WS-08's own risk note: "parsing arbitrary tool arguments is
        unbounded... rules address declared argument paths only" — a deeply
        nested payload under an unrelated key must not crash the detector,
        even though nothing in it is inspected."""
        nested: dict[str, object] = {"level": 0}
        cursor = nested
        for i in range(1, 200):
            cursor["child"] = {"level": i}
            cursor = cursor["child"]  # type: ignore[assignment]
        det = ToolCallsDetector(_POLICY)
        findings = det.scan_tool_call("search_docs", {"query": "fine", "nested": nested}, "salt")
        assert isinstance(findings, list)

    def test_scan_is_protocol_conformant_noop(self) -> None:
        det = ToolCallsDetector(_POLICY)
        nc = normalize("irrelevant")
        assert det.scan(nc, Plane.action, "salt") == []
        assert det.supported_planes == frozenset({Plane.action})
