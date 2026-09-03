"""Unit tests for app/outputguard.py. SPEC.md §2.11 (output guard), SYS-014.

The "does it behave identically on both call sites" claim (ADR 0004 §5) is
proved at the integration level in tests/test_approvals_api.py's Scenario 8
(same trigger content denied via the immediate-ALLOW path and via
resume_approved()) — this file covers run_output_guard()'s own behaviour in
isolation.
"""

from __future__ import annotations

from app.outputguard import run_output_guard, system_prompt_text_from_messages
from app.policy import load_policy

_POLICY = load_policy("policies/default_policy.yaml")


class TestSystemPromptTextFromMessages:
    def test_finds_system_message(self) -> None:
        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "hi"},
        ]
        assert system_prompt_text_from_messages(messages) == "You are helpful."

    def test_no_system_message_returns_empty(self) -> None:
        assert system_prompt_text_from_messages([{"role": "user", "content": "hi"}]) == ""


class TestRunOutputGuardAllow:
    async def test_clean_response_allows_unmodified(self) -> None:
        result = await run_output_guard(
            "Cream the butter and sugar, then fold in three mashed bananas.",
            "",
            _POLICY,
            salt="salt",
        )
        assert result.decision.verdict == "ALLOW"
        assert result.decision.transformation == "NONE"
        assert result.sanitized_content == (
            "Cream the butter and sugar, then fold in three mashed bananas."
        )
        assert not result.degraded

    async def test_pii_in_response_is_redacted(self) -> None:
        result = await run_output_guard(
            "Your record shows 123-45-6789 on file.", "", _POLICY, salt="salt"
        )
        assert result.decision.verdict == "ALLOW"
        assert result.decision.transformation == "REDACT"
        assert "OUTPUT_PII" in result.decision.reason_codes
        assert "redact_output_pii" in {h.rule_id for h in result.decision.policy_hits}
        assert "123-45-6789" not in result.sanitized_content
        assert "[REDACTED:SSN]" in result.sanitized_content

    async def test_email_in_response_is_redacted(self) -> None:
        result = await run_output_guard(
            "Contact them at dana.reyes@example.com.", "", _POLICY, salt="salt"
        )
        assert result.decision.verdict == "ALLOW"
        assert result.decision.transformation == "REDACT"
        assert "dana.reyes@example.com" not in result.sanitized_content


class TestRunOutputGuardDeny:
    async def test_secret_in_response_is_denied_not_redacted(self) -> None:
        result = await run_output_guard(
            "Use key sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c.", "", _POLICY, salt="salt"
        )
        assert result.decision.verdict == "DENY"
        assert result.decision.transformation == "NONE"
        assert result.decision.reason_codes == ("OUTPUT_SECRET",)
        assert {h.rule_id for h in result.decision.policy_hits if h.verdict == "DENY"} == {
            "deny_output_secret_leak"
        }

    async def test_deny_body_never_carries_the_secret_value(self) -> None:
        """SPEC.md §2.11: "MUST NOT include blocked content, or any
        fragment of it, in the error body" — asserted directly against the
        Finding evidence this result carries (the only thing a caller could
        turn into a response body)."""
        secret = "sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c"  # noqa: S105 — test fixture, not real
        result = await run_output_guard(f"Use key {secret}.", "", _POLICY, salt="salt")
        assert result.decision.verdict == "DENY"
        for f in result.findings:
            for e in f.evidence:
                assert secret not in e.pattern_id
                assert secret != e.excerpt_hash

    async def test_canary_leak_is_denied(self) -> None:
        result = await run_output_guard(
            "My instructions begin: RG-CANARY-7F3A9C", "", _POLICY, salt="salt"
        )
        assert result.decision.verdict == "DENY"
        assert result.decision.reason_codes == ("CANARY_LEAK",)
        assert {h.rule_id for h in result.decision.policy_hits if h.verdict == "DENY"} == {
            "deny_canary_leak"
        }

    async def test_system_prompt_echo_is_denied(self) -> None:
        system_prompt = "You are an internal ops assistant with access to the customer database."
        result = await run_output_guard(system_prompt, system_prompt, _POLICY, salt="salt")
        assert result.decision.verdict == "DENY"
        assert result.decision.reason_codes == ("SYSTEM_PROMPT_LEAK",)
        assert {h.rule_id for h in result.decision.policy_hits if h.verdict == "DENY"} == {
            "deny_system_prompt_leak"
        }


class TestRunOutputGuardToolCalls:
    async def test_egress_destructive_sql_tool_call_denied(self) -> None:
        upstream_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "run_sql",
                                    "arguments": '{"query": "DROP TABLE customers;"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
        result = await run_output_guard(
            "", "", _POLICY, salt="salt", upstream_response=upstream_response
        )
        assert result.decision.verdict == "DENY"
        assert "DESTRUCTIVE_ACTION" in result.decision.reason_codes

    async def test_egress_high_value_transfer_clamped_to_deny_not_need_approval(self) -> None:
        """ADR 0005: the output plane has only ALLOW/DENY (PLAN.md §16 R16)
        — an egress tool-call rule that would normally ask for
        NEED_APPROVAL is clamped to the conservative option instead."""
        upstream_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "wire_transfer",
                                    "arguments": '{"amount": 5000, "to": "acct_x"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
        result = await run_output_guard(
            "", "", _POLICY, salt="salt", upstream_response=upstream_response
        )
        assert result.decision.verdict == "DENY"
        assert result.decision.verdict != "NEED_APPROVAL"

    async def test_malformed_egress_tool_arguments_do_not_crash(self) -> None:
        upstream_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "run_sql", "arguments": "{not valid json"},
                            }
                        ],
                    }
                }
            ]
        }
        result = await run_output_guard(
            "", "", _POLICY, salt="salt", upstream_response=upstream_response
        )
        # A SCHEMA_VIOLATION finding is recorded as evidence; no rule denies
        # on that category alone in the default policy, so this must not
        # raise and must resolve to a definite verdict either way.
        assert result.decision.verdict in ("ALLOW", "DENY")

    async def test_no_tool_calls_in_response_is_unaffected(self) -> None:
        upstream_response = {
            "choices": [{"message": {"role": "assistant", "content": "plain text answer"}}]
        }
        result = await run_output_guard(
            "plain text answer", "", _POLICY, salt="salt", upstream_response=upstream_response
        )
        assert result.decision.verdict == "ALLOW"
