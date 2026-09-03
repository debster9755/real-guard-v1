"""Deterministic mock provider. SPEC.md §2.9, TST-021/TST-022.

- No network I/O, ever (§2.9 prohibited responsibilities).
- Identical normalized input -> byte-identical response (determinism is what
  makes the corpus and CI reproducible without a real model).
- Recognizes a small set of seeded trigger tokens so output-plane corpus
  cases (OUT-*, LEK-*) are exercisable without a real model choosing to leak
  anything. Triggers are inert text as far as the *input* plane is concerned
  (TST-022) — they must not, by themselves, change any input-plane verdict;
  they only affect what MockProvider echoes back.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from app.ids import new_id

PROVIDER_NAME = "mock"

# TST-021 trigger table — token in any message content -> deterministic
# response content. Checked in this fixed order; the first match wins so a
# payload combining triggers still produces one deterministic response.
_TRIGGER_SSN = "__RG_TEST_EMIT_SSN__"
_TRIGGER_EMAIL = "__RG_TEST_EMIT_EMAIL__"
_TRIGGER_SECRET = "__RG_TEST_EMIT_SECRET__"  # noqa: S105 — a sentinel token, not a credential
_TRIGGER_CANARY = "__RG_TEST_EMIT_CANARY__"
_TRIGGER_SYSPROMPT = "__RG_TEST_EMIT_SYSPROMPT__"
_TRIGGER_TOOLCALL = "__RG_TEST_EMIT_TOOLCALL__"


def _all_content(request: dict[str, Any]) -> str:
    messages = request.get("messages", [])
    return "\n".join(str(m.get("content", "")) for m in messages if isinstance(m, dict))


def _system_message_content(request: dict[str, Any]) -> str:
    for m in request.get("messages", []):
        if isinstance(m, dict) and m.get("role") == "system":
            return str(m.get("content", ""))
    return ""


def _deterministic_reply(request: dict[str, Any]) -> str:
    """Fallback response when no trigger matches: derived solely from a
    stable hash of the normalized request (§2.9) so identical input always
    produces an identical reply."""
    payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()[:12]
    return f"[mock response {digest}] Acknowledged your request."


def _build_reply_content(request: dict[str, Any]) -> str:
    content = _all_content(request)

    if _TRIGGER_SSN in content:
        return "Your record shows 123-45-6789 on file."
    if _TRIGGER_EMAIL in content:
        return "Contact them at dana.reyes@example.com."
    if _TRIGGER_SECRET in content:
        return "Use key sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c."
    if _TRIGGER_CANARY in content:
        return "My instructions begin: RG-CANARY-7F3A9C"
    if _TRIGGER_SYSPROMPT in content:
        sys_content = _system_message_content(request)
        return sys_content if sys_content else "(no system message was provided)"
    # _TRIGGER_TOOLCALL is handled separately in complete() since it changes
    # the message shape (tool_calls) rather than the text content.
    return _deterministic_reply(request)


def _build_tool_calls(request: dict[str, Any]) -> list[dict[str, Any]] | None:
    content = _all_content(request)
    if _TRIGGER_TOOLCALL not in content:
        return None
    return [
        {
            "id": new_id("call"),
            "type": "function",
            "function": {
                "name": "wire_transfer",
                "arguments": json.dumps({"amount": 5000, "to": "acct_x"}),
            },
        }
    ]


class MockProvider:
    """SPEC.md §2.9. name == "mock" is asserted by DEP-004 visibility tests."""

    name = PROVIDER_NAME

    async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        model = request.get("model") or "mock-model"
        tool_calls = _build_tool_calls(request)

        message: dict[str, Any] = {"role": "assistant"}
        if tool_calls is not None:
            message["content"] = None
            message["tool_calls"] = tool_calls
            finish_reason = "tool_calls"
        else:
            message["content"] = _build_reply_content(request)
            finish_reason = "stop"

        prompt_tokens = max(1, len(_all_content(request)) // 4)
        completion_tokens = max(1, len(str(message.get("content") or "")) // 4)

        return {
            "id": new_id("chatcmpl"),
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }
