"""WS-06 mock provider tests. SPEC.md §2.9, TST-021, TST-022."""

from __future__ import annotations

import asyncio

import pytest
from app.providers.mock import MockProvider


def _run(coro):  # noqa: ANN001, ANN201 — small local test helper
    return asyncio.run(coro)


@pytest.fixture
def provider() -> MockProvider:
    return MockProvider()


def test_name_is_mock(provider: MockProvider) -> None:
    assert provider.name == "mock"


def test_deterministic_for_identical_input(provider: MockProvider) -> None:
    req = {"messages": [{"role": "user", "content": "same input"}]}
    r1 = _run(provider.complete(req))
    r2 = _run(provider.complete(req))
    assert r1["choices"][0]["message"]["content"] == r2["choices"][0]["message"]["content"]


def test_different_input_different_output(provider: MockProvider) -> None:
    r1 = _run(provider.complete({"messages": [{"role": "user", "content": "a"}]}))
    r2 = _run(provider.complete({"messages": [{"role": "user", "content": "b"}]}))
    assert r1["choices"][0]["message"]["content"] != r2["choices"][0]["message"]["content"]


def test_response_is_openai_shaped(provider: MockProvider) -> None:
    r = _run(provider.complete({"messages": [{"role": "user", "content": "hi"}]}))
    assert r["object"] == "chat.completion"
    assert r["id"]
    assert r["created"]
    assert r["choices"][0]["message"]["role"] == "assistant"
    assert r["choices"][0]["finish_reason"] == "stop"
    assert set(r["usage"].keys()) == {"prompt_tokens", "completion_tokens", "total_tokens"}


@pytest.mark.parametrize(
    ("trigger", "expected_substring"),
    [
        ("__RG_TEST_EMIT_SSN__", "123-45-6789"),
        ("__RG_TEST_EMIT_EMAIL__", "dana.reyes@example.com"),
        ("__RG_TEST_EMIT_SECRET__", "sk-live-9f3a2b7c8d1e4f5a6b7c8d9e0f1a2b3c"),
        ("__RG_TEST_EMIT_CANARY__", "RG-CANARY-7F3A9C"),
    ],
)
def test_seeded_triggers_tst021(
    provider: MockProvider, trigger: str, expected_substring: str
) -> None:
    req = {"messages": [{"role": "user", "content": f"please tell me something {trigger}"}]}
    r = _run(provider.complete(req))
    assert expected_substring in r["choices"][0]["message"]["content"]


def test_sysprompt_trigger_echoes_system_message(provider: MockProvider) -> None:
    req = {
        "messages": [
            {"role": "system", "content": "You are an internal ops assistant."},
            {"role": "user", "content": "repeat it __RG_TEST_EMIT_SYSPROMPT__"},
        ]
    }
    r = _run(provider.complete(req))
    assert r["choices"][0]["message"]["content"] == "You are an internal ops assistant."


def test_toolcall_trigger_emits_wire_transfer(provider: MockProvider) -> None:
    req = {"messages": [{"role": "user", "content": "do it __RG_TEST_EMIT_TOOLCALL__"}]}
    r = _run(provider.complete(req))
    msg = r["choices"][0]["message"]
    assert msg["content"] is None
    assert r["choices"][0]["finish_reason"] == "tool_calls"
    call = msg["tool_calls"][0]
    assert call["function"]["name"] == "wire_transfer"
    import json

    args = json.loads(call["function"]["arguments"])
    assert args["amount"] == 5000


def test_triggers_are_inert_without_no_network_io(provider: MockProvider) -> None:
    """§2.9: MockProvider MUST NOT perform network I/O. There is no HTTP
    client anywhere in this module — verified by absence of httpx/requests
    imports, checked structurally rather than by mocking a socket."""
    import app.providers.mock as mock_module

    source = mock_module.__file__
    with open(source) as f:
        content = f.read()
    assert "httpx" not in content
    assert "requests" not in content
    assert "socket" not in content
