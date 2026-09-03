"""Unit tests for the generic OpenAI-compatible provider adapter. SPEC.md
§2.8, §2.10. httpx is mocked via respx — no live network access required
(WS-06's own acceptance note: "do not require live network access for
tests")."""

from __future__ import annotations

import httpx
import pytest
import respx
from app.providers.base import UpstreamResponseError, UpstreamTimeoutError
from app.providers.openai_compatible import (
    OpenAICompatibleProvider,
    SsrfValidationError,
    validate_upstream_url_for_production,
)

_BASE_URL = "http://upstream.example.internal:11434/v1"


def _completion_body(content: str = "hello from upstream") -> dict[str, object]:
    return {
        "id": "chatcmpl_upstream_1",
        "object": "chat.completion",
        "created": 1772409600,
        "model": "qwen3:8b",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
    }


@pytest.mark.respx(base_url=_BASE_URL)
async def test_successful_completion(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(200, json=_completion_body())
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key="sk-test", model="qwen3:8b")
    result = await provider.complete({"messages": [{"role": "user", "content": "hi"}]})
    assert result["choices"][0]["message"]["content"] == "hello from upstream"


@pytest.mark.respx(base_url=_BASE_URL)
async def test_model_defaults_to_configured_model_when_absent(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(200, json=_completion_body())
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="qwen3:8b")
    await provider.complete({"messages": [{"role": "user", "content": "hi"}]})
    sent = route.calls.last.request
    import json as _json

    assert _json.loads(sent.content)["model"] == "qwen3:8b"


@pytest.mark.respx(base_url=_BASE_URL)
async def test_authorization_header_sent_when_api_key_configured(
    respx_mock: respx.MockRouter,
) -> None:
    route = respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(200, json=_completion_body())
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key="sk-secret-123", model="m")
    await provider.complete({"messages": []})
    assert route.calls.last.request.headers["Authorization"] == "Bearer sk-secret-123"


@pytest.mark.respx(base_url=_BASE_URL)
async def test_no_authorization_header_when_no_api_key(respx_mock: respx.MockRouter) -> None:
    route = respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(200, json=_completion_body())
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    await provider.complete({"messages": []})
    assert "Authorization" not in route.calls.last.request.headers


@pytest.mark.respx(base_url=_BASE_URL)
async def test_timeout_retries_once_then_raises_upstream_timeout_error(
    respx_mock: respx.MockRouter,
) -> None:
    """SPEC.md §3.8: exactly one bounded retry on timeout, then ERR-013."""
    route = respx_mock.post("/chat/completions").mock(
        side_effect=httpx.TimeoutException("timed out")
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    with pytest.raises(UpstreamTimeoutError):
        await provider.complete({"messages": []})
    assert route.call_count == 2  # the original attempt plus exactly one retry


@pytest.mark.respx(base_url=_BASE_URL)
async def test_5xx_raises_upstream_response_error(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("/chat/completions").mock(return_value=httpx.Response(500, text="boom"))
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    with pytest.raises(UpstreamResponseError):
        await provider.complete({"messages": []})


@pytest.mark.respx(base_url=_BASE_URL)
async def test_4xx_raises_upstream_response_error(respx_mock: respx.MockRouter) -> None:
    respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(401, json={"error": "invalid key"})
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    with pytest.raises(UpstreamResponseError):
        await provider.complete({"messages": []})


@pytest.mark.respx(base_url=_BASE_URL)
async def test_malformed_json_response_raises_upstream_response_error(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("/chat/completions").mock(
        return_value=httpx.Response(200, content=b"not json at all")
    )
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    with pytest.raises(UpstreamResponseError):
        await provider.complete({"messages": []})


@pytest.mark.respx(base_url=_BASE_URL)
async def test_response_missing_choices_raises_upstream_response_error(
    respx_mock: respx.MockRouter,
) -> None:
    respx_mock.post("/chat/completions").mock(return_value=httpx.Response(200, json={"id": "x"}))
    provider = OpenAICompatibleProvider(base_url=_BASE_URL, api_key=None, model="m")
    with pytest.raises(UpstreamResponseError):
        await provider.complete({"messages": []})


class TestSsrfValidation:
    def test_loopback_ip_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://127.0.0.1:11434/v1")

    def test_localhost_hostname_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://localhost:11434/v1")

    def test_link_local_ip_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://169.254.1.2:8080/v1")

    def test_metadata_service_ip_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://169.254.169.254/latest/meta-data")

    def test_metadata_service_hostname_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://metadata.google.internal/computeMetadata")

    def test_public_ip_literal_accepted(self) -> None:
        # A literal public IP needs no DNS lookup at all — deterministic,
        # no network access required (WS-06's own testing note).
        validate_upstream_url_for_production("http://8.8.8.8:443/v1")  # must not raise

    def test_public_hostname_accepted_no_network(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A hostname that resolves to a public address must not raise —
        exercised without a real DNS lookup by monkeypatching resolution,
        consistent with the project's "no live network access" testing
        rule."""
        monkeypatch.setattr(
            "app.providers.openai_compatible.socket.gethostbyname", lambda host: "93.184.216.34"
        )
        validate_upstream_url_for_production("https://api.example.com/v1")  # must not raise

    def test_hostname_resolving_to_loopback_rejected_no_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DNS name that merely points at a loopback address must not
        slip past a purely lexical check — the docstring's own stated
        threat model."""
        monkeypatch.setattr(
            "app.providers.openai_compatible.socket.gethostbyname",
            lambda host: "127.0.0.1",
        )
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("http://sneaky.example.com/v1")

    def test_unresolvable_hostname_is_not_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import socket as _socket

        def _raise(host: str) -> str:
            raise _socket.gaierror("name not known")

        monkeypatch.setattr("app.providers.openai_compatible.socket.gethostbyname", _raise)
        validate_upstream_url_for_production("http://does-not-resolve.invalid/v1")  # must not raise

    def test_url_with_no_host_rejected(self) -> None:
        with pytest.raises(SsrfValidationError):
            validate_upstream_url_for_production("not-a-url")
