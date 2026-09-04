"""Unit tests for the Ollama startup preflight. SPEC.md §2.10, DEP-003
(PLAN.md Phase 5). httpx is mocked via respx — no live network access
required, mirroring tests/test_provider_openai_compatible.py's own
justification for WS-06."""

from __future__ import annotations

import httpx
import respx
from app.providers.ollama_preflight import _derive_tags_url, check_ollama_preflight

_BASE_URL = "http://ollama.example.internal:11434/v1"
_TAGS_URL = "http://ollama.example.internal:11434/api/tags"


def test_derive_tags_url_strips_v1_suffix() -> None:
    assert _derive_tags_url("http://host.docker.internal:11434/v1") == (
        "http://host.docker.internal:11434/api/tags"
    )


def test_derive_tags_url_strips_trailing_slash_before_v1() -> None:
    assert _derive_tags_url("http://host.docker.internal:11434/v1/") == (
        "http://host.docker.internal:11434/api/tags"
    )


def test_derive_tags_url_no_v1_suffix_used_as_is() -> None:
    assert _derive_tags_url("http://host.docker.internal:11434") == (
        "http://host.docker.internal:11434/api/tags"
    )


@respx.mock
def test_reachable_and_model_present_is_ok() -> None:
    respx.get(_TAGS_URL).mock(
        return_value=httpx.Response(200, json={"models": [{"name": "qwen3:8b"}]})
    )
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "ok"
    assert "qwen3:8b" in result.message


@respx.mock
def test_reachable_but_model_missing_is_unreachable_with_actionable_message() -> None:
    respx.get(_TAGS_URL).mock(
        return_value=httpx.Response(200, json={"models": [{"name": "llama3:8b"}]})
    )
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"
    assert "qwen3:8b" in result.message
    assert "ollama pull qwen3:8b" in result.message


@respx.mock
def test_connection_error_is_unreachable_with_host_prerequisite_message() -> None:
    respx.get(_TAGS_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"
    assert "host.docker.internal" in result.message


@respx.mock
def test_timeout_is_unreachable_and_never_raises() -> None:
    respx.get(_TAGS_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"


@respx.mock
def test_http_error_status_is_unreachable() -> None:
    respx.get(_TAGS_URL).mock(return_value=httpx.Response(500))
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"
    assert "500" in result.message


@respx.mock
def test_unparseable_body_is_unreachable() -> None:
    respx.get(_TAGS_URL).mock(return_value=httpx.Response(200, content=b"not json"))
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"


@respx.mock
def test_empty_models_list_is_unreachable() -> None:
    respx.get(_TAGS_URL).mock(return_value=httpx.Response(200, json={"models": []}))
    result = check_ollama_preflight(_BASE_URL, "qwen3:8b")
    assert result.status == "unreachable"
    assert "none" in result.message
