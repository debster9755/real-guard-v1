"""WS-03 acceptance criterion, verified against the REAL openai SDK — not a
hand-rolled client. This is the test that caught ADR 0002 (the `response`
wrapper broke ChatCompletion parsing) during Phase 1's own smoke test; it
stays in the suite so that regression can never happen silently again.

Uses httpx's ASGI transport to talk to the app in-process (no real network
port), so this runs in CI without binding a socket.
"""

from __future__ import annotations

import httpx
import pytest
from app.main import create_app
from openai import AsyncOpenAI

_BASE_URL = "http://testserver/v1"


@pytest.fixture
async def sdk_client():  # noqa: ANN201
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=_BASE_URL) as http_client:
        yield AsyncOpenAI(base_url=_BASE_URL, api_key="unused-in-dev", http_client=http_client)


async def test_unmodified_sdk_gets_a_working_completion(sdk_client: AsyncOpenAI) -> None:
    """PRD FR6 / WS-03: "an unmodified openai Python client can call the
    endpoint" — the actual claim under test, not a paraphrase of it."""
    resp = await sdk_client.chat.completions.create(
        model="qwen3:8b",
        messages=[{"role": "user", "content": "What is a good banana bread recipe?"}],
    )
    assert resp.id is not None
    assert resp.choices[0].message.content is not None
    assert resp.usage is not None


async def test_firewall_metadata_reachable_via_model_extra(sdk_client: AsyncOpenAI) -> None:
    """ADR 0002: firewall metadata rides as a tolerated extra top-level
    field, not a wrapper the SDK can't see through."""
    resp = await sdk_client.chat.completions.create(
        model="qwen3:8b",
        messages=[{"role": "user", "content": "hello"}],
    )
    fw = resp.model_extra["firewall"]
    assert fw["decision"] == "ALLOW"
    assert fw["transaction_id"].startswith("txn_")
    assert fw["mode"] == "mock"


async def test_sdk_raises_cleanly_on_a_4xx(sdk_client: AsyncOpenAI) -> None:
    """Confirms the DENY path (403, not yet wired to policy in Phase 1, so
    exercised here via the stream:true 400 path instead) raises
    openai.APIStatusError rather than crashing on ChatCompletion parsing —
    the reasoning ADR 0002 relies on for leaving DENY unchanged."""
    from openai import BadRequestError

    with pytest.raises(BadRequestError) as exc_info:
        await sdk_client.chat.completions.create(
            model="qwen3:8b",
            messages=[{"role": "user", "content": "hi"}],
            extra_body={"stream": True},
        )
    assert exc_info.value.status_code == 400
