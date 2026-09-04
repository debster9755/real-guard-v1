"""Ollama startup preflight. SPEC.md §2.10, DEP-003 (PLAN.md Phase 5).

"a startup preflight `GET /api/tags` that reports whether the host Ollama
is reachable and whether the configured model is present" (§2.10).
"a failed preflight MUST mark `/readyz` not-ready with an actionable
message naming the host prerequisite. It MUST NOT crash the process"
(§2.10, DEP-003).

This module performs exactly that one HTTP call, synchronously, at process
startup (see app/main.py's `AppState.__init__`) — not on a timer, not on
every `/readyz` poll. ADR 0007 documents why: SPEC.md's own wording says
"startup preflight", singular, and a live re-check on every readiness poll
would turn `/readyz` (documented as fast and dependency-light) into a
network call against a host service on every probe.

Deliberately synchronous (`httpx.Client`, not `AsyncClient`): this runs once,
before the event loop is serving any request, from `AppState.__init__`,
which is itself synchronous (it also does a blocking policy-file read and,
elsewhere, a blocking DB connectivity check in the `/readyz` handler) — no
different in kind from those, and avoids a startup-only `asyncio.run()` just
to make one HTTP call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import httpx

PreflightStatus = Literal["ok", "unreachable"]

_DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class OllamaPreflightResult:
    status: PreflightStatus
    message: str


def _derive_tags_url(upstream_base_url: str) -> str:
    """`UPSTREAM_BASE_URL` for the Ollama profile is Ollama's
    OpenAI-compatible endpoint, e.g. `http://host.docker.internal:11434/v1`
    (this project's own `.env.example` and the `ollama-host` compose
    profile). Ollama's native `/api/tags` lives one level up, at the same
    host:port with no `/v1` suffix — so the trailing `/v1` (with or without
    a trailing slash) is stripped before appending `/api/tags`. A base URL
    that doesn't end in `/v1` is used as-is; this only ever runs when an
    operator has explicitly set `OLLAMA_PREFLIGHT_ENABLED=true`, so an
    unexpected shape here is *their* configuration to see fail with a clear
    reachability message, not this function's to silently guess around."""
    trimmed = upstream_base_url.rstrip("/")
    if trimmed.endswith("/v1"):
        trimmed = trimmed[: -len("/v1")]
    return f"{trimmed}/api/tags"


def check_ollama_preflight(
    upstream_base_url: str,
    expected_model: str,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> OllamaPreflightResult:
    """Runs the §2.10 preflight. Never raises — every failure mode (network
    error, timeout, non-2xx, unparseable JSON, unexpected shape) is caught
    and turned into an `"unreachable"` result with an actionable message, so
    a callsite can log it and mark `/readyz` not-ready without risking the
    "MUST NOT crash the process" requirement on a startup code path that, by
    definition, runs before anything else has had a chance to catch it.
    """
    tags_url = _derive_tags_url(upstream_base_url)

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.get(tags_url)
    except httpx.HTTPError as e:
        return OllamaPreflightResult(
            status="unreachable",
            message=(
                f"Ollama preflight failed: could not reach {tags_url} "
                f"({type(e).__name__}). Ensure Ollama is running on the host "
                "and reachable from the container — on macOS/Windows this "
                "requires host.docker.internal (already configured by the "
                "ollama-host compose profile's extra_hosts entry per DEP-003); "
                "on Linux, confirm the same extra_hosts mapping resolves. "
                "See README.md's Ollama profile section."
            ),
        )

    if response.status_code >= 400:
        return OllamaPreflightResult(
            status="unreachable",
            message=(
                f"Ollama preflight failed: {tags_url} returned "
                f"HTTP {response.status_code}. Ensure the host Ollama service "
                "is healthy."
            ),
        )

    try:
        data = response.json()
        names = {m.get("name") for m in data.get("models", []) if isinstance(m, dict)}
    except (ValueError, AttributeError):
        return OllamaPreflightResult(
            status="unreachable",
            message=(
                f"Ollama preflight failed: {tags_url} returned a response "
                "that could not be parsed as Ollama's /api/tags JSON shape."
            ),
        )

    if expected_model not in names:
        return OllamaPreflightResult(
            status="unreachable",
            message=(
                f"Ollama preflight: reached {tags_url}, but the configured "
                f"model {expected_model!r} is not pulled on the host "
                f"(available: {sorted(n for n in names if n) or 'none'}). "
                f"Run `ollama pull {expected_model}` on the host, then "
                "restart the container."
            ),
        )

    return OllamaPreflightResult(
        status="ok",
        message=f"Ollama preflight ok: {tags_url} reachable, model {expected_model!r} present.",
    )
