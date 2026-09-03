"""Generic OpenAI-compatible provider adapter. SPEC.md §2.8, §2.10.

httpx-based; config-driven via UPSTREAM_BASE_URL/UPSTREAM_API_KEY/
UPSTREAM_MODEL. This is also what the Ollama profile uses without any
separate code path — §2.10 is explicit that Ollama support is
"configuration of the generic OpenAI-compatible adapter, not separate
code": `UPSTREAM_BASE_URL=http://host.docker.internal:11434/v1`,
`UPSTREAM_MODEL=qwen3:8b`. The Ollama-specific `GET /api/tags` startup
preflight (§2.10's own responsibility beyond plain adapter behaviour) is
Phase 5 scope (PLAN.md §6) — this module only needs to be reachable and
correct; wiring it into a live compose profile with a preflight check is a
later phase's work.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from app.providers.base import UpstreamResponseError, UpstreamTimeoutError

PROVIDER_NAME = "openai_compatible"

_DEFAULT_TIMEOUT_SECONDS = 60.0
# SPEC.md §3.8's upstream-failure sequence diagram shows exactly one bounded
# retry on timeout before failing — "G->>U: bounded retry / U--xG: timeout
# again / G->>A: audit UPSTREAM_TIMEOUT". Provider.complete() MUST NOT retry
# a non-idempotent failure more than this configured limit (§2.8 prohibited
# responsibilities), and a chat completion is never assumed idempotent, so
# retries are scoped to *timeouts only* — a definite non-delivery, not a
# response that may or may not have taken effect upstream.
_MAX_RETRIES_ON_TIMEOUT = 1


class SsrfValidationError(ValueError):
    """SYS-013: the configured upstream base URL resolves to a loopback,
    link-local or metadata-service address, which is disallowed when
    APP_ENV=production."""


_METADATA_SERVICE_HOSTS = {"metadata.google.internal"}
_METADATA_SERVICE_IP = ipaddress.ip_address("169.254.169.254")


def validate_upstream_url_for_production(base_url: str) -> None:
    """SYS-013: "The upstream base URL MUST be validated at startup against
    SSRF rules (§19): loopback, link-local, and metadata-service addresses
    MUST be rejected when APP_ENV=production." Raises SsrfValidationError
    naming the offending host; app/main.py's AppState wraps that as a
    ConfigurationError so an unsafe production configuration fails at
    startup (CFG-002), never at request time.

    A hostname (rather than a literal IP) is resolved before the address
    class is checked, so an operator-controlled DNS name that merely points
    at a loopback/link-local address (e.g. "localhost.example.com") cannot
    slip past a purely lexical check. An unresolvable hostname is not
    rejected here — startup DNS may legitimately differ from request-time
    DNS in some deployments, and the provider's first real call will surface
    a genuine resolution failure clearly (ERR-014/015) rather than this
    function guessing at one.
    """
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        raise SsrfValidationError(f"UPSTREAM_BASE_URL has no host: {base_url!r}")
    if host in _METADATA_SERVICE_HOSTS:
        raise SsrfValidationError(f"UPSTREAM_BASE_URL host is a metadata service: {host!r}")

    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(host)
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
        except OSError:
            return  # unresolvable now; the first real call will surface it clearly
        addr = ipaddress.ip_address(resolved)

    if addr.is_loopback or addr.is_link_local or addr == _METADATA_SERVICE_IP:
        raise SsrfValidationError(
            f"UPSTREAM_BASE_URL resolves to a disallowed address in production: {host!r} -> {addr}"
        )


class OpenAICompatibleProvider:
    """SPEC.md §2.8 provider adapter; §2.10 Ollama configuration path.

    `name` deliberately stays "openai_compatible" regardless of which
    upstream is actually configured (Ollama included) — DEP-004's mock-mode
    marker only ever needs to distinguish "mock" from "live"; the specific
    live provider is a configuration detail, not a firewall-visible mode.
    """

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None,
        model: str,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        """SPEC.md §2.8: protocol translation, timeouts, bounded retries,
        error classification. `request` is already transformed and
        authorized (only ever reachable from the post-decision path) — this
        adapter performs no inspection of its own; that is the output
        guard's job (app/outputguard.py), not this one's (§2.8 prohibited
        responsibilities: "MUST NOT be reachable except from the
        post-decision path" — enforced by callers, not this protocol).
        """
        payload = {**request, "model": request.get("model") or self._model}
        url = f"{self._base_url}/chat/completions"

        last_error: Exception | None = None
        for _attempt in range(_MAX_RETRIES_ON_TIMEOUT + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                    response = await client.post(url, json=payload, headers=self._headers())
            except httpx.TimeoutException as e:
                last_error = e
                continue
            except httpx.HTTPError as e:
                # ERR-014: a transport-level failure that isn't specifically
                # a timeout (connection refused, TLS failure, etc).
                raise UpstreamResponseError(f"upstream request failed: {type(e).__name__}") from e

            if response.status_code >= 400:
                # ERR-014: any non-2xx status. §2.8 doesn't distinguish 4xx
                # from 5xx in its own failure table (both map to ERR-014);
                # the caller (app/main.py) decides the wire status.
                raise UpstreamResponseError(f"upstream returned HTTP {response.status_code}")

            try:
                data: dict[str, Any] = response.json()
            except ValueError as e:
                # ERR-015: 2xx but the body isn't valid JSON.
                raise UpstreamResponseError("upstream response was not valid JSON") from e

            if not isinstance(data, dict) or "choices" not in data:
                # ERR-015: valid JSON, but not a recognisable chat-completion
                # shape.
                raise UpstreamResponseError("upstream response is missing `choices`")
            return data

        raise UpstreamTimeoutError(
            f"upstream timed out after {_MAX_RETRIES_ON_TIMEOUT + 1} attempt(s)"
        ) from last_error
