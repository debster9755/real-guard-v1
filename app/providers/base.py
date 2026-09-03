"""Provider adapter protocol. SPEC.md §2.8.

A provider translates an already-authorized, already-transformed request into
an upstream call (or, for the mock provider, a synthetic one) and returns a
normalized chat-completion response. Providers MUST NOT be reachable except
from the post-decision path — that boundary is enforced by callers (the
gateway), not by this protocol itself.
"""

from __future__ import annotations

from typing import Any, Protocol


class UpstreamError(Exception):
    """Base for provider-adapter failures. Maps to ERR-013/014/015 by the
    caller, which knows the request context this module doesn't."""


class UpstreamTimeoutError(UpstreamError):
    """ERR-013."""


class UpstreamResponseError(UpstreamError):
    """ERR-014 (upstream returned an error) or ERR-015 (unparseable)."""


class Provider(Protocol):
    """SPEC.md §2.8 provider adapter interface."""

    name: str

    async def complete(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return an OpenAI-shaped chat-completion response dict for the
        given (already-transformed, already-authorized) request dict."""
        ...
