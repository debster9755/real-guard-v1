"""Authentication and identity resolution. SPEC.md §11 (SEC-001, SEC-002,
SEC-006, SEC-009).

ADR 0004 scope: bearer-key authentication only. The alternate reviewer
session-cookie route (SEC-005, SEC-007 — the `/dashboard` login exchange and
CSRF) belongs to the reviewer-dashboard workstream (WS-10) and is deferred;
`POST /v1/firewall/approvals/{id}/decision` accepts `Authorization: Bearer
<reviewer key>` in this slice, exactly as SPEC.md §4.6 allows as one of its
two valid auth routes.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

from app.config import Settings
from app.errors import ErrorCode, FirewallError

ANONYMOUS_DEV_IDENTITY = "svc_anonymous_dev"


class IdentityClass(StrEnum):
    SERVICE = "service"
    REVIEWER = "reviewer"


@dataclass(frozen=True)
class Identity:
    identity_class: IdentityClass
    identity_id: str  # a stable key_id (SEC-002), or ANONYMOUS_DEV_IDENTITY


def key_id_for(key: str) -> str:
    """SEC-002: "a stable key_id (a truncated hash) for logging; the key
    itself MUST NEVER be logged." Sixteen hex characters of SHA-256 is
    ample to distinguish keys within one deployment without being invertible."""
    return "key_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _constant_time_member(presented: str, candidates: list[str]) -> bool:
    """SEC-002: constant-time comparison per candidate, so a match's
    position in the list isn't observable via early-exit character
    comparison. (List *length* leaks via total loop time regardless; that's
    an accepted, documented limit of this MVP's key store, not a claim of
    full side-channel resistance.)"""
    found = False
    for candidate in candidates:
        if hmac.compare_digest(presented, candidate):
            found = True
    return found


def resolve_identity(authorization_header: str | None, settings: Settings) -> Identity:
    """Resolve the caller's identity from an `Authorization: Bearer <key>`
    header. SEC-009: only the presented key is authoritative — no
    client-supplied header is ever trusted as identity.

    Returns the anonymous dev-mode fallback only when no header was
    presented *and* no keys of either class are configured — the same
    condition CFG-002/SEC-003 already requires for unauthenticated
    operation (loopback bind, non-production), so this function never needs
    to re-check environment/bind-host itself.
    """
    if authorization_header is None:
        if not settings.service_keys and not settings.reviewer_keys:
            return Identity(IdentityClass.SERVICE, ANONYMOUS_DEV_IDENTITY)
        raise FirewallError(ErrorCode.INVALID_AUTHENTICATION, "Missing Authorization header.")

    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise FirewallError(
            ErrorCode.INVALID_AUTHENTICATION, "Authorization header must be 'Bearer <key>'."
        )

    if _constant_time_member(token, settings.service_keys):
        return Identity(IdentityClass.SERVICE, key_id_for(token))
    if _constant_time_member(token, settings.reviewer_keys):
        return Identity(IdentityClass.REVIEWER, key_id_for(token))

    raise FirewallError(ErrorCode.INVALID_AUTHENTICATION, "Unrecognized API key.")


def require_reviewer(identity: Identity) -> None:
    """SEC-006: "A service-class identity MUST NOT be able to decide an
    approval by any route." Also gates the approvals-list endpoint (API-010)."""
    if identity.identity_class != IdentityClass.REVIEWER:
        raise FirewallError(
            ErrorCode.INSUFFICIENT_PRIVILEGE,
            "This endpoint requires a reviewer-class identity.",
        )
