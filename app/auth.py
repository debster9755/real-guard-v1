"""Authentication and identity resolution. SPEC.md §11 (SEC-001, SEC-002,
SEC-005, SEC-006, SEC-007, SEC-009).

ADR 0004 scope: bearer-key authentication only. Phase 4 (ADR 0006) adds the
second valid auth route SPEC.md §4.6 always named but ADR 0004 deferred: "a
valid session cookie plus `X-CSRF-Token`" — `resolve_decision_identity()`
below is the single entry point `POST
/v1/firewall/approvals/{id}/decision` uses for both routes, so the
CSRF-enforcement rule (SEC-007) lives in exactly one place regardless of
which auth route a given request took.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

from app.config import Settings
from app.errors import ErrorCode, FirewallError
from app.session import verify_csrf_token, verify_session_cookie

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

    Returns the anonymous dev-mode fallback whenever no keys of either class
    are configured — the same condition CFG-002/SEC-003 already requires
    for unauthenticated operation (loopback bind, non-production), so this
    function never needs to re-check environment/bind-host itself.

    Phase 6 (WS-13, ADR 0008): this fallback now applies even when a header
    *is* presented, not only when one is absent. Before Phase 6,
    `resolve_identity()` was only ever reached (for the ALLOW/DENY verdicts)
    from the `NEED_APPROVAL` branch of `app/main.py`'s handler — moving the
    call to the top of every request (so the rate limiter has an identity
    to scope by) surfaced a latent inconsistency: a client presenting *any*
    placeholder bearer token (an unmodified `openai` SDK always sends one;
    it has no concept of "no credential") would get `INVALID_AUTHENTICATION`
    in dev mode purely because that code path had never been exercised for
    ALLOW before. When zero keys of either class are configured, there is
    nothing a presented token could be validated against — rejecting it
    protects nothing SEC-003 doesn't already gate at the loopback/bind
    level, so it is treated identically to no header at all.
    """
    if not settings.service_keys and not settings.reviewer_keys:
        return Identity(IdentityClass.SERVICE, ANONYMOUS_DEV_IDENTITY)

    if authorization_header is None:
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


def resolve_decision_identity(
    *,
    authorization_header: str | None,
    session_cookie: str | None,
    csrf_header: str | None,
    settings: Settings,
) -> Identity:
    """SPEC.md §4.6: "Headers: `Authorization: Bearer <reviewer key>` or a
    valid session cookie plus `X-CSRF-Token`." A bearer header, when
    present, is resolved exactly as `resolve_identity()` already did before
    this function existed — every prior bearer-only test keeps behaving
    identically. Only when no `Authorization` header is present is the
    session cookie consulted.

    SEC-007: cookie-based auth additionally requires a matching
    `X-CSRF-Token`; a missing or mismatched token raises `CSRF_TOKEN_INVALID`
    (403) before the caller ever reaches the state-changing logic. Bearer-key
    auth is exempt — a browser cannot be tricked into attaching an
    `Authorization` header to a forged cross-site request the way it
    automatically attaches cookies, so CSRF does not apply to that route.

    SEC-006: a session is only ever *issued* to a reviewer identity (see
    `app/dashboard.py`'s login route, which calls `resolve_identity()` and
    rejects anything but `IdentityClass.REVIEWER` before a cookie is ever
    created) — there is no "service session" for this function to decode,
    so SEC-006 is enforced at issuance rather than here. `require_reviewer()`
    is still called by every caller of this function as belt-and-braces.
    """
    if authorization_header is not None:
        return resolve_identity(authorization_header, settings)

    session = verify_session_cookie(session_cookie, settings)
    if session is not None:
        if not verify_csrf_token(csrf_header, session.session_id, settings):
            raise FirewallError(
                ErrorCode.CSRF_TOKEN_INVALID,
                "Missing or invalid X-CSRF-Token for this session.",
            )
        return Identity(IdentityClass.REVIEWER, session.identity_id)

    # No usable credential of either kind: fall back to resolve_identity()'s
    # existing logic, which raises INVALID_AUTHENTICATION or returns the
    # anonymous dev identity under SEC-003's conditions.
    return resolve_identity(authorization_header, settings)


def require_reviewer(identity: Identity) -> None:
    """SEC-006: "A service-class identity MUST NOT be able to decide an
    approval by any route." Also gates the approvals-list endpoint (API-010)."""
    if identity.identity_class != IdentityClass.REVIEWER:
        raise FirewallError(
            ErrorCode.INSUFFICIENT_PRIVILEGE,
            "This endpoint requires a reviewer-class identity.",
        )
