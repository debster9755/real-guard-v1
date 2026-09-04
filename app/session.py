"""Reviewer session cookies and CSRF tokens. SPEC.md §11.3 (SEC-005, SEC-007).

Phase 4 (ADR 0006) implements the alternate reviewer auth route SPEC.md
§4.6 names but ADR 0004 deferred: "a valid session cookie plus
`X-CSRF-Token`." Two independent, stateless, HMAC-based primitives:

1. A **signed session cookie** (`create_session_cookie`/`verify_session_cookie`):
   payload is `session_id|identity_id|issued_epoch|expires_epoch`,
   base64url-encoded, then HMAC-SHA256-signed with
   `Settings.effective_session_secret()`. Stateless — no server-side session
   table — verification is "does the signature match, and has `expires_at`
   not passed." A session is only ever issued for a reviewer identity (see
   `app/dashboard.py`'s login route), so `identity_class` is not part of the
   payload; nothing decodes a cookie into anything but a reviewer identity.

2. A **synchronizer CSRF token** (`csrf_token_for_session`/`verify_csrf_token`):
   deterministically derived as `HMAC(SESSION_SECRET, "csrf:" + session_id)`,
   not a random value stored anywhere. This is deliberately *not* the
   double-submit-cookie pattern (a second, JS-readable cookie mirroring the
   token) — the token is rendered directly into the dashboard's HTML forms
   and vendored HTMX JS reads it from there, so there is nothing for a
   cross-site page to read: it does not have the `HttpOnly` session cookie's
   `session_id`, and does not know `SESSION_SECRET`, so it cannot compute a
   valid token even though the browser will still attach the session cookie
   itself to a forged cross-origin request. This is the standard
   synchronizer-token security property without needing a session store.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import UTC, datetime

from app.config import Settings

SESSION_COOKIE_NAME = "rg_session"
_CSRF_HEADER_NAME = "X-CSRF-Token"
_FIELD_SEP = "|"


@dataclass(frozen=True)
class SessionData:
    session_id: str
    identity_id: str
    issued_at: datetime
    expires_at: datetime


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _sign(payload_b64: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()


def new_session_id() -> str:
    """128 bits of randomness, hex-encoded. Not an API-004 identifier (this
    is an internal cookie value, never returned in a JSON response body or
    parsed by a client), so it does not use the `<prefix>_` convention."""
    return os.urandom(16).hex()


def create_session_cookie(identity_id: str, settings: Settings) -> tuple[str, SessionData]:
    """SEC-005: issues a signed session token. Returns the cookie value to
    set and the decoded SessionData (so the caller can render the matching
    CSRF token without a second verify round-trip)."""
    now = datetime.now(UTC)
    issued_epoch = int(now.timestamp())
    expires_epoch = issued_epoch + settings.SESSION_TTL_SECONDS
    session_id = new_session_id()
    payload = _FIELD_SEP.join(
        [session_id, identity_id, str(issued_epoch), str(expires_epoch)]
    ).encode("utf-8")
    payload_b64 = _b64url_encode(payload)
    signature = _sign(payload_b64, settings.effective_session_secret())
    cookie_value = f"{payload_b64}.{signature}"
    data = SessionData(
        session_id=session_id,
        identity_id=identity_id,
        issued_at=now,
        expires_at=datetime.fromtimestamp(expires_epoch, tz=UTC),
    )
    return cookie_value, data


def verify_session_cookie(cookie_value: str | None, settings: Settings) -> SessionData | None:
    """Returns None for anything invalid, unsigned, tampered, malformed, or
    expired — callers treat that identically to "no session presented"
    (SEC-005's cookie carries no ambient trust of its own; an invalid cookie
    is exactly as authenticated as no cookie)."""
    if not cookie_value or "." not in cookie_value:
        return None
    payload_b64, _, signature = cookie_value.rpartition(".")
    expected_signature = _sign(payload_b64, settings.effective_session_secret())
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        raw = _b64url_decode(payload_b64)
        session_id, identity_id, issued_str, expires_str = raw.decode("utf-8").split(_FIELD_SEP)
        issued_epoch = int(issued_str)
        expires_epoch = int(expires_str)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    now_epoch = int(datetime.now(UTC).timestamp())
    if expires_epoch <= now_epoch:
        return None
    return SessionData(
        session_id=session_id,
        identity_id=identity_id,
        issued_at=datetime.fromtimestamp(issued_epoch, tz=UTC),
        expires_at=datetime.fromtimestamp(expires_epoch, tz=UTC),
    )


def csrf_token_for_session(session_id: str, settings: Settings) -> str:
    """SEC-007: a synchronizer token bound to this session — see module
    docstring for why a deterministic HMAC needs no server-side store."""
    return hmac.new(
        settings.effective_session_secret().encode("utf-8"),
        b"csrf:" + session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_csrf_token(presented: str | None, session_id: str, settings: Settings) -> bool:
    """SEC-007: "A missing or mismatched token MUST return 403" — both cases
    return False here; the caller is responsible for the 403."""
    if not presented:
        return False
    expected = csrf_token_for_session(session_id, settings)
    return hmac.compare_digest(presented, expected)
