"""Unit tests for app/session.py — SPEC.md §11.3 (SEC-005, SEC-007).

These are pure unit tests against the signing/verification primitives, not
against the HTTP layer (tests/test_dashboard.py covers that end to end).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.session import (
    create_session_cookie,
    csrf_token_for_session,
    verify_csrf_token,
    verify_session_cookie,
)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "APP_ENV": "development",
        "BIND_HOST": "127.0.0.1",
        "FIREWALL_API_KEYS": "",
        "FIREWALL_REVIEWER_KEYS": "",
        "SESSION_SECRET": "a-fixed-test-session-secret-of-32-bytes-min",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class TestSessionCookieRoundTrip:
    def test_valid_cookie_round_trips_to_the_same_identity(self) -> None:
        settings = _settings()
        cookie_value, data = create_session_cookie("key_abc123", settings)
        verified = verify_session_cookie(cookie_value, settings)
        assert verified is not None
        assert verified.identity_id == "key_abc123"
        assert verified.session_id == data.session_id

    def test_none_cookie_is_rejected(self) -> None:
        settings = _settings()
        assert verify_session_cookie(None, settings) is None

    def test_garbage_cookie_is_rejected(self) -> None:
        settings = _settings()
        assert verify_session_cookie("not-a-valid-cookie-value", settings) is None
        assert verify_session_cookie("", settings) is None
        assert verify_session_cookie("abc.def", settings) is None

    def test_tampered_payload_is_rejected(self) -> None:
        """Flipping any byte of the payload without re-signing must fail —
        the signature is over the exact base64 payload string."""
        settings = _settings()
        cookie_value, _ = create_session_cookie("key_abc123", settings)
        payload_b64, _, signature = cookie_value.rpartition(".")
        tampered = payload_b64 + "x." + signature
        assert verify_session_cookie(tampered, settings) is None

    def test_tampered_signature_is_rejected(self) -> None:
        settings = _settings()
        cookie_value, _ = create_session_cookie("key_abc123", settings)
        payload_b64, _, signature = cookie_value.rpartition(".")
        flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
        assert verify_session_cookie(f"{payload_b64}.{flipped}", settings) is None

    def test_cookie_signed_with_a_different_secret_is_rejected(self) -> None:
        settings_a = _settings(SESSION_SECRET="secret-one-that-is-at-least-32-bytes-long")
        settings_b = _settings(SESSION_SECRET="secret-two-that-is-at-least-32-bytes-long")
        cookie_value, _ = create_session_cookie("key_abc123", settings_a)
        assert verify_session_cookie(cookie_value, settings_b) is None

    def test_expired_cookie_is_rejected(self) -> None:
        """SEC-005: expiry SESSION_TTL_SECONDS (default 3600) — a cookie
        signed with a TTL of 1 second is rejected once that second passes,
        even though the signature itself is still valid."""
        settings = _settings(SESSION_TTL_SECONDS=300)
        # A TTL below the Settings field's own minimum (ge=300) can't be
        # constructed via Settings, so we directly forge an already-expired
        # payload using the same encoding create_session_cookie() uses.
        import base64

        from app.session import _FIELD_SEP, _b64url_encode, _sign  # noqa: SLF001 — test-only

        now_epoch = int(datetime.now(UTC).timestamp())
        expired_payload = _FIELD_SEP.join(
            [
                "deadbeefdeadbeefdeadbeefdeadbeef",
                "key_abc123",
                str(now_epoch - 10),
                str(now_epoch - 1),
            ]
        ).encode("utf-8")
        payload_b64 = _b64url_encode(expired_payload)
        signature = _sign(payload_b64, settings.effective_session_secret())
        cookie_value = f"{payload_b64}.{signature}"
        assert base64  # silence unused-import lint if inlined differs
        assert verify_session_cookie(cookie_value, settings) is None

    def test_cookie_data_expires_at_matches_settings_ttl(self) -> None:
        settings = _settings(SESSION_TTL_SECONDS=1800)
        _cookie_value, data = create_session_cookie("key_abc123", settings)
        delta = data.expires_at - data.issued_at
        assert abs(delta - timedelta(seconds=1800)) < timedelta(seconds=2)


class TestCsrfToken:
    def test_token_is_deterministic_for_the_same_session_and_secret(self) -> None:
        settings = _settings()
        t1 = csrf_token_for_session("session-id-1", settings)
        t2 = csrf_token_for_session("session-id-1", settings)
        assert t1 == t2

    def test_token_differs_across_sessions(self) -> None:
        settings = _settings()
        t1 = csrf_token_for_session("session-id-1", settings)
        t2 = csrf_token_for_session("session-id-2", settings)
        assert t1 != t2

    def test_token_differs_across_secrets(self) -> None:
        settings_a = _settings(SESSION_SECRET="secret-one-that-is-at-least-32-bytes-long")
        settings_b = _settings(SESSION_SECRET="secret-two-that-is-at-least-32-bytes-long")
        assert csrf_token_for_session("session-id-1", settings_a) != csrf_token_for_session(
            "session-id-1", settings_b
        )

    def test_verify_accepts_the_correct_token(self) -> None:
        settings = _settings()
        token = csrf_token_for_session("session-id-1", settings)
        assert verify_csrf_token(token, "session-id-1", settings) is True

    def test_verify_rejects_missing_token(self) -> None:
        settings = _settings()
        assert verify_csrf_token(None, "session-id-1", settings) is False
        assert verify_csrf_token("", "session-id-1", settings) is False

    def test_verify_rejects_mismatched_token(self) -> None:
        settings = _settings()
        token = csrf_token_for_session("session-id-1", settings)
        assert verify_csrf_token(token, "a-different-session-id", settings) is False
        assert verify_csrf_token("0" * len(token), "session-id-1", settings) is False


def test_ephemeral_secret_is_stable_within_a_process_lifetime() -> None:
    """No SESSION_SECRET configured (dev-mode default): the effective
    secret must not change between two calls in the same process, or every
    session/CSRF token would be unverifiable moments after being issued."""
    settings = Settings(
        APP_ENV="development",
        BIND_HOST="127.0.0.1",
        FIREWALL_API_KEYS="",
        FIREWALL_REVIEWER_KEYS="",
    )
    cookie_value, _ = create_session_cookie("key_abc123", settings)
    time.sleep(0.01)
    assert verify_session_cookie(cookie_value, settings) is not None
