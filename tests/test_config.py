"""WS-02 configuration tests. SPEC.md §15 (CFG-001..004)."""

from __future__ import annotations

import pytest
from app.config import ConfigurationError, Settings

VALID_KEY_A = "a" * 32
VALID_KEY_B = "b" * 32


def test_defaults_are_valid_in_development(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("UPSTREAM_BASE_URL", raising=False)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.APP_ENV.value == "development"
    assert s.mock_mode is True
    assert s.is_loopback_bind is True


def test_production_requires_service_and_reviewer_keys() -> None:
    with pytest.raises(ConfigurationError, match="FIREWALL_API_KEYS is required"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            APP_ENV="production",
            UPSTREAM_BASE_URL="https://api.example.com/v1",
            SESSION_SECRET="s" * 32,
            HASH_SALT="h" * 16,
            METRICS_REQUIRE_AUTH=True,
        )


def test_production_with_valid_keys_succeeds() -> None:
    s = Settings(  # type: ignore[call-arg]
        _env_file=None,
        APP_ENV="production",
        BIND_HOST="0.0.0.0",
        FIREWALL_API_KEYS=VALID_KEY_A,
        FIREWALL_REVIEWER_KEYS=VALID_KEY_B,
        UPSTREAM_BASE_URL="https://api.example.com/v1",
        SESSION_SECRET="s" * 32,
        HASH_SALT="h" * 16,
        METRICS_REQUIRE_AUTH=True,
    )
    assert s.service_keys == [VALID_KEY_A]
    assert s.reviewer_keys == [VALID_KEY_B]


def test_service_and_reviewer_keys_must_be_disjoint() -> None:
    """SEC-006/APR-009: a shared key would let one identity both call the
    gateway and decide approvals — the confused-deputy control."""
    with pytest.raises(ConfigurationError, match="disjoint"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            APP_ENV="production",
            FIREWALL_API_KEYS=VALID_KEY_A,
            FIREWALL_REVIEWER_KEYS=VALID_KEY_A,
            UPSTREAM_BASE_URL="https://api.example.com/v1",
            SESSION_SECRET="s" * 32,
            HASH_SALT="h" * 16,
            METRICS_REQUIRE_AUTH=True,
        )


def test_short_keys_rejected() -> None:
    with pytest.raises(ConfigurationError, match="FIREWALL_API_KEYS"):
        Settings(_env_file=None, FIREWALL_API_KEYS="too-short")  # type: ignore[call-arg]


def test_nonloopback_bind_without_keys_rejected_in_dev() -> None:
    """SEC-003: unauthenticated operation only on a loopback bind."""
    with pytest.raises(ConfigurationError, match="loopback"):
        Settings(_env_file=None, BIND_HOST="0.0.0.0")  # type: ignore[call-arg]


def test_nonloopback_bind_with_keys_is_fine_in_dev() -> None:
    s = Settings(  # type: ignore[call-arg]
        _env_file=None,
        BIND_HOST="0.0.0.0",
        FIREWALL_API_KEYS=VALID_KEY_A,
    )
    assert s.is_loopback_bind is False


def test_production_requires_upstream_url_dep005() -> None:
    """DEP-005: mock mode must not activate silently in production."""
    with pytest.raises(ConfigurationError, match="UPSTREAM_BASE_URL"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            APP_ENV="production",
            FIREWALL_API_KEYS=VALID_KEY_A,
            FIREWALL_REVIEWER_KEYS=VALID_KEY_B,
            SESSION_SECRET="s" * 32,
            HASH_SALT="h" * 16,
            METRICS_REQUIRE_AUTH=True,
        )


def test_production_allows_mock_with_explicit_override() -> None:
    s = Settings(  # type: ignore[call-arg]
        _env_file=None,
        APP_ENV="production",
        FIREWALL_API_KEYS=VALID_KEY_A,
        FIREWALL_REVIEWER_KEYS=VALID_KEY_B,
        SESSION_SECRET="s" * 32,
        HASH_SALT="h" * 16,
        METRICS_REQUIRE_AUTH=True,
        ALLOW_MOCK_IN_PRODUCTION=True,
    )
    assert s.mock_mode is True


def test_content_retention_full_refused_in_production() -> None:
    """PRV-002."""
    with pytest.raises(ConfigurationError, match="CONTENT_RETENTION=full"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            APP_ENV="production",
            FIREWALL_API_KEYS=VALID_KEY_A,
            FIREWALL_REVIEWER_KEYS=VALID_KEY_B,
            UPSTREAM_BASE_URL="https://api.example.com/v1",
            SESSION_SECRET="s" * 32,
            HASH_SALT="h" * 16,
            METRICS_REQUIRE_AUTH=True,
            CONTENT_RETENTION="full",
        )


def test_content_retention_full_allowed_in_dev() -> None:
    s = Settings(_env_file=None, CONTENT_RETENTION="full")  # type: ignore[call-arg]
    assert s.CONTENT_RETENTION.value == "full"


def test_content_encryption_key_required_when_encrypted() -> None:
    with pytest.raises(ConfigurationError, match="CONTENT_ENCRYPTION_KEY"):
        Settings(_env_file=None, CONTENT_RETENTION="encrypted")  # type: ignore[call-arg]


def test_content_retention_days_must_not_exceed_audit_retention() -> None:
    with pytest.raises(ConfigurationError, match="CONTENT_RETENTION_DAYS"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            AUDIT_RETENTION_DAYS=10,
            CONTENT_RETENTION_DAYS=20,
        )


def test_metrics_require_auth_forced_in_production() -> None:
    with pytest.raises(ConfigurationError, match="METRICS_REQUIRE_AUTH"):
        Settings(  # type: ignore[call-arg]
            _env_file=None,
            APP_ENV="production",
            FIREWALL_API_KEYS=VALID_KEY_A,
            FIREWALL_REVIEWER_KEYS=VALID_KEY_B,
            UPSTREAM_BASE_URL="https://api.example.com/v1",
            SESSION_SECRET="s" * 32,
            HASH_SALT="h" * 16,
            METRICS_REQUIRE_AUTH=False,
        )


def test_bind_port_out_of_range_rejected() -> None:
    with pytest.raises(Exception, match="BIND_PORT|less than or equal"):
        Settings(_env_file=None, BIND_PORT=99999)  # type: ignore[call-arg]


def test_secret_value_never_appears_in_repr() -> None:
    """CFG-003: SecretStr fields must not leak their value via repr/str."""
    s = Settings(_env_file=None, SESSION_SECRET="s" * 32)  # type: ignore[call-arg]
    assert "s" * 32 not in repr(s.SESSION_SECRET)
    assert "**********" in repr(s.SESSION_SECRET) or "SecretStr" in repr(s.SESSION_SECRET)


def test_ephemeral_session_secret_stable_within_a_process() -> None:
    """"Ephemeral" means not persisted across restarts — NOT regenerated on
    every call. A value that changed between calls within one process would
    make a session cookie unverifiable moments after being signed."""
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    secret1 = s.effective_session_secret()
    secret2 = s.effective_session_secret()
    assert len(secret1) > 0
    assert secret1 == secret2


def test_ephemeral_session_secret_differs_across_instances() -> None:
    """Different process/instance -> different ephemeral secret (it isn't a
    hardcoded fallback constant)."""
    s1 = Settings(_env_file=None)  # type: ignore[call-arg]
    s2 = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s1.effective_session_secret() != s2.effective_session_secret()


def test_ephemeral_hash_salt_stable_within_a_process() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.effective_hash_salt() == s.effective_hash_salt()
