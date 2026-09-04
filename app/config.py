"""Environment configuration. SPEC.md §15 (CFG-001..004).

CFG-001: all configuration comes from environment variables, parsed and
validated by this Pydantic model at startup.
CFG-002: invalid configuration MUST fail startup with a message naming the
variable and the constraint violated — never a partially configured start.
CFG-003: a variable marked secret MUST NOT be logged or echoed in an error.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from typing import Annotated

from pydantic import (
    AfterValidator,
    Field,
    PrivateAttr,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.errors import ConfigurationError


class AppEnv(StrEnum):
    development = "development"
    staging = "staging"
    production = "production"


class ContentRetention(StrEnum):
    none = "none"
    metadata = "metadata"
    encrypted = "encrypted"
    full = "full"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def _split_csv(raw: str | list[str]) -> list[str]:
    if isinstance(raw, list):
        return [s.strip() for s in raw if s.strip()]
    return [s.strip() for s in raw.split(",") if s.strip()]


CsvList = Annotated[list[str], AfterValidator(lambda v: v)]

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_MIN_KEY_LENGTH = 32
_MIN_SESSION_SECRET_BYTES = 32
_MIN_HASH_SALT_BYTES = 16
_MIN_CONTENT_ENCRYPTION_KEY_BYTES = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Core ------------------------------------------------------------
    APP_ENV: AppEnv = AppEnv.development
    BIND_HOST: str = "127.0.0.1"
    BIND_PORT: int = Field(default=8000, ge=1, le=65535)

    # --- Authentication (SEC-001..004) ------------------------------------
    FIREWALL_API_KEYS: str = ""
    FIREWALL_REVIEWER_KEYS: str = ""
    SESSION_SECRET: SecretStr | None = None

    # --- Upstream provider -------------------------------------------------
    UPSTREAM_BASE_URL: str | None = None
    UPSTREAM_API_KEY: SecretStr | None = None
    UPSTREAM_MODEL: str = Field(default="qwen3:8b", min_length=1)

    # --- Policy and storage ------------------------------------------------
    POLICY_PATH: str = "policies/default_policy.yaml"
    DATABASE_URL: str = "sqlite:///./data/realguard.db"
    CONTENT_RETENTION: ContentRetention = ContentRetention.metadata
    CONTENT_ENCRYPTION_KEY: SecretStr | None = None

    # --- Logging / limits ----------------------------------------------
    LOG_LEVEL: LogLevel = LogLevel.INFO
    REQUEST_TIMEOUT_SECONDS: float = Field(default=60.0, ge=1, le=600)
    MAX_REQUEST_BYTES: int = Field(default=262144, ge=1024, le=10485760)
    APPROVAL_TTL_SECONDS: int = Field(default=3600, ge=60, le=604800)
    DETECTOR_TIMEOUT_MS: int = Field(default=250, ge=10, le=5000)
    MAX_DECODE_DEPTH: int = Field(default=3, ge=0, le=5)
    MAX_RESUME_ATTEMPTS: int = Field(default=3, ge=1, le=10)
    SESSION_TTL_SECONDS: int = Field(default=3600, ge=300, le=86400)
    IDEMPOTENCY_TTL_SECONDS: int = Field(default=86400, ge=60, le=604800)
    AUDIT_RETENTION_DAYS: int = Field(default=90, ge=1, le=3650)
    CONTENT_RETENTION_DAYS: int = Field(default=7, ge=1)
    RATE_LIMIT_REQUESTS: int = Field(default=60, ge=1)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, ge=1)
    METRICS_REQUIRE_AUTH: bool = False

    # --- Secrets with no safe default -----------------------------------
    HASH_SALT: SecretStr | None = None

    # --- Escape hatches (DEP-005, PRV-002) --------------------------------
    ALLOW_MOCK_IN_PRODUCTION: bool = False
    ALLOW_PLAINTEXT_RETENTION: bool = False

    # --- Ollama preflight (SPEC.md §2.10, DEP-003; Phase 5 / ADR 0007) -----
    # Not in SPEC.md §15's table verbatim — ADR 0007 documents why a
    # dedicated opt-in flag (rather than sniffing UPSTREAM_BASE_URL for
    # something that looks like Ollama) is the startup preflight's trigger.
    # False by default everywhere except the `ollama-host` compose profile,
    # which sets it true alongside UPSTREAM_BASE_URL.
    OLLAMA_PREFLIGHT_ENABLED: bool = False

    # ---- process-lifetime caches for lazily-generated ephemeral secrets --
    # (not settings fields themselves — see effective_session_secret/salt)
    _ephemeral_session_secret: str | None = PrivateAttr(default=None)
    _ephemeral_hash_salt: str | None = PrivateAttr(default=None)

    # ---- field-level validation -------------------------------------------

    @field_validator("BIND_HOST")
    @classmethod
    def _bind_host_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ConfigurationError("BIND_HOST must not be empty")
        return v

    @field_validator("CONTENT_RETENTION_DAYS")
    @classmethod
    def _content_retention_days_positive(cls, v: int) -> int:
        # Upper bound (<= AUDIT_RETENTION_DAYS) is a cross-field rule; see
        # model_validator below (CFG-002: name the constraint that failed).
        return v

    # ---- cross-field / environment-dependent validation (CFG-002) --------

    @model_validator(mode="after")
    def _validate_cross_field(self) -> Settings:
        errors: list[str] = []
        is_production = AppEnv.production == self.APP_ENV
        is_loopback = self.BIND_HOST in _LOOPBACK_HOSTS

        # SEC-003 / SEC-004: unauthenticated operation only on loopback dev;
        # production requires both key sets, each entry long enough, disjoint.
        service_keys = _split_csv(self.FIREWALL_API_KEYS)
        reviewer_keys = _split_csv(self.FIREWALL_REVIEWER_KEYS)

        for key in service_keys:
            if len(key) < _MIN_KEY_LENGTH:
                errors.append(
                    f"FIREWALL_API_KEYS: every key must be >= {_MIN_KEY_LENGTH} chars "
                    f"(found one of length {len(key)})"
                )
                break
        for key in reviewer_keys:
            if len(key) < _MIN_KEY_LENGTH:
                errors.append(
                    f"FIREWALL_REVIEWER_KEYS: every key must be >= {_MIN_KEY_LENGTH} chars "
                    f"(found one of length {len(key)})"
                )
                break

        overlap = set(service_keys) & set(reviewer_keys)
        if overlap:
            errors.append(
                "FIREWALL_API_KEYS and FIREWALL_REVIEWER_KEYS must be disjoint "
                f"(found {len(overlap)} shared key(s)) — SEC-006/APR-009"
            )

        if is_production:
            if not service_keys:
                errors.append("FIREWALL_API_KEYS is required when APP_ENV=production (SEC-004)")
            if not reviewer_keys:
                errors.append(
                    "FIREWALL_REVIEWER_KEYS is required when APP_ENV=production (SEC-004)"
                )
        elif not is_loopback and not service_keys and not reviewer_keys:
            errors.append(
                "BIND_HOST is non-loopback but no API keys are configured — "
                "unauthenticated operation is permitted only on a loopback bind (SEC-003)"
            )

        # SESSION_SECRET: production requires a persistent value >= 32 bytes.
        if is_production:
            if self.SESSION_SECRET is None:
                errors.append("SESSION_SECRET is required when APP_ENV=production")
            elif len(self.SESSION_SECRET.get_secret_value()) < _MIN_SESSION_SECRET_BYTES:
                errors.append(
                    f"SESSION_SECRET must be >= {_MIN_SESSION_SECRET_BYTES} bytes in production"
                )

        # HASH_SALT: production requires a persistent value >= 16 bytes.
        if is_production:
            if self.HASH_SALT is None:
                errors.append("HASH_SALT is required when APP_ENV=production")
            elif len(self.HASH_SALT.get_secret_value()) < _MIN_HASH_SALT_BYTES:
                errors.append(f"HASH_SALT must be >= {_MIN_HASH_SALT_BYTES} bytes in production")

        # UPSTREAM_BASE_URL required in production (DEP-005: mock must not
        # activate silently).
        if is_production and not self.UPSTREAM_BASE_URL and not self.ALLOW_MOCK_IN_PRODUCTION:
            errors.append(
                "UPSTREAM_BASE_URL is required when APP_ENV=production "
                "(mock mode must not activate silently — DEP-005). "
                "Set ALLOW_MOCK_IN_PRODUCTION=true to override explicitly."
            )

        # OLLAMA_PREFLIGHT_ENABLED only makes sense against a real upstream
        # (ADR 0007) — enabling it in mock mode would mean checking Ollama's
        # health for a provider that never talks to it.
        if self.OLLAMA_PREFLIGHT_ENABLED and not self.UPSTREAM_BASE_URL:
            errors.append(
                "OLLAMA_PREFLIGHT_ENABLED=true requires UPSTREAM_BASE_URL to be set "
                "(the preflight checks the host Ollama the configured upstream points at; "
                "mock mode has no upstream to check)"
            )

        # CONTENT_RETENTION=full: warn in any env, refuse in production
        # without the explicit override (PRV-002).
        if (
            ContentRetention.full == self.CONTENT_RETENTION
            and is_production
            and not self.ALLOW_PLAINTEXT_RETENTION
        ):
            errors.append(
                "CONTENT_RETENTION=full is refused when APP_ENV=production "
                "unless ALLOW_PLAINTEXT_RETENTION=true is also set (PRV-002)"
            )

        # CONTENT_ENCRYPTION_KEY required if CONTENT_RETENTION=encrypted.
        if ContentRetention.encrypted == self.CONTENT_RETENTION:
            if self.CONTENT_ENCRYPTION_KEY is None:
                errors.append("CONTENT_ENCRYPTION_KEY is required when CONTENT_RETENTION=encrypted")
            elif (
                len(self.CONTENT_ENCRYPTION_KEY.get_secret_value())
                < _MIN_CONTENT_ENCRYPTION_KEY_BYTES
            ):
                errors.append(
                    f"CONTENT_ENCRYPTION_KEY must be >= {_MIN_CONTENT_ENCRYPTION_KEY_BYTES} bytes"
                )

        # CONTENT_RETENTION_DAYS <= AUDIT_RETENTION_DAYS.
        if self.CONTENT_RETENTION_DAYS > self.AUDIT_RETENTION_DAYS:
            errors.append(
                "CONTENT_RETENTION_DAYS must be <= AUDIT_RETENTION_DAYS "
                f"(got {self.CONTENT_RETENTION_DAYS} > {self.AUDIT_RETENTION_DAYS})"
            )

        # METRICS_REQUIRE_AUTH: production must not run with metrics
        # unauthenticated (fail-safe production defaults, PLAN.md principle 8)
        # — fails startup rather than silently overriding the operator's
        # explicit choice.
        if is_production and not self.METRICS_REQUIRE_AUTH:
            errors.append(
                "METRICS_REQUIRE_AUTH must be true when APP_ENV=production "
                "(set METRICS_REQUIRE_AUTH=true explicitly)"
            )

        if errors:
            raise ConfigurationError(
                "Invalid configuration ("
                + str(len(errors))
                + " error(s)):\n  - "
                + "\n  - ".join(errors)
            )
        return self

    # ---- derived helpers ---------------------------------------------------

    @property
    def service_keys(self) -> list[str]:
        return _split_csv(self.FIREWALL_API_KEYS)

    @property
    def reviewer_keys(self) -> list[str]:
        return _split_csv(self.FIREWALL_REVIEWER_KEYS)

    @property
    def is_loopback_bind(self) -> bool:
        return self.BIND_HOST in _LOOPBACK_HOSTS

    @property
    def mock_mode(self) -> bool:
        """DEP-004/DEP-005: mock mode is active iff no upstream is configured."""
        return not self.UPSTREAM_BASE_URL

    def effective_session_secret(self) -> str:
        """Ephemeral means "not persisted across restarts", NOT "regenerated
        on every call" — a value that changed between two calls within the
        same process would make every session cookie unverifiable moments
        after being signed, defeating session auth entirely in development.
        Generated once, lazily, and cached for this process's lifetime;
        production always has a persistent, operator-supplied one by the
        validation above, so this fallback path never runs there."""
        if self.SESSION_SECRET is not None:
            return self.SESSION_SECRET.get_secret_value()
        if self._ephemeral_session_secret is None:
            self._ephemeral_session_secret = secrets.token_urlsafe(32)
        return self._ephemeral_session_secret

    def effective_hash_salt(self) -> str:
        """See effective_session_secret() — same "stable per process" reasoning
        applies: a salt that changed between calls would make every
        previously-computed content hash unreproducible within the same
        process."""
        if self.HASH_SALT is not None:
            return self.HASH_SALT.get_secret_value()
        if self._ephemeral_hash_salt is None:
            self._ephemeral_hash_salt = secrets.token_urlsafe(16)
        return self._ephemeral_hash_salt


def load_settings() -> Settings:
    """Construct Settings, translating pydantic's ValidationError message
    class into our ConfigurationError type where relevant. Pydantic-level
    field errors (e.g. BIND_PORT out of range) already carry a field name and
    constraint, satisfying CFG-002; ConfigurationError from the cross-field
    validator is re-raised as-is.
    """
    return Settings()  # values come from the environment, not call arguments
