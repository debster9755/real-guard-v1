"""Stable error codes and the error envelope. SPEC.md §4.8 (ERR-001), §16.

ConfigurationError (ERR-017) is raised at startup, never inside a request
handler — SEC-004: "a startup failure, never a request-time one."
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    """SPEC.md §16 table. Values are the wire `code`."""

    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_FIELD = "UNSUPPORTED_FIELD"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    INVALID_AUTHENTICATION = "INVALID_AUTHENTICATION"
    INSUFFICIENT_PRIVILEGE = "INSUFFICIENT_PRIVILEGE"
    RATE_LIMITED = "RATE_LIMITED"
    POLICY_DENIED = "POLICY_DENIED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    DETECTOR_UNAVAILABLE = "DETECTOR_UNAVAILABLE"
    POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    INVALID_UPSTREAM_RESPONSE = "INVALID_UPSTREAM_RESPONSE"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    DATABASE_ERROR = "DATABASE_ERROR"
    SELF_APPROVAL_FORBIDDEN = "SELF_APPROVAL_FORBIDDEN"
    INVALID_APPROVAL_STATE = "INVALID_APPROVAL_STATE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# ERR-002 .. ERR-021: (code, default HTTP status, error `type`).
# ERR-011 status is context-dependent (ERR-023) and handled by the caller.
ERROR_STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.UNSUPPORTED_FIELD: 400,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.INVALID_AUTHENTICATION: 401,
    ErrorCode.INSUFFICIENT_PRIVILEGE: 403,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.POLICY_DENIED: 403,
    ErrorCode.IDEMPOTENCY_CONFLICT: 409,
    ErrorCode.DETECTOR_UNAVAILABLE: 403,  # fail_closed default; ERR-023 may override to 503
    ErrorCode.POLICY_UNAVAILABLE: 503,
    ErrorCode.UPSTREAM_TIMEOUT: 504,
    ErrorCode.UPSTREAM_ERROR: 502,
    ErrorCode.INVALID_UPSTREAM_RESPONSE: 502,
    ErrorCode.APPROVAL_EXPIRED: 409,
    ErrorCode.DATABASE_ERROR: 503,
    ErrorCode.SELF_APPROVAL_FORBIDDEN: 403,
    ErrorCode.INVALID_APPROVAL_STATE: 409,
    ErrorCode.INTERNAL_ERROR: 500,
}

ERROR_TYPE: dict[ErrorCode, str] = {
    ErrorCode.INVALID_REQUEST: "invalid_request",
    ErrorCode.UNSUPPORTED_FIELD: "invalid_request",
    ErrorCode.PAYLOAD_TOO_LARGE: "invalid_request",
    ErrorCode.INVALID_AUTHENTICATION: "authentication_error",
    ErrorCode.INSUFFICIENT_PRIVILEGE: "authorization_error",
    ErrorCode.RATE_LIMITED: "rate_limit_error",
    ErrorCode.POLICY_DENIED: "policy_denied",
    ErrorCode.IDEMPOTENCY_CONFLICT: "conflict",
    ErrorCode.DETECTOR_UNAVAILABLE: "degraded",
    ErrorCode.POLICY_UNAVAILABLE: "dependency_error",
    ErrorCode.UPSTREAM_TIMEOUT: "upstream_error",
    ErrorCode.UPSTREAM_ERROR: "upstream_error",
    ErrorCode.INVALID_UPSTREAM_RESPONSE: "upstream_error",
    ErrorCode.APPROVAL_EXPIRED: "conflict",
    ErrorCode.DATABASE_ERROR: "dependency_error",
    ErrorCode.SELF_APPROVAL_FORBIDDEN: "authorization_error",
    ErrorCode.INVALID_APPROVAL_STATE: "conflict",
    ErrorCode.INTERNAL_ERROR: "internal_error",
}


class FirewallError(Exception):
    """Base for request-time errors that become an ERR-001 envelope.

    ERR-022: `details` MUST NOT carry request content, evidence spans, stack
    traces or file paths — callers are responsible for keeping it to typed,
    structural information only (reason codes, policy hit ids, field names).
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        status: int | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status if status is not None else ERROR_STATUS[code]
        self.details = details or {}

    def to_envelope(self, transaction_id: str) -> dict[str, object]:
        body: dict[str, object] = {
            "error": {
                "code": self.code.value,
                "type": ERROR_TYPE[self.code],
                "message": self.message,
                "transaction_id": transaction_id,
            }
        }
        if self.details:
            body["error"]["details"] = self.details  # type: ignore[index]
        return body


class ConfigurationError(Exception):
    """ERR-017. Raised only at startup (CFG-002), never inside a request.

    The message MUST name the variable and the constraint violated, and MUST
    NOT include a secret's value (CFG-003) — only its presence/absence or
    length class.
    """
