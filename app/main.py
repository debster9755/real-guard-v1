"""FastAPI gateway. SPEC.md §2.1, §4.

Phase 1 scope only (PLAN.md §6): the gateway, the mock provider, and the
error/response envelope. There is deliberately **no detection and no policy
evaluation yet** — every request that passes validation is ALLOW/NONE via
MockProvider. WS-04 (detectors) and WS-05 (decision engine) replace the
`_run_pipeline` stub in Phase 2 without changing this module's contract.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import Settings, load_settings
from app.errors import ConfigurationError, ErrorCode, FirewallError
from app.ids import new_transaction_id
from app.policy import Policy, PolicyLoadError, load_policy
from app.providers.mock import MockProvider
from app.schemas import (
    AllowedResponse,
    FirewallMetadata,
    HealthzResponse,
    ReadyzDependencies,
    ReadyzResponse,
)

logger = logging.getLogger("realguard")

_STREAM_FIELD_MESSAGE = (
    "stream:true is not supported in the MVP (API-014) — the output guard "
    "cannot safely inspect a token stream without buffering it, which "
    "forfeits streaming's benefit. See SPEC.md §3.12 and PLAN.md §2.3 "
    "(V1.1 follow-up)."
)


class AppState:
    """Process-wide state assembled at startup. Not a DB session — Phase 1
    has no persistence yet (that arrives with WS-09 in Phase 4)."""

    settings: Settings
    policy: Policy | None
    policy_error: str | None
    provider: MockProvider

    def __init__(self) -> None:
        self.settings = load_settings()
        self.provider = MockProvider()

        # DEP-004: mock mode must be visible in at least four places. This
        # is place 1 (startup log, WARNING); /readyz and the X-RealGuard-Mode
        # header are the other two live in Phase 1 — the dashboard header
        # arrives with WS-11 in Phase 4.
        if self.settings.mock_mode:
            logger.warning(
                "real-guard-v1 starting in MOCK MODE — no UPSTREAM_BASE_URL is "
                "configured. Every completion is synthetic (app/providers/mock.py). "
                "This is the default for local evaluation; set UPSTREAM_BASE_URL to "
                "use a real provider."
            )

        try:
            self.policy = load_policy(
                self.settings.POLICY_PATH, app_env=self.settings.APP_ENV.value
            )
            self.policy_error = None
        except PolicyLoadError as e:
            # POL-009: no cached policy exists yet at first boot — surfaced
            # via /readyz rather than crashing the process, so /healthz still
            # reports the process alive and operators can see *why* readiness
            # is failing.
            self.policy = None
            self.policy_error = str(e)


def create_app() -> FastAPI:
    state = AppState()
    app = FastAPI(
        title="real-guard-v1",
        version="0.1.0",
        description="Open-source AI Firewall / FWaaS. See SPEC.md.",
    )
    app.state.rg = state

    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, settings=state.settings)

    register_exception_handlers(app)
    register_routes(app)
    return app


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """API-003: echo X-Correlation-Id if supplied, else generate one."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-Id") or f"cor_{uuid.uuid4().hex}"
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-Id"] = correlation_id
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """API-006: reject oversized bodies *before* parsing.

    Fast path uses Content-Length when present. Without one (chunked
    transfer), we enforce the limit while streaming the body so an
    attacker cannot bypass the check by omitting the header.
    """

    def __init__(self, app: Any, *, settings: Settings) -> None:
        super().__init__(app)
        self._max_bytes = settings.MAX_REQUEST_BYTES

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > self._max_bytes:
                        return _payload_too_large_response(request)
                except ValueError:
                    pass  # malformed header; let body-read enforcement below catch it
            else:
                body = await request.body()
                if len(body) > self._max_bytes:
                    return _payload_too_large_response(request)

                async def _receive() -> dict[str, Any]:
                    return {"type": "http.request", "body": body, "more_body": False}

                request._receive = _receive  # noqa: SLF001 — Starlette's documented re-inject pattern
        return await call_next(request)


def _payload_too_large_response(request: Request) -> JSONResponse:
    txn_id = new_transaction_id()
    return JSONResponse(
        status_code=413,
        content={
            "error": {
                "code": ErrorCode.PAYLOAD_TOO_LARGE.value,
                "type": "invalid_request",
                "message": "Request body exceeds MAX_REQUEST_BYTES.",
                "transaction_id": txn_id,
            }
        },
    )


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(FirewallError)
    async def _firewall_error_handler(request: Request, exc: FirewallError) -> JSONResponse:
        txn_id = getattr(request.state, "transaction_id", None) or new_transaction_id()
        return JSONResponse(status_code=exc.status, content=exc.to_envelope(txn_id))

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # ERR-002 INVALID_REQUEST. ERR-022: no request content in the body —
        # Pydantic's error `loc`/`msg` are structural (field paths and
        # constraint names), not content, so they're safe to return.
        txn_id = new_transaction_id()
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": ErrorCode.INVALID_REQUEST.value,
                    "type": "invalid_request",
                    "message": "Request body failed validation.",
                    "transaction_id": txn_id,
                    "details": {"errors": exc.errors()},
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        txn_id = getattr(request.state, "transaction_id", None) or new_transaction_id()
        logger.exception("unhandled exception", extra={"transaction_id": txn_id})
        # ERR-021 / ERR-022: generic message + transaction_id only; no stack
        # trace or internal detail crosses the wire.
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": ErrorCode.INTERNAL_ERROR.value,
                    "type": "internal_error",
                    "message": "An internal error occurred.",
                    "transaction_id": txn_id,
                }
            },
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def register_routes(app: FastAPI) -> None:
    @app.post("/v1/chat/completions")
    async def create_chat_completion(request: Request) -> Response:
        state: AppState = app.state.rg
        txn_id = new_transaction_id()
        request.state.transaction_id = txn_id

        body = await request.json()

        # API-014: stream:true is rejected before any detection/policy work.
        if body.get("stream") is True:
            raise FirewallError(
                ErrorCode.UNSUPPORTED_FIELD,
                _STREAM_FIELD_MESSAGE,
                details={"field": "stream"},
            )

        if "messages" not in body or not isinstance(body["messages"], list) or not body["messages"]:
            raise FirewallError(
                ErrorCode.INVALID_REQUEST,
                "`messages` is required and must be a non-empty array.",
            )

        mode = "mock" if state.settings.mock_mode else "live"
        policy_version = state.policy.policy_version if state.policy else "unavailable"

        t0 = time.perf_counter()
        upstream_response = await state.provider.complete(body)
        firewall_added_ms = (time.perf_counter() - t0) * 1000

        # ADR 0002: the completion fields go at the TOP LEVEL (unpacked from
        # upstream_response), not nested under a `response` key — required
        # for the real openai SDK's ChatCompletion parsing to work unmodified.
        allowed = AllowedResponse(
            id=upstream_response["id"],
            object=upstream_response["object"],
            created=upstream_response["created"],
            model=upstream_response["model"],
            choices=upstream_response["choices"],
            usage=upstream_response["usage"],
            firewall=FirewallMetadata(
                transaction_id=txn_id,
                policy_version=policy_version,
                mode=mode,
                timings_ms={
                    "detection": 0.0,
                    "policy": 0.0,
                    "upstream": firewall_added_ms,
                    "output_guard": 0.0,
                    "firewall_added": firewall_added_ms,
                },
            ),
        )
        response = JSONResponse(status_code=200, content=allowed.model_dump())
        response.headers["X-RealGuard-Transaction-Id"] = txn_id
        response.headers["X-RealGuard-Mode"] = mode
        return response

    @app.get("/healthz")
    async def healthz() -> HealthzResponse:
        # API-015: never touches the database, never rate limited.
        return HealthzResponse()

    @app.get("/readyz")
    async def readyz(response: Response) -> ReadyzResponse:
        state: AppState = app.state.rg
        mode = "mock" if state.settings.mock_mode else "live"
        policy_status: Any = "ok" if state.policy is not None else "invalid"
        provider_status: Any = "ok" if mode == "mock" else "not_configured"

        ready = state.policy is not None
        if not ready:
            response.status_code = 503

        return ReadyzResponse(
            ready=ready,
            mode=mode,
            dependencies=ReadyzDependencies(
                database="not_configured",  # DB arrives in Phase 4 (WS-09)
                policy=policy_status,
                provider=provider_status,
            ),
        )


try:
    app = create_app()
except ConfigurationError as e:
    # SEC-004 / CFG-002: configuration failures are startup failures, not
    # request-time ones. Fail loudly and refuse to serve anything.
    raise SystemExit(f"real-guard-v1: invalid configuration, refusing to start:\n{e}") from e
