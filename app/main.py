"""FastAPI gateway. SPEC.md §2.1, §4.

Phase 2 (PLAN.md §6, ADR 0003): full input-plane inspection is wired in —
normalizer, detector orchestrator, risk aggregation, decision engine, and
REDACT transformation.

ADR 0004 (pulled forward from Phase 4, at the user's direction, before
Phase 3): the NEED_APPROVAL path is real — durable persistence, the full
state machine, a reviewer decision endpoint, a poll endpoint and a list
endpoint — not the refusal stub Phase 2 shipped. See app/approvals.py and
docs/adr/0004-approval-workflow-mvp.md for the full account and its scope
boundary (the HTML reviewer dashboard is not part of this slice).

Phase 3 (ADR 0005): the generic OpenAI-compatible provider adapter is wired
in alongside MockProvider; the output guard (app/outputguard.py) runs after
every upstream call on the ALLOW path (and, via app/approvals.py, on the
approval-resume path too — SYS-014); and tool-call inspection
(app/detectors/tool_calls.py, app/pipeline.py) gives the decision engine's
already-built condition evaluator real tool_name/tool_arguments instead of
Phase 2's empty stub.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CollectorRegistry, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from app.approvals import (
    APPROVAL_STATES,
    count_by_state,
    create_approval,
    decide_and_resume,
    get_approval_by_transaction,
    get_transaction,
    list_approvals,
    reconcile_resuming_on_startup,
    sweep_expired,
)
from app.audit import record_decision_event
from app.auth import IdentityClass, require_reviewer, resolve_decision_identity, resolve_identity
from app.config import Settings, load_settings
from app.dashboard import register_dashboard_routes
from app.db import make_engine
from app.decision import combine_decisions
from app.detectors.base import Category, Detector, Finding
from app.errors import ConfigurationError, ErrorCode, FirewallError
from app.ids import new_id, new_transaction_id
from app.logging_config import configure_logging
from app.materialargs import compute_material_args_hash
from app.metrics import ENDPOINT_TEMPLATES, Metrics, build_metrics
from app.outputguard import run_output_guard, system_prompt_text_from_messages
from app.pipeline import build_input_detectors, run_input_pipeline
from app.policy import Policy, PolicyLoadError, load_policy
from app.providers.base import Provider, UpstreamResponseError, UpstreamTimeoutError
from app.providers.mock import MockProvider
from app.providers.ollama_preflight import check_ollama_preflight
from app.providers.openai_compatible import (
    OpenAICompatibleProvider,
    SsrfValidationError,
    validate_upstream_url_for_production,
)
from app.ratelimit import check_rate_limit, rate_limit_config_from_policy
from app.schemas import (
    AllowedResponse,
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalListResponse,
    ApprovalPreview,
    DeniedFirewallMetadata,
    DeniedResponse,
    FindingSummary,
    FirewallMetadata,
    HealthzResponse,
    NeedApprovalResponse,
    ReadyzDependencies,
    ReadyzResponse,
    TransactionStatusResponse,
)
from app.session import SESSION_COOKIE_NAME
from app.transform import TransformationError, apply_transformation_to_messages

logger = logging.getLogger("realguard")


def _rfc3339(dt: datetime) -> str:
    """API-005: RFC 3339 UTC with a `Z` suffix. Every datetime this module
    touches is naive-but-UTC by app/approvals.py's `_now()` convention."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_allowlist_from_policy(policy: Policy) -> frozenset[str]:
    """OBS-012 (Phase 6): the bounded vocabulary `realguard_tool_findings_total`'s
    `tool_name` label is clamped to — read from the loaded policy's own
    `agent_tool_allowlist` rule, mirroring
    app/detectors/tool_calls.py's `_extract_allowlist()` exactly, so the
    metric's bound can never silently drift from what the policy actually
    allows."""
    for rule in policy.rules:
        if rule.get("id") != "agent_tool_allowlist":
            continue
        condition = rule.get("when", {})
        if "tool_not_in" in condition:
            return frozenset(condition["tool_not_in"])
    return frozenset()


_STREAM_FIELD_MESSAGE = (
    "stream:true is not supported in the MVP (API-014) — the output guard "
    "cannot safely inspect a token stream without buffering it, which "
    "forfeits streaming's benefit. See SPEC.md §3.12 and PLAN.md §2.3 "
    "(V1.1 follow-up)."
)


class AppState:
    """Process-wide state assembled at startup.

    ADR 0004: `db_engine` backs the approval workflow only (transactions are
    written to it exactly when the verdict is NEED_APPROVAL — the ALLOW/DENY
    paths remain exactly as Phase 2 left them, no DB dependency). Full
    per-request persistence for every verdict is still Phase 4 (WS-09).
    """

    settings: Settings
    policy: Policy | None
    policy_error: str | None
    provider: Provider
    detectors: list[Detector]
    db_engine: Any
    metrics: Metrics
    provider_status: str
    """ok | unreachable | not_configured — surfaced verbatim on `/readyz`.

    mock mode: always "ok" (the mock provider cannot fail — SPEC.md §2.9).
    Live mode, preflight disabled: "not_configured" — unchanged Phase 1-4
    behaviour; this build makes no reachability claim about a generic
    OpenAI-compatible upstream it was never asked to check.
    Live mode, preflight enabled (`OLLAMA_PREFLIGHT_ENABLED=true` — the
    `ollama-host` compose profile): the real result of the §2.10/DEP-003
    startup preflight below, cached for the process's lifetime.
    """

    def __init__(self) -> None:
        self.settings = load_settings()
        # OBS-004/PRV-007 (Phase 6, WS-12): configured before anything else
        # logs, so every line this process ever writes — including the
        # mock-mode warning three lines below — goes through the
        # allowlist-filtering JSON formatter.
        configure_logging(self.settings.LOG_LEVEL.value)
        self.provider = self._build_provider(self.settings)
        self.db_engine = make_engine(self.settings.DATABASE_URL)
        # Phase 6 (WS-12): a fresh CollectorRegistry per AppState, never the
        # process-wide default — tests/conftest.py's client_factory builds
        # many AppStates in one process, and re-registering the same metric
        # name against a shared registry raises (app/metrics.py docstring).
        self.metrics = build_metrics(CollectorRegistry())
        # APR-014: reconcile any row a prior process crash left in RESUMING
        # before this process serves a single request.
        reconciled = reconcile_resuming_on_startup(
            self.db_engine, self.settings.MAX_RESUME_ATTEMPTS, metrics=self.metrics
        )
        if reconciled:
            logger.warning("startup: reconciled %d RESUMING approval(s) (APR-014)", reconciled)

        # realguard_approval_queue_depth: computed live at scrape time
        # (never push-updated), so it can never drift from the database.
        for state_name in APPROVAL_STATES:
            self.metrics.approval_queue_depth.labels(state=state_name).set_function(
                lambda s=state_name: count_by_state(self.db_engine, s)  # type: ignore[misc]
            )
        self.metrics.build_info.labels(version="0.1.0", commit="unknown").set(1)

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
            self.provider_status = "ok"
        elif self.settings.OLLAMA_PREFLIGHT_ENABLED:
            # SPEC.md §2.10 / DEP-003 (Phase 5): a startup preflight against
            # the host Ollama's `GET /api/tags`, run once here and cached —
            # see app/providers/ollama_preflight.py's module docstring for
            # why this isn't re-checked on every /readyz poll. A failed
            # preflight logs the actionable message DEP-003 requires and
            # marks /readyz not-ready (below); it never raises, so a
            # misconfigured or unreachable Ollama degrades readiness rather
            # than crashing the process — the dashboard and approval queue
            # stay reachable throughout.
            assert self.settings.UPSTREAM_BASE_URL is not None  # validated above
            result = check_ollama_preflight(
                self.settings.UPSTREAM_BASE_URL, self.settings.UPSTREAM_MODEL
            )
            self.provider_status = result.status
            if result.status == "ok":
                logger.info(result.message)
            else:
                logger.warning(result.message)
        else:
            self.provider_status = "not_configured"

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

        self.detectors = build_input_detectors(self.policy) if self.policy else []

        if self.policy is not None:
            self.metrics.policy_info.labels(
                policy_version=self.policy.policy_version,
                schema_version=str(self.policy.raw.get("schema_version", "unknown")),
            ).set(1)
            self.metrics.tool_allowlist = _tool_allowlist_from_policy(self.policy)

    @staticmethod
    def _build_provider(settings: Settings) -> Provider:
        """WS-06 (ADR 0005): mock mode stays the default (DEP-004/DEP-005 —
        unchanged from Phase 1); when UPSTREAM_BASE_URL is set, a real
        OpenAICompatibleProvider is built instead (this is also the Ollama
        profile's code path per SPEC.md §2.10 — Ollama is configuration, not
        separate code). SYS-013: in production, the configured URL is
        validated against SSRF rules *at startup*, so an unsafe upstream
        fails the process rather than the first request (CFG-002)."""
        if settings.mock_mode:
            return MockProvider()

        assert settings.UPSTREAM_BASE_URL is not None  # settings.mock_mode already excluded None
        if settings.APP_ENV.value == "production":
            try:
                validate_upstream_url_for_production(settings.UPSTREAM_BASE_URL)
            except SsrfValidationError as e:
                raise ConfigurationError(f"UPSTREAM_BASE_URL is unsafe (SYS-013): {e}") from e

        return OpenAICompatibleProvider(
            base_url=settings.UPSTREAM_BASE_URL,
            api_key=(
                settings.UPSTREAM_API_KEY.get_secret_value() if settings.UPSTREAM_API_KEY else None
            ),
            model=settings.UPSTREAM_MODEL,
            timeout_seconds=settings.REQUEST_TIMEOUT_SECONDS,
        )


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
    app.add_middleware(SecurityHeadersMiddleware, settings=state.settings)
    # Added last -> outermost in Starlette's stack, so it times the whole
    # request (every other middleware's overhead included), matching what a
    # real client would perceive as `realguard_http_request_duration_seconds`.
    app.add_middleware(HttpMetricsMiddleware, metrics=state.metrics)

    register_exception_handlers(app)
    register_routes(app)
    register_dashboard_routes(app)
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """SEC-008. Applied to every response, system-wide, not scoped to
    `/dashboard*` alone.

    SPEC.md §11.4 states SEC-008 without a "for the dashboard" qualifier
    (contrast §2.19, which *does* scope its own three prohibitions
    explicitly to the dashboard component) — read as written, SEC-008 is a
    system-wide requirement, and PLAN.md principle 8 ("fail-safe production
    defaults... unsafe configuration fails at startup, not at request
    time") tie-breaks toward the broader, safer reading wherever SPEC.md is
    ambiguous. Applying it as global middleware also means it literally
    cannot be forgotten on a future route the way a per-router opt-in could
    be. The JSON API surface gains these headers as a harmless side effect
    (a JSON response was never at risk of being framed or MIME-sniffed as
    HTML, but there is no cost to sending the header anyway).
    """

    def __init__(self, app: Any, *, settings: Settings) -> None:
        super().__init__(app)
        self._is_production = settings.APP_ENV.value == "production"

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # SEC-008: `default-src 'self'`, no `unsafe-inline` — every template
        # in app/templates/dashboard/ loads CSS/JS from same-origin
        # /dashboard/static/ files only (app/dashboard.py, ADR 0006); no
        # inline <script> or <style> exists anywhere in this codebase.
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        if self._is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


class HttpMetricsMiddleware(BaseHTTPMiddleware):
    """OBS-001/OBS-012 (Phase 6, WS-12): `realguard_http_requests_total` and
    `realguard_http_request_duration_seconds`. `endpoint` is always the
    matched route's *template* (`request.scope["route"].path_format`, set
    by Starlette's router before this middleware's `call_next()` returns —
    a `BaseHTTPMiddleware` sees the same mutable `scope` dict the router
    populated), never the raw resolved path; an unmatched route (a genuine
    404) is labelled `"unmatched"` rather than leaking an arbitrary
    caller-supplied path into a metric label."""

    def __init__(self, app: Any, *, metrics: Metrics) -> None:
        super().__init__(app)
        self._metrics = metrics

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        t0 = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - t0

        route = request.scope.get("route")
        endpoint = getattr(route, "path_format", None)
        if endpoint not in ENDPOINT_TEMPLATES:
            endpoint = "unmatched"

        status_class = f"{response.status_code // 100}xx"
        self._metrics.http_requests_total.labels(
            endpoint=endpoint, method=request.method, status_class=status_class
        ).inc()
        self._metrics.http_request_duration_seconds.labels(endpoint=endpoint).observe(duration)
        return response


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
        state: AppState = app.state.rg
        state.metrics.errors_total.labels(error_code=exc.code.value).inc()
        response = JSONResponse(status_code=exc.status, content=exc.to_envelope(txn_id))
        # ERR-007: "Retryable, after Retry-After" — set whenever the raiser
        # supplied one (app/ratelimit.py, via app/main.py's rate-limit check).
        retry_after = exc.details.get("retry_after_seconds")
        if retry_after is not None:
            response.headers["Retry-After"] = str(retry_after)
        return response

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # ERR-002 INVALID_REQUEST. ERR-022: no request content in the body —
        # Pydantic's error `loc`/`msg` are structural (field paths and
        # constraint names), not content, so they're safe to return.
        txn_id = new_transaction_id()
        state: AppState = app.state.rg
        state.metrics.errors_total.labels(error_code=ErrorCode.INVALID_REQUEST.value).inc()
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
        state: AppState = app.state.rg
        state.metrics.errors_total.labels(error_code=ErrorCode.INTERNAL_ERROR.value).inc()
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


_RISK_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _max_risk_level(a: str, b: str) -> str:
    """The worse of two risk_levels — used to combine the input pipeline's
    assessment with the output guard's (ADR 0005): a request that scores
    NONE on input but CRITICAL on egress must report CRITICAL overall."""
    return a if _RISK_RANK[a] >= _RISK_RANK[b] else b


def _confidence_for_reason_codes(
    findings: tuple[Finding, ...], reason_codes: tuple[str, ...]
) -> list[FindingSummary]:
    """API-009: the DENY response's findings_summary carries detector
    identity, category and confidence only — never evidence text. One
    summary entry per distinct (detector_id, category) pair among the
    findings that actually contributed to the winning verdict."""
    seen: set[tuple[str, str]] = set()
    summaries: list[FindingSummary] = []
    for f in findings:
        if f.category.value not in reason_codes:
            continue
        key = (f.detector_id, f.category.value)
        if key in seen:
            continue
        seen.add(key)
        summaries.append(
            FindingSummary(
                detector_id=f.detector_id, category=f.category.value, confidence=f.confidence.value
            )
        )
    return summaries


def _apply_transformation_or_deny(
    messages: list[dict[str, Any]], transformation: str
) -> list[dict[str, Any]]:
    """TRN-007: fail closed — DENY with TRANSFORMATION_FAILED — rather than
    forward partially-transformed content. Shared by the ALLOW and
    NEED_APPROVAL branches (ADR 0004): the approval's `transformed_payload`
    must be produced by exactly the same code the ALLOW path uses, or the
    two could silently diverge."""
    try:
        return apply_transformation_to_messages(messages, transformation)
    except TransformationError as e:
        raise FirewallError(
            ErrorCode.POLICY_DENIED,
            "A required content transformation could not be applied.",
            status=403,
            details={"reason_codes": ["TRANSFORMATION_FAILED"]},
        ) from e


def _degraded_reason(findings: tuple[Finding, ...]) -> str:
    """OBS-012-bounded `reason` label for `realguard_degraded_transactions_total`
    — one of exactly two values, never a raw exception message. A
    `DETECTOR_TIMEOUT` finding means at least one detector missed its
    deadline (POL-007); any other degraded case is a detector that raised
    (app/orchestrator.py's `_run_one()` isolates either without aborting the
    rest)."""
    if any(f.category == Category.DETECTOR_TIMEOUT for f in findings):
        return "detector_timeout"
    return "detector_error"


def _audit_decision(
    state: AppState,
    *,
    transaction_id: str,
    correlation_id: str,
    identity_id: str,
    verdict: str,
    risk_level: str,
    transformation: str,
    reason_codes: tuple[str, ...],
    policy_hits: tuple[str, ...],
    policy_version: str,
    mode: str,
    degraded: bool,
) -> None:
    """PRV-009: exactly one `event_type="decision"` audit event per
    transaction, for every verdict. §2.15: "an audit write failure MUST
    fail the transaction closed when APP_ENV=production. Evidence is not
    optional." — in any other environment, a write failure is logged and
    the response still goes out, so a database hiccup in development never
    blocks a request over an evidence write it can't yet make durable."""
    try:
        record_decision_event(
            state.db_engine,
            transaction_id=transaction_id,
            correlation_id=correlation_id,
            actor_id=identity_id,
            verdict=verdict,
            risk_level=risk_level,
            transformation=transformation,
            reason_codes=list(reason_codes),
            policy_hits=list(policy_hits),
            policy_version=policy_version,
            mode=mode,
            degraded=degraded,
        )
    except Exception:  # noqa: BLE001 — see §2.15 handling below
        if state.settings.APP_ENV.value == "production":
            raise FirewallError(ErrorCode.DATABASE_ERROR, "The audit log is unavailable.") from None
        logger.warning(
            "audit event write failed — continuing (non-production)",
            extra={"transaction_id": transaction_id},
        )


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

        # Phase 6 (WS-13): identity resolved up front — every branch below
        # needs it now (the rate limiter scopes by it; NEED_APPROVAL needed
        # it already, just later). SEC-009: only the presented key/session
        # is ever authoritative for it.
        identity = resolve_identity(request.headers.get("Authorization"), state.settings)

        # WS-13: rate limiting runs before any detection work — a "blunt
        # cost and abuse" control that should reject a request before this
        # system spends any CPU inspecting it, not after. §2.17: never
        # applied to GET /healthz, GET /readyz, or the approval-decision
        # endpoint — trivially satisfied, since this check exists in no
        # other handler.
        rate_limit_config = rate_limit_config_from_policy(
            state.policy,
            default_requests=state.settings.RATE_LIMIT_REQUESTS,
            default_window_seconds=state.settings.RATE_LIMIT_WINDOW_SECONDS,
        )
        try:
            rate_result = check_rate_limit(
                state.db_engine, identity_id=identity.identity_id, config=rate_limit_config
            )
        except Exception:  # noqa: BLE001 — §2.17 fail-open/closed handling below
            # §2.17: "a limiter backend failure fails open in development
            # and closed in production."
            if state.settings.APP_ENV.value == "production":
                raise FirewallError(
                    ErrorCode.DATABASE_ERROR, "The rate limiter is unavailable."
                ) from None
            logger.warning("rate limiter backend failure — failing open (development)")
            rate_result = None

        if rate_result is not None and not rate_result.allowed:
            state.metrics.rate_limited_total.labels(scope=rate_limit_config.scope).inc()
            raise FirewallError(
                ErrorCode.RATE_LIMITED,
                "Rate limit exceeded for this identity.",
                details={"retry_after_seconds": rate_result.retry_after_seconds},
            )

        # POL-009: no cached policy and none loaded at boot -> 503, never a
        # silent allow.
        if state.policy is None:
            raise FirewallError(
                ErrorCode.POLICY_UNAVAILABLE,
                "The policy engine is unavailable and no cached policy exists.",
            )
        policy_version = state.policy.policy_version

        t_detect0 = time.perf_counter()
        result = await run_input_pipeline(
            body["messages"],
            state.policy,
            state.detectors,
            salt=state.settings.effective_hash_salt(),
            detector_timeout_ms=state.settings.DETECTOR_TIMEOUT_MS,
            tools=body.get("tools"),
            metrics=state.metrics,
        )
        detection_ms = (time.perf_counter() - t_detect0) * 1000
        decision = result.decision

        # Instrumentation common to every verdict (OBS-001..003, OBS-012):
        # recorded once here rather than duplicated in each branch below.
        state.metrics.decisions_total.labels(
            verdict=decision.verdict, plane="input", mode=mode
        ).inc()
        state.metrics.risk_level_total.labels(level=result.risk.risk_level.value).inc()
        for h in decision.policy_hits:
            state.metrics.policy_hits_total.labels(rule_id=h.rule_id).inc()
        for rc in decision.reason_codes:
            state.metrics.reason_codes_total.labels(reason_code=rc).inc()
        if decision.degraded:
            state.metrics.degraded_transactions_total.labels(
                reason=_degraded_reason(result.findings)
            ).inc()
        state.metrics.firewall_added_seconds.labels(plane="input").observe(detection_ms / 1000)

        if decision.verdict == "DENY":
            state.metrics.upstream_calls_avoided_total.labels(verdict="DENY").inc()
            _audit_decision(
                state,
                transaction_id=txn_id,
                correlation_id=request.state.correlation_id,
                identity_id=identity.identity_id,
                verdict=decision.verdict,
                risk_level=result.risk.risk_level.value,
                transformation=decision.transformation,
                reason_codes=decision.reason_codes,
                policy_hits=tuple(h.rule_id for h in decision.policy_hits),
                policy_version=policy_version,
                mode=mode,
                degraded=decision.degraded,
            )
            denied = DeniedResponse(
                risk_level=result.risk.risk_level.value,
                reason_codes=list(decision.reason_codes),
                policy_hits=[h.rule_id for h in decision.policy_hits if h.verdict == "DENY"],
                transaction_id=txn_id,
                message="Request blocked by policy.",
                firewall=DeniedFirewallMetadata(
                    policy_version=policy_version,
                    degraded=decision.degraded,
                    mode=mode,
                    findings_summary=_confidence_for_reason_codes(
                        result.findings, decision.reason_codes
                    ),
                ),
            )
            response = JSONResponse(status_code=403, content=denied.model_dump())
            response.headers["X-RealGuard-Transaction-Id"] = txn_id
            response.headers["X-RealGuard-Mode"] = mode
            return response

        if decision.verdict == "NEED_APPROVAL":
            # ADR 0004: real persistence, not a refusal stub. APR-005: the
            # approval row is committed *before* this handler returns 202.
            # (`identity` was already resolved above, Phase 6 — WS-13 needed
            # it before this branch existed to reach it.)
            t_transform0 = time.perf_counter()
            transformed_messages = _apply_transformation_or_deny(
                body["messages"], decision.transformation
            )
            state.metrics.transformation_duration_seconds.labels(
                transformation=decision.transformation
            ).observe(time.perf_counter() - t_transform0)
            if decision.transformation != "NONE":
                state.metrics.transformations_total.labels(
                    transformation=decision.transformation, plane="input"
                ).inc()
            request_id = new_id("req")
            transformed_payload = {**body, "messages": transformed_messages}
            material_args_hash = compute_material_args_hash(transformed_messages, body.get("tools"))
            retain_raw = state.settings.CONTENT_RETENTION.value in ("full", "encrypted")
            need_approval_policy_hits = [
                h.rule_id for h in decision.policy_hits if h.verdict == "NEED_APPROVAL"
            ]
            creation = create_approval(
                state.db_engine,
                transaction_id=txn_id,
                request_id=request_id,
                correlation_id=request.state.correlation_id,
                creator_identity_id=identity.identity_id,
                mode=mode,
                risk_level=result.risk.risk_level.value,
                reason_codes=list(decision.reason_codes),
                policy_hits=need_approval_policy_hits,
                transformation=decision.transformation,
                policy_version=policy_version,
                preview_content={"messages": transformed_messages},
                transformed_payload=transformed_payload,
                material_args_hash=material_args_hash,
                ttl_seconds=state.settings.APPROVAL_TTL_SECONDS,
                retain_raw_content=retain_raw,
                raw_request_content=body if retain_raw else None,
                metrics=state.metrics,
            )
            approval = creation.approval
            _audit_decision(
                state,
                transaction_id=txn_id,
                correlation_id=request.state.correlation_id,
                identity_id=identity.identity_id,
                verdict=decision.verdict,
                risk_level=result.risk.risk_level.value,
                transformation=decision.transformation,
                reason_codes=decision.reason_codes,
                policy_hits=tuple(need_approval_policy_hits),
                policy_version=policy_version,
                mode=mode,
                degraded=decision.degraded,
            )
            need_approval = NeedApprovalResponse(
                risk_level=result.risk.risk_level.value,
                reason_codes=list(decision.reason_codes),
                policy_hits=need_approval_policy_hits,
                transformation=decision.transformation,
                transaction_id=txn_id,
                request_id=request_id,
                approval_id=approval.id,
                expires_at=_rfc3339(approval.expires_at),
                poll_url=f"/v1/firewall/requests/{request_id}",
                message="Held for human approval.",
            )
            response = JSONResponse(status_code=202, content=need_approval.model_dump())
            response.headers["X-RealGuard-Transaction-Id"] = txn_id
            response.headers["X-RealGuard-Mode"] = mode
            return response

        # ALLOW — apply REDACT (the only input-plane transformation; ADR
        # 0003) to each message's content before forwarding upstream.
        t_transform0 = time.perf_counter()
        forward_messages = _apply_transformation_or_deny(body["messages"], decision.transformation)
        state.metrics.transformation_duration_seconds.labels(
            transformation=decision.transformation
        ).observe(time.perf_counter() - t_transform0)
        if decision.transformation != "NONE":
            state.metrics.transformations_total.labels(
                transformation=decision.transformation, plane="input"
            ).inc()
        forward_body = {**body, "messages": forward_messages}

        t_upstream0 = time.perf_counter()
        try:
            upstream_response = await state.provider.complete(forward_body)
        except (UpstreamTimeoutError, UpstreamResponseError) as e:
            # TST-016 (SPEC.md §16 ERR-013/014/015): this handler does not
            # yet map these to the documented error codes/status — a
            # pre-existing gap this phase's scope (WS-12/13/17) does not
            # extend to fixing (see docs/adr/0008). Real instrumentation
            # regardless: the error still surfaces (via the generic
            # exception handler, unchanged), but is now counted first.
            kind = "timeout" if isinstance(e, UpstreamTimeoutError) else "response_error"
            state.metrics.upstream_errors_total.labels(
                provider=state.provider.name, kind=kind
            ).inc()
            raise
        upstream_ms = (time.perf_counter() - t_upstream0) * 1000
        state.metrics.upstream_duration_seconds.labels(provider=state.provider.name).observe(
            upstream_ms / 1000
        )

        # SYS-006/SYS-014 (ADR 0005): the output guard runs on every ALLOW
        # response before it is ever serialized to the client — the only
        # other route to a response body in this handler is the DENY/
        # NEED_APPROVAL branches above, neither of which calls the upstream
        # provider at all (SYS-002/APR-002), so no return statement in this
        # handler bypasses the output guard for content that actually came
        # from a model.
        response_content = ""
        response_choices = upstream_response.get("choices") or []
        if response_choices and isinstance(response_choices[0], dict):
            response_message = response_choices[0].get("message")
            if isinstance(response_message, dict):
                response_content = response_message.get("content") or ""

        t_output0 = time.perf_counter()
        guard_result = await run_output_guard(
            response_content,
            system_prompt_text_from_messages(forward_messages),
            state.policy,
            salt=state.settings.effective_hash_salt(),
            detector_timeout_ms=state.settings.DETECTOR_TIMEOUT_MS,
            upstream_response=upstream_response,
            metrics=state.metrics,
        )
        output_guard_ms = (time.perf_counter() - t_output0) * 1000
        state.metrics.firewall_added_seconds.labels(plane="response").observe(
            output_guard_ms / 1000
        )
        for h in guard_result.decision.policy_hits:
            state.metrics.policy_hits_total.labels(rule_id=h.rule_id).inc()
        for rc in guard_result.decision.reason_codes:
            state.metrics.reason_codes_total.labels(reason_code=rc).inc()
        if guard_result.decision.transformation != "NONE":
            state.metrics.transformations_total.labels(
                transformation=guard_result.decision.transformation, plane="response"
            ).inc()

        # ADR 0005: combine_decisions() (originally built to merge several
        # per-tool-candidate Decisions, app/pipeline.py) applies unchanged
        # to merging the input-plane decision with the output guard's —
        # same POL-002 precedence, same "union evidence, don't discard it"
        # rule either way.
        overall_decision = combine_decisions((decision, guard_result.decision))
        overall_findings = result.findings + guard_result.findings
        overall_risk_level = _max_risk_level(
            result.risk.risk_level.value, guard_result.risk.risk_level.value
        )
        state.metrics.decisions_total.labels(
            verdict=overall_decision.verdict, plane="response", mode=mode
        ).inc()
        state.metrics.risk_level_total.labels(level=overall_risk_level).inc()
        if overall_decision.degraded and not decision.degraded:
            # Only count once: if the input plane was already degraded, the
            # transaction-level increment already happened above.
            state.metrics.degraded_transactions_total.labels(
                reason=_degraded_reason(overall_findings)
            ).inc()

        if overall_decision.verdict == "DENY":
            # SPEC.md §3.7/§2.11: the upstream call already happened, but a
            # response-plane DENY must still deny — the offending content is
            # discarded here and never reaches the client (API-009 applies
            # to output leaks exactly as it does to input ones). See the ADR
            # for why this is the conservative, deliberately-chosen behaviour
            # rather than silently downgrading to ALLOW because "the model
            # already answered."
            _audit_decision(
                state,
                transaction_id=txn_id,
                correlation_id=request.state.correlation_id,
                identity_id=identity.identity_id,
                verdict=overall_decision.verdict,
                risk_level=overall_risk_level,
                transformation=overall_decision.transformation,
                reason_codes=overall_decision.reason_codes,
                policy_hits=tuple(h.rule_id for h in overall_decision.policy_hits),
                policy_version=policy_version,
                mode=mode,
                degraded=overall_decision.degraded,
            )
            denied = DeniedResponse(
                risk_level=overall_risk_level,
                reason_codes=list(overall_decision.reason_codes),
                policy_hits=[
                    h.rule_id for h in overall_decision.policy_hits if h.verdict == "DENY"
                ],
                transaction_id=txn_id,
                message="Response blocked by policy.",
                firewall=DeniedFirewallMetadata(
                    policy_version=policy_version,
                    degraded=overall_decision.degraded,
                    mode=mode,
                    findings_summary=_confidence_for_reason_codes(
                        overall_findings, overall_decision.reason_codes
                    ),
                ),
            )
            response = JSONResponse(status_code=403, content=denied.model_dump())
            response.headers["X-RealGuard-Transaction-Id"] = txn_id
            response.headers["X-RealGuard-Mode"] = mode
            return response

        # ALLOW (optionally REDACT-transformed by either plane): splice the
        # output guard's sanitized content back into the response before it
        # is ever serialized.
        final_choices = list(upstream_response["choices"])
        if final_choices and isinstance(final_choices[0], dict):
            final_message = final_choices[0].get("message")
            if isinstance(final_message, dict) and "content" in final_message:
                final_choices[0] = {
                    **final_choices[0],
                    "message": {**final_message, "content": guard_result.sanitized_content},
                }

        _audit_decision(
            state,
            transaction_id=txn_id,
            correlation_id=request.state.correlation_id,
            identity_id=identity.identity_id,
            verdict=overall_decision.verdict,
            risk_level=overall_risk_level,
            transformation=overall_decision.transformation,
            reason_codes=overall_decision.reason_codes,
            policy_hits=tuple(h.rule_id for h in overall_decision.policy_hits),
            policy_version=policy_version,
            mode=mode,
            degraded=overall_decision.degraded,
        )

        # ADR 0002: the completion fields go at the TOP LEVEL (unpacked from
        # upstream_response), not nested under a `response` key — required
        # for the real openai SDK's ChatCompletion parsing to work unmodified.
        allowed = AllowedResponse(
            id=upstream_response["id"],
            object=upstream_response["object"],
            created=upstream_response["created"],
            model=upstream_response["model"],
            choices=final_choices,
            usage=upstream_response["usage"],
            firewall=FirewallMetadata(
                transaction_id=txn_id,
                transformation=overall_decision.transformation,
                risk_level=overall_risk_level,
                reason_codes=list(overall_decision.reason_codes),
                policy_hits=[
                    h.rule_id for h in overall_decision.policy_hits if h.verdict == "ALLOW"
                ],
                policy_version=policy_version,
                degraded=overall_decision.degraded,
                mode=mode,
                timings_ms={
                    "detection": detection_ms,
                    "policy": 0.0,  # folded into detection_ms; not separated yet
                    "upstream": upstream_ms,
                    "output_guard": output_guard_ms,
                    "firewall_added": detection_ms + output_guard_ms,
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
        # DEP-003: a failed Ollama preflight (state.provider_status ==
        # "unreachable") must mark /readyz not-ready — folded into `ready`
        # below alongside the pre-existing policy/database checks.
        provider_status: Any = state.provider_status

        database_status: Any
        try:
            with state.db_engine.connect() as conn:
                conn.exec_driver_sql("SELECT 1")
            database_status = "ok"
        except Exception:  # noqa: BLE001 — readiness probe: report, never raise
            database_status = "unreachable"

        ready = (
            state.policy is not None
            and database_status == "ok"
            and provider_status != "unreachable"
        )
        if not ready:
            response.status_code = 503

        return ReadyzResponse(
            ready=ready,
            mode=mode,
            dependencies=ReadyzDependencies(
                database=database_status,
                policy=policy_status,
                provider=provider_status,
            ),
        )

    @app.get("/metrics")
    async def metrics_endpoint(request: Request) -> Response:
        """SPEC.md §2.16, §4.7, OBS-001, API-017. Prometheus text
        exposition. API-017: "MAY require a service key when
        METRICS_REQUIRE_AUTH=true, which MUST default to true in
        production" (`app/config.py` already fails startup if production
        leaves it false). When `False` (the non-production default), the
        endpoint is open — no identity check at all, regardless of whether
        keys happen to be configured, matching the setting's own literal
        wording ("MAY require... when METRICS_REQUIRE_AUTH=true"). When
        `True`, any recognized key of *either* class is accepted:
        SPEC.md §11.1's table explicitly lists `/metrics` under Service's
        allowed endpoints and leaves Reviewer's "may NOT call" column empty
        for it — read permissively rather than inventing an undocumented
        restriction (see docs/adr/0008)."""
        state: AppState = app.state.rg
        if state.settings.METRICS_REQUIRE_AUTH:
            resolve_identity(request.headers.get("Authorization"), state.settings)
        return PlainTextResponse(
            generate_latest(state.metrics.registry).decode("utf-8"),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/v1/firewall/requests/{transaction_or_request_id}")
    async def get_transaction_status(transaction_or_request_id: str, request: Request) -> Response:
        """SPEC.md §4.5. API-011: a cross-identity read returns 404, not
        403, so the endpoint never confirms another identity's transaction
        exists."""
        state: AppState = app.state.rg
        identity = resolve_identity(request.headers.get("Authorization"), state.settings)
        sweep_expired(state.db_engine, metrics=state.metrics)

        txn = get_transaction(state.db_engine, transaction_or_request_id)
        if txn is None or (
            identity.identity_class != IdentityClass.REVIEWER
            and txn.identity_id != identity.identity_id
        ):
            raise FirewallError(ErrorCode.TRANSACTION_NOT_FOUND, "Unknown transaction.")

        body: dict[str, Any] = {"transaction_id": txn.id, "status": txn.status}
        if txn.status == "COMPLETED":
            body["decision"] = txn.final_verdict
            approval = get_approval_by_transaction(state.db_engine, txn.id)
            if approval is not None:
                body["response"] = approval.completion_result
        payload = TransactionStatusResponse.model_validate(body).model_dump(exclude_none=True)
        response = JSONResponse(status_code=200, content=payload)
        response.headers["X-RealGuard-Transaction-Id"] = txn.id
        response.headers["X-RealGuard-Mode"] = txn.mode
        return response

    @app.get("/v1/firewall/approvals")
    async def list_pending_approvals(
        request: Request,
        status: list[str] | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ApprovalListResponse:
        """SPEC.md §4.4. API-010: reviewer-only, transformed preview only."""
        state: AppState = app.state.rg
        identity = resolve_identity(request.headers.get("Authorization"), state.settings)
        require_reviewer(identity)
        sweep_expired(state.db_engine, metrics=state.metrics)

        limit = max(1, min(limit, 200))
        rows, next_cursor = list_approvals(
            state.db_engine, statuses=status, limit=limit, cursor=cursor
        )
        items = [
            ApprovalPreview(
                approval_id=r.id,
                transaction_id=r.transaction_id,
                status=r.state,
                risk_level=r.risk_level,
                reason_codes=r.reason_codes,
                policy_hits=r.policy_hits,
                preview=r.preview_content,
                created_at=_rfc3339(r.created_at),
                expires_at=_rfc3339(r.expires_at),
            )
            for r in rows
        ]
        return ApprovalListResponse(items=items, next_cursor=next_cursor)

    @app.post("/v1/firewall/approvals/{approval_id}/decision")
    async def decide_approval_endpoint(
        approval_id: str, request: Request, body: ApprovalDecisionRequest
    ) -> Response:
        """SPEC.md §4.6. API-012: reviewer-only, Idempotency-Key required,
        non-empty note required for DENY, self-approval forbidden (APR-009),
        replay/conflict handling (APR-010).

        Phase 4 (ADR 0006): identity resolution now accepts either of
        SPEC.md §4.6's two named auth routes — `Authorization: Bearer
        <reviewer key>`, or a valid session cookie plus `X-CSRF-Token`
        (SEC-005/SEC-007) — via `resolve_decision_identity()`, which raises
        `CSRF_TOKEN_INVALID` (403) for a missing/mismatched token on the
        cookie route. In *practice* a real browser never presents this
        endpoint with the SEC-005 cookie automatically, because that
        cookie's `Path=/dashboard` scope means it is only ever attached to
        requests under `/dashboard` — this endpoint's cookie support exists
        for literal SPEC.md §4.6 fidelity and for any client that presents
        the cookie value explicitly (not from a browser's automatic cookie
        jar). The dashboard's own approve/deny buttons instead call
        `POST /dashboard/approvals/{id}/decide` (app/dashboard.py), which
        the session cookie *does* reach — see docs/adr/0006 for the full
        reasoning and the concrete proof (a curl-cookie-jar Path test) that
        led to that split.
        """
        state: AppState = app.state.rg
        identity = resolve_decision_identity(
            authorization_header=request.headers.get("Authorization"),
            session_cookie=request.cookies.get(SESSION_COOKIE_NAME),
            csrf_header=request.headers.get("X-CSRF-Token"),
            settings=state.settings,
        )
        require_reviewer(identity)

        idempotency_key = request.headers.get("Idempotency-Key")
        if not idempotency_key:
            raise FirewallError(
                ErrorCode.INVALID_REQUEST,
                "The Idempotency-Key header is required for this endpoint (API-007).",
            )

        result = await decide_and_resume(
            state.db_engine,
            approval_id,
            decision=body.decision,
            note=body.note,
            reviewer_identity=identity,
            idempotency_key=idempotency_key,
            correlation_id=getattr(request.state, "correlation_id", approval_id),
            provider=state.provider,
            policy=state.policy,
            salt=state.settings.effective_hash_salt(),
            detector_timeout_ms=state.settings.DETECTOR_TIMEOUT_MS,
            retain_response_content=state.settings.CONTENT_RETENTION.value in ("full", "encrypted"),
            metrics=state.metrics,
        )

        payload = ApprovalDecisionResponse(
            approval_id=approval_id,
            status=result.final_approval.state,
            decided_at=_rfc3339(result.decision_row.created_at),
        )
        return JSONResponse(status_code=200, content=payload.model_dump())


try:
    app = create_app()
except ConfigurationError as e:
    # SEC-004 / CFG-002: configuration failures are startup failures, not
    # request-time ones. Fail loudly and refuse to serve anything.
    raise SystemExit(f"real-guard-v1: invalid configuration, refusing to start:\n{e}") from e
