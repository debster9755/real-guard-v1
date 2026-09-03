"""Wire-level Pydantic models. Mirrors openapi.json's components/schemas —
SPEC.md §4. Kept intentionally permissive on ChatCompletionRequest
(API-013: unknown fields are forwarded to the upstream unchanged).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["ALLOW", "DENY", "NEED_APPROVAL"]
Transformation = Literal["NONE", "REDACT", "MASK", "SANITIZE", "REWRITE", "TRUNCATE"]
RiskLevel = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None


class ChatCompletionRequest(BaseModel):
    """API-013: extra="allow" — unknown fields are forwarded upstream
    unchanged rather than rejected."""

    model_config = ConfigDict(extra="allow")

    messages: list[ChatMessage] = Field(min_length=1)
    model: str | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: Any = None
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    stop: Any = None
    n: int | None = None
    seed: int | None = None
    user: str | None = None
    stream: bool | None = None


class TimingsMs(BaseModel):
    detection: float = 0.0
    policy: float = 0.0
    upstream: float = 0.0
    output_guard: float = 0.0
    firewall_added: float = 0.0


class FirewallMetadata(BaseModel):
    """ADR 0002: carried as one top-level `firewall` field on AllowedResponse,
    never wrapping the OpenAI completion fields."""

    decision: Literal["ALLOW"] = "ALLOW"
    transformation: Transformation = "NONE"
    transaction_id: str
    risk_level: RiskLevel = "NONE"
    reason_codes: list[str] = Field(default_factory=list)
    policy_hits: list[str] = Field(default_factory=list)
    policy_version: str
    degraded: bool = False
    mode: Literal["mock", "live"]
    timings_ms: TimingsMs = Field(default_factory=TimingsMs)


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class AllowedResponse(BaseModel):
    """ADR 0002: the OpenAI chat-completion object AT THE TOP LEVEL — id,
    object, created, model, choices, usage — plus one additional `firewall`
    metadata field. MUST NOT nest the completion under a `response` field;
    that broke the real `openai` SDK's ChatCompletion parsing (verified
    empirically against openai-python during Phase 1's end-to-end smoke
    test, not merely asserted)."""

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: Usage
    firewall: FirewallMetadata


class FindingSummary(BaseModel):
    """API-009: identity, category and confidence only — never evidence text."""

    detector_id: str
    category: str
    confidence: Literal["LOW", "MEDIUM", "HIGH"]


class DeniedFirewallMetadata(BaseModel):
    policy_version: str
    degraded: bool = False
    mode: Literal["mock", "live"]
    findings_summary: list[FindingSummary] = Field(default_factory=list)


class DeniedResponse(BaseModel):
    decision: Literal["DENY"] = "DENY"
    risk_level: RiskLevel
    reason_codes: list[str]
    policy_hits: list[str]
    transformation: Literal["NONE"] = "NONE"
    transaction_id: str
    message: str
    firewall: DeniedFirewallMetadata


class NeedApprovalResponse(BaseModel):
    decision: Literal["NEED_APPROVAL"] = "NEED_APPROVAL"
    risk_level: RiskLevel
    reason_codes: list[str]
    policy_hits: list[str]
    transformation: Transformation
    transaction_id: str
    request_id: str
    approval_id: str
    status: Literal["PENDING"] = "PENDING"
    expires_at: str
    poll_url: str
    message: str


class ApprovalDecisionRequest(BaseModel):
    """SPEC.md §4.6. API-012: `note` is required (non-empty) when
    `decision` is DENY — enforced in app/approvals.py, not here, since the
    rule is conditional on the field's own value."""

    decision: Literal["APPROVE", "DENY"]
    note: str | None = None
    reviewer_id: str | None = None


class ApprovalDecisionResponse(BaseModel):
    approval_id: str
    status: str
    decided_at: str


class ApprovalPreview(BaseModel):
    """API-010, APR-012: `preview` carries transformed content only."""

    approval_id: str
    transaction_id: str
    status: str
    risk_level: RiskLevel
    reason_codes: list[str]
    policy_hits: list[str]
    preview: dict[str, Any]
    created_at: str
    expires_at: str


class ApprovalListResponse(BaseModel):
    items: list[ApprovalPreview]
    next_cursor: str | None = None


class TransactionStatusResponse(BaseModel):
    transaction_id: str
    status: str
    decision: Verdict | None = None
    response: dict[str, Any] | None = None


class ErrorDetail(BaseModel):
    code: str
    type: str
    message: str
    transaction_id: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorDetail


class HealthzResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ReadyzDependencies(BaseModel):
    database: Literal["ok", "unreachable", "not_configured"] = "not_configured"
    policy: Literal["ok", "invalid", "unavailable"]
    provider: Literal["ok", "unreachable", "not_configured"]


class ReadyzResponse(BaseModel):
    ready: bool
    mode: Literal["mock", "live"]
    dependencies: ReadyzDependencies
