"""Prometheus metrics. SPEC.md §2.16, §13 (OBS-001..005, OBS-012).
Phase 6 (PLAN.md WS-12) — see
docs/adr/0008-phase6-rate-limiting-metrics-and-security-scanning.md.

Every metric name, type and label set below is copied verbatim from
SPEC.md §13.1's catalogue table — nothing here is invented. `Metrics` is
built once per `AppState`, bound to a fresh `CollectorRegistry` (never the
global default registry): tests construct many `AppState`s in one process
(`tests/conftest.py`'s `client_factory`), and re-registering the same
metric name against the process-wide default registry twice raises
`ValueError: Duplicated timeseries`. A registry-per-app is also the
correct real-world shape for this MVP — one process, one `/metrics`
endpoint, one set of counters for its own lifetime.

OBS-012 (cardinality): every label used below is drawn from a small,
enumerable set fixed at either compile time (verdict/plane/mode/state/
outcome/transformation/risk level/error code) or policy-load time
(`rule_id`, `detector_id` — bounded by the loaded policy's own rule/detector
count, itself small and operator-controlled). `endpoint` is always a route
*template* string (`ENDPOINT_TEMPLATES` below), never a resolved path.
`tool_name` is bounded to the policy's tool allowlist plus the literal
`"other"` (`bounded_tool_name()`). No metric ever carries `transaction_id`,
`identity_id`, `correlation_id`, user content, or a model-supplied string as
a label — `tests/test_metrics.py::test_cardinality_...` asserts the exact
label set of every metric registered here, directly against this module's
own `METRIC_LABELS` table, so a future edit that adds an unbounded label
fails that test rather than silently shipping.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

# OBS-012: `endpoint` is the route *template*, never a resolved path. This is
# the complete, fixed set of routes this app ever registers (app/main.py,
# app/dashboard.py) — a request that matches none of them (a genuine 404)
# is labelled "unmatched" rather than leaking the raw requested path.
ENDPOINT_TEMPLATES: tuple[str, ...] = (
    "/v1/chat/completions",
    "/v1/firewall/approvals",
    "/v1/firewall/approvals/{approval_id}/decision",
    "/v1/firewall/requests/{transaction_or_request_id}",
    "/healthz",
    "/readyz",
    "/metrics",
    "/dashboard",
    "unmatched",
)

# Mirrors policies/default_policy.yaml's `agent_tool_allowlist` rule
# (`tool_not_in: [...]`) — the same bounded vocabulary
# app/detectors/tool_calls.py already reads out of the loaded policy.
# Falls back to this literal list if a policy without that rule is loaded
# (POL-009 degraded mode has no policy at all, so no tool metric fires then).
_DEFAULT_TOOL_ALLOWLIST = frozenset(
    {"search_docs", "get_weather", "lookup_order", "wire_transfer", "run_sql", "send_email"}
)


def bounded_tool_name(tool_name: str, allowlist: frozenset[str]) -> str:
    """OBS-012: `tool_name` MUST be bounded to the allowlist plus `"other"` —
    never an arbitrary model- or caller-supplied string."""
    return tool_name if tool_name in allowlist else "other"


# The exact label set SPEC.md §13.1 declares for each metric — the single
# source of truth `tests/test_metrics.py`'s cardinality test compares the
# live registry against.
METRIC_LABELS: dict[str, tuple[str, ...]] = {
    "realguard_http_requests_total": ("endpoint", "method", "status_class"),
    "realguard_http_request_duration_seconds": ("endpoint",),
    "realguard_decisions_total": ("verdict", "plane", "mode"),
    "realguard_risk_level_total": ("level",),
    "realguard_policy_hits_total": ("rule_id",),
    "realguard_reason_codes_total": ("reason_code",),
    "realguard_detector_duration_seconds": ("detector_id",),
    "realguard_detector_failures_total": ("detector_id", "reason"),
    "realguard_policy_duration_seconds": (),
    "realguard_transformation_duration_seconds": ("transformation",),
    "realguard_transformations_total": ("transformation", "plane"),
    "realguard_upstream_duration_seconds": ("provider",),
    "realguard_upstream_errors_total": ("provider", "kind"),
    "realguard_upstream_calls_avoided_total": ("verdict",),
    "realguard_firewall_added_seconds": ("plane",),
    "realguard_output_decisions_total": ("verdict",),
    "realguard_approvals_total": ("state",),
    "realguard_approval_queue_depth": ("state",),
    "realguard_approval_wait_seconds": (),
    "realguard_resume_total": ("outcome",),
    "realguard_rate_limited_total": ("scope",),
    "realguard_degraded_transactions_total": ("reason",),
    "realguard_errors_total": ("error_code",),
    "realguard_tool_findings_total": ("tool_name", "category"),
    "realguard_policy_info": ("policy_version", "schema_version"),
    "realguard_build_info": ("version", "commit"),
}


@dataclass
class Metrics:
    registry: CollectorRegistry
    tool_allowlist: frozenset[str]

    http_requests_total: Counter
    http_request_duration_seconds: Histogram
    decisions_total: Counter
    risk_level_total: Counter
    policy_hits_total: Counter
    reason_codes_total: Counter
    detector_duration_seconds: Histogram
    detector_failures_total: Counter
    policy_duration_seconds: Histogram
    transformation_duration_seconds: Histogram
    transformations_total: Counter
    upstream_duration_seconds: Histogram
    upstream_errors_total: Counter
    upstream_calls_avoided_total: Counter
    firewall_added_seconds: Histogram
    output_decisions_total: Counter
    approvals_total: Counter
    approval_queue_depth: Gauge
    approval_wait_seconds: Histogram
    resume_total: Counter
    rate_limited_total: Counter
    degraded_transactions_total: Counter
    errors_total: Counter
    tool_findings_total: Counter
    policy_info: Gauge
    build_info: Gauge

    def bounded_tool_name(self, tool_name: str) -> str:
        return bounded_tool_name(tool_name, self.tool_allowlist)


def build_metrics(
    registry: CollectorRegistry, *, tool_allowlist: frozenset[str] | None = None
) -> Metrics:
    allowlist = tool_allowlist if tool_allowlist is not None else _DEFAULT_TOOL_ALLOWLIST

    def counter(name: str, doc: str) -> Counter:
        return Counter(name, doc, list(METRIC_LABELS[name]), registry=registry)

    def histogram(name: str, doc: str) -> Histogram:
        return Histogram(name, doc, list(METRIC_LABELS[name]), registry=registry)

    def gauge(name: str, doc: str) -> Gauge:
        return Gauge(name, doc, list(METRIC_LABELS[name]), registry=registry)

    return Metrics(
        registry=registry,
        tool_allowlist=allowlist,
        http_requests_total=counter(
            "realguard_http_requests_total", "Total HTTP requests by route template."
        ),
        http_request_duration_seconds=histogram(
            "realguard_http_request_duration_seconds", "HTTP request duration in seconds."
        ),
        decisions_total=counter(
            "realguard_decisions_total", "Total policy decisions by verdict/plane/mode."
        ),
        risk_level_total=counter("realguard_risk_level_total", "Total transactions by risk level."),
        policy_hits_total=counter(
            "realguard_policy_hits_total", "Total policy rule hits by rule_id."
        ),
        reason_codes_total=counter(
            "realguard_reason_codes_total", "Total occurrences by reason code."
        ),
        detector_duration_seconds=histogram(
            "realguard_detector_duration_seconds", "Per-detector scan duration in seconds."
        ),
        detector_failures_total=counter(
            "realguard_detector_failures_total", "Detector failures by detector_id/reason."
        ),
        policy_duration_seconds=histogram(
            "realguard_policy_duration_seconds", "Policy evaluation duration in seconds."
        ),
        transformation_duration_seconds=histogram(
            "realguard_transformation_duration_seconds", "Transformation duration in seconds."
        ),
        transformations_total=counter(
            "realguard_transformations_total", "Total transformations applied by type/plane."
        ),
        upstream_duration_seconds=histogram(
            "realguard_upstream_duration_seconds", "Upstream provider call duration in seconds."
        ),
        upstream_errors_total=counter(
            "realguard_upstream_errors_total", "Upstream errors by provider/kind."
        ),
        upstream_calls_avoided_total=counter(
            "realguard_upstream_calls_avoided_total",
            "Upstream calls avoided by a DENY or an un-resumed NEED_APPROVAL (OBS-003).",
        ),
        firewall_added_seconds=histogram(
            "realguard_firewall_added_seconds",
            "Firewall-added latency (total - upstream), by plane.",
        ),
        output_decisions_total=counter(
            "realguard_output_decisions_total", "Output-guard decisions by verdict."
        ),
        approvals_total=counter("realguard_approvals_total", "Total approvals by state reached."),
        approval_queue_depth=gauge(
            "realguard_approval_queue_depth", "Current approval count by state."
        ),
        approval_wait_seconds=histogram(
            "realguard_approval_wait_seconds", "Time from approval creation to reviewer decision."
        ),
        resume_total=counter("realguard_resume_total", "Total resume attempts by outcome."),
        rate_limited_total=counter(
            "realguard_rate_limited_total", "Total requests refused by the rate limiter, by scope."
        ),
        degraded_transactions_total=counter(
            "realguard_degraded_transactions_total", "Total degraded transactions by reason."
        ),
        errors_total=counter("realguard_errors_total", "Total errors by error_code."),
        tool_findings_total=counter(
            "realguard_tool_findings_total", "Total tool-call findings by tool_name/category."
        ),
        policy_info=gauge("realguard_policy_info", "Loaded policy identity (always 1)."),
        build_info=gauge("realguard_build_info", "Build identity (always 1)."),
    )
