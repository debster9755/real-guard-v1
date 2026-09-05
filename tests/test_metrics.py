"""`GET /metrics` tests. SPEC.md §2.16, §4.7, §13 (OBS-001, OBS-012),
API-017. Phase 6 (WS-12) — PLAN.md's "metric-cardinality test" and the
`GET /metrics` half of its Phase 6 automated checks.

`prometheus_client`'s own text parser groups exposition lines into
*families* keyed by the metric's base name (e.g. a `_total`-suffixed
counter's family name has the suffix stripped, per the Prometheus text
format's own convention) — `_samples_by_name()` below re-keys by each
individual sample's *full* name instead, so assertions can address
`realguard_decisions_total` (a real wire name) directly rather than the
parser's internal family grouping.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from app.metrics import METRIC_LABELS, Metrics, bounded_tool_name, build_metrics
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client.samples import Sample


def _samples_by_name(text: str) -> dict[str, list[Sample]]:
    out: dict[str, list[Sample]] = {}
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            out.setdefault(sample.name, []).append(sample)
    return out


def test_metrics_endpoint_returns_prometheus_text_exposition(
    client_factory: Callable[..., TestClient],
) -> None:
    client = client_factory()
    client.post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "What is a good banana bread recipe?"}]},
    )

    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")

    # A real Prometheus text-exposition parse, not a substring grep — proves
    # the wire format itself is valid, not just that some bytes came back.
    samples = _samples_by_name(resp.text)
    assert "realguard_decisions_total" in samples
    assert "realguard_http_requests_total" in samples


def test_reflects_real_request_activity(client_factory: Callable[..., TestClient]) -> None:
    client = client_factory()
    for _ in range(3):
        client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hello there"}]},
        )

    samples = _samples_by_name(client.get("/metrics").text)

    allow_input_samples = [
        s
        for s in samples["realguard_decisions_total"]
        if s.labels.get("verdict") == "ALLOW" and s.labels.get("plane") == "input"
    ]
    assert allow_input_samples and sum(s.value for s in allow_input_samples) >= 3


class TestMetricsRequireAuth:
    def test_open_when_metrics_require_auth_is_false(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        client = client_factory(METRICS_REQUIRE_AUTH="false")
        assert client.get("/metrics").status_code == 200

    def test_requires_a_valid_key_when_true(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        service_key = "s" * 40
        reviewer_key = "r" * 40
        client = client_factory(
            METRICS_REQUIRE_AUTH="true",
            FIREWALL_API_KEYS=service_key,
            FIREWALL_REVIEWER_KEYS=reviewer_key,
        )
        assert client.get("/metrics").status_code == 401

        assert (
            client.get("/metrics", headers={"Authorization": f"Bearer {service_key}"}).status_code
            == 200
        )
        # SEC-001's table lists /metrics under Service's allowed column and
        # leaves Reviewer's "may NOT call" cell empty for it — read
        # permissively (docs/adr/0008): a reviewer key also works.
        assert (
            client.get("/metrics", headers={"Authorization": f"Bearer {reviewer_key}"}).status_code
            == 200
        )

        assert (
            client.get("/metrics", headers={"Authorization": "Bearer " + "x" * 40}).status_code
            == 401
        )


class TestCardinality:
    # OBS-012: "A test MUST assert the exact label set of every metric."
    # Introspects each `Metrics` field's own declared label names directly
    # (`Counter`/`Histogram`/`Gauge._labelnames`) rather than requiring a
    # live sample of every metric to exist first — a labelled Prometheus
    # metric that has never been `.labels(...)`'d emits nothing at all in
    # the exposition text, regardless of whether its label *set* is
    # correctly bounded, so this is the deterministic form of the check.

    def test_every_declared_metric_has_exactly_its_spec_label_set(self) -> None:
        metrics = build_metrics(CollectorRegistry())
        name_by_field = {
            "http_requests_total": "realguard_http_requests_total",
            "http_request_duration_seconds": "realguard_http_request_duration_seconds",
            "decisions_total": "realguard_decisions_total",
            "risk_level_total": "realguard_risk_level_total",
            "policy_hits_total": "realguard_policy_hits_total",
            "reason_codes_total": "realguard_reason_codes_total",
            "detector_duration_seconds": "realguard_detector_duration_seconds",
            "detector_failures_total": "realguard_detector_failures_total",
            "policy_duration_seconds": "realguard_policy_duration_seconds",
            "transformation_duration_seconds": "realguard_transformation_duration_seconds",
            "transformations_total": "realguard_transformations_total",
            "upstream_duration_seconds": "realguard_upstream_duration_seconds",
            "upstream_errors_total": "realguard_upstream_errors_total",
            "upstream_calls_avoided_total": "realguard_upstream_calls_avoided_total",
            "firewall_added_seconds": "realguard_firewall_added_seconds",
            "output_decisions_total": "realguard_output_decisions_total",
            "approvals_total": "realguard_approvals_total",
            "approval_queue_depth": "realguard_approval_queue_depth",
            "approval_wait_seconds": "realguard_approval_wait_seconds",
            "resume_total": "realguard_resume_total",
            "rate_limited_total": "realguard_rate_limited_total",
            "degraded_transactions_total": "realguard_degraded_transactions_total",
            "errors_total": "realguard_errors_total",
            "tool_findings_total": "realguard_tool_findings_total",
            "policy_info": "realguard_policy_info",
            "build_info": "realguard_build_info",
        }
        assert set(name_by_field.values()) == set(METRIC_LABELS), (
            "this test's field/name map is out of sync with app/metrics.py's own catalogue"
        )

        for field in dataclasses.fields(Metrics):
            if field.name not in name_by_field:
                continue  # registry / tool_allowlist: not a Prometheus metric
            metric_name = name_by_field[field.name]
            metric_obj = getattr(metrics, field.name)
            assert tuple(metric_obj._labelnames) == METRIC_LABELS[metric_name], (
                f"{metric_name}: declared labels {metric_obj._labelnames} != "
                f"SPEC.md §13.1's {METRIC_LABELS[metric_name]}"
            )

    def test_metrics_registered_over_http_carry_only_their_declared_labels(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        """A live-request sanity check alongside the deterministic
        introspection above: whatever *does* get emitted over the wire for
        one real request must still carry exactly its declared labels."""
        client = client_factory()
        client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hello"}]},
        )
        samples = _samples_by_name(client.get("/metrics").text)

        for metric_name, expected_labels in METRIC_LABELS.items():
            candidate = metric_name if metric_name in samples else f"{metric_name}_count"
            if candidate not in samples:
                continue  # this scenario never incremented this metric — fine
            for sample in samples[candidate]:
                assert set(sample.labels.keys()) == set(expected_labels), (
                    f"{metric_name} sample has labels {sorted(sample.labels)}, "
                    f"expected exactly {sorted(expected_labels)}"
                )

    def test_tool_name_is_bounded_to_the_allowlist_plus_other(self) -> None:
        allowlist = frozenset({"search_docs", "wire_transfer"})
        assert bounded_tool_name("wire_transfer", allowlist) == "wire_transfer"
        assert bounded_tool_name("some_arbitrary_model_supplied_tool", allowlist) == "other"

    def test_endpoint_label_is_a_route_template_not_a_resolved_path(
        self, client_factory: Callable[..., TestClient]
    ) -> None:
        client = client_factory()
        client.get("/does-not-exist-at-all")
        samples = _samples_by_name(client.get("/metrics").text)
        endpoints = {s.labels.get("endpoint") for s in samples["realguard_http_requests_total"]}
        assert "/does-not-exist-at-all" not in endpoints
        assert "unmatched" in endpoints
