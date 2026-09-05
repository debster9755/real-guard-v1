"""WS-04 orchestrator tests. SPEC.md §2.3 (DET-012..014). SPEC.md TST-020
("no detector exceeds its deadline on adversarial input") — Phase 7/WS-14."""

from __future__ import annotations

import time

from app.detectors.base import Category, Confidence, Finding
from app.normalizer import normalize
from app.orchestrator import DetectorOrchestrator
from app.pipeline import build_input_detectors
from app.planes import Plane
from app.policy import load_policy
from hypothesis import given, settings
from hypothesis import strategies as st


class _GoodDetector:
    detector_id = "good"
    detector_version = "1.0.0"
    supported_planes = frozenset({Plane.input})

    def scan(self, content, plane, salt):  # noqa: ANN001
        return [
            Finding(
                detector_id="good",
                detector_version="1.0.0",
                category=Category.PII_DETECTED,
                score=0.9,
                confidence=Confidence.HIGH,
            )
        ]


class _RaisingDetector:
    detector_id = "raising"
    detector_version = "1.0.0"
    supported_planes = frozenset({Plane.input})

    def scan(self, content, plane, salt):  # noqa: ANN001
        raise ValueError("boom with sensitive content that must never leak")


class _SlowDetector:
    detector_id = "slow"
    detector_version = "1.0.0"
    supported_planes = frozenset({Plane.input})

    def scan(self, content, plane, salt):  # noqa: ANN001
        time.sleep(0.5)
        return []


class _WrongPlaneDetector:
    detector_id = "wrong_plane"
    detector_version = "1.0.0"
    supported_planes = frozenset({Plane.response})

    def scan(self, content, plane, salt):  # noqa: ANN001
        raise AssertionError("should never be called for a plane it doesn't support")


async def test_good_detector_findings_survive_alongside_a_failure() -> None:
    orch = DetectorOrchestrator([_GoodDetector(), _RaisingDetector()], detector_timeout_ms=1000)
    result = await orch.run(normalize("hello"), Plane.input, "salt")
    assert any(f.detector_id == "good" for f in result.findings)


async def test_raising_detector_isolated_det014() -> None:
    orch = DetectorOrchestrator([_RaisingDetector()], detector_timeout_ms=1000)
    result = await orch.run(normalize("hello"), Plane.input, "salt")  # must not raise
    assert result.degraded is True


async def test_error_type_recorded_never_message_err022() -> None:
    orch = DetectorOrchestrator([_RaisingDetector()], detector_timeout_ms=1000)
    result = await orch.run(normalize("hello"), Plane.input, "salt")
    report = result.reports[0]
    assert report.error == "ValueError"  # the type
    assert "sensitive content" not in (report.error or "")  # never the message


async def test_slow_detector_times_out_and_marks_degraded() -> None:
    orch = DetectorOrchestrator([_SlowDetector()], detector_timeout_ms=50)
    result = await orch.run(normalize("hello"), Plane.input, "salt")
    assert result.degraded is True
    assert any(f.category == Category.DETECTOR_TIMEOUT for f in result.findings)


async def test_detector_only_invoked_for_supported_plane() -> None:
    orch = DetectorOrchestrator([_WrongPlaneDetector()], detector_timeout_ms=1000)
    result = await orch.run(
        normalize("hello"), Plane.input, "salt"
    )  # must not raise AssertionError
    assert result.findings == ()


async def test_empty_detector_list_yields_no_findings() -> None:
    orch = DetectorOrchestrator([], detector_timeout_ms=1000)
    result = await orch.run(normalize("hello"), Plane.input, "salt")
    assert result.findings == ()
    assert result.degraded is False


# --- TST-020 property test: "no detector exceeds its deadline on
# adversarial input" ---------------------------------------------------
#
# Phase 7 (WS-14) adds this — Phase 2 (ADR 0003) only had a normalizer
# property test, not one covering DET-012's per-detector deadline. Runs
# every *real* bundled detector (not a fake) against Hypothesis-generated
# arbitrary text, including strings deliberately shaped to provoke
# catastrophic regex backtracking (long repeated runs of a few characters
# that almost, but don't quite, match a pattern's tail). The property under
# test is `asyncio.wait_for`'s own guarantee (app/orchestrator.py): the
# orchestrator's wall-clock return time is bounded by
# `detector_timeout_ms` plus a small fixed overhead *regardless* of how
# long a synchronous `scan()` call actually takes inside its worker
# thread — a slow/hung detector's thread is abandoned, not force-killed,
# so `scan()` itself is not bounded by this property; the caller-visible
# orchestrator result is, which is what actually matters for DET-012's own
# "the platform must remain responsive" intent.
_REAL_POLICY = load_policy("policies/default_policy.yaml")
_REAL_DETECTORS = build_input_detectors(_REAL_POLICY)
_DEADLINE_MS = 250
# Generous slack over the deadline: thread-pool scheduling jitter under
# Hypothesis's own shrinking/replay overhead, not a claim about steady-state
# latency (docs/benchmarks.md is the authority on that).
_MAX_ALLOWED_MS = _DEADLINE_MS + 2000


@given(
    st.one_of(
        st.text(max_size=3000),
        # Adversarial shapes literature associates with regex backtracking:
        # long runs of a repeated near-miss character/word.
        st.text(alphabet="aA ", min_size=0, max_size=3000),
        st.text(alphabet="ignore previous instructions ", min_size=0, max_size=3000),
    )
)
@settings(max_examples=300, deadline=None)
async def test_real_detectors_bounded_by_deadline_on_adversarial_input(text: str) -> None:
    orch = DetectorOrchestrator(_REAL_DETECTORS, detector_timeout_ms=_DEADLINE_MS)
    t0 = time.perf_counter()
    result = await orch.run(normalize(text), Plane.input, "salt")
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _MAX_ALLOWED_MS, (
        f"orchestrator took {elapsed_ms:.1f}ms (> {_MAX_ALLOWED_MS}ms budget) "
        f"for input of length {len(text)}"
    )
    assert result is not None  # must not raise, regardless of input (DET-014)
