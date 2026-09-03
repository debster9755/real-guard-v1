"""WS-04 orchestrator tests. SPEC.md §2.3 (DET-012..014)."""

from __future__ import annotations

import time

from app.detectors.base import Category, Confidence, Finding
from app.normalizer import normalize
from app.orchestrator import DetectorOrchestrator
from app.planes import Plane


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
