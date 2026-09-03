"""Detector orchestrator. SPEC.md §2.3 (DET-012, DET-013, DET-014, POL-007).

Runs every applicable detector concurrently against one plane's content,
enforces a per-detector deadline, and isolates a raising or slow detector so
one bad detector never takes the others down with it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from app.detectors.base import Category, Confidence, Detector, Finding
from app.normalizer import NormalizedContent
from app.planes import Plane

logger = logging.getLogger("realguard.orchestrator")


@dataclass(frozen=True)
class DetectorExecutionReport:
    detector_id: str
    detector_version: str
    ok: bool
    timed_out: bool = False
    error: str | None = None  # ERR-022: a class/kind, never the raw exception text with content


@dataclass(frozen=True)
class OrchestratorResult:
    findings: tuple[Finding, ...]
    reports: tuple[DetectorExecutionReport, ...] = field(default_factory=tuple)

    @property
    def degraded(self) -> bool:
        return any(not r.ok for r in self.reports)


async def _run_one(
    detector: Detector, content: NormalizedContent, plane: Plane, salt: str, timeout_s: float
) -> tuple[DetectorExecutionReport, list[Finding]]:
    try:
        findings = await asyncio.wait_for(
            asyncio.to_thread(detector.scan, content, plane, salt), timeout=timeout_s
        )
        return (
            DetectorExecutionReport(detector.detector_id, detector.detector_version, ok=True),
            findings,
        )
    except TimeoutError:
        # POL-007: DET-012's deadline exceeded MUST produce a DETECTOR_TIMEOUT
        # finding and MUST NOT abort the others (DET-013/014).
        logger.warning("detector timed out", extra={"detector_id": detector.detector_id})
        timeout_finding = Finding(
            detector_id=detector.detector_id,
            detector_version=detector.detector_version,
            category=Category.DETECTOR_TIMEOUT,
            score=0.0,
            confidence=Confidence.LOW,
            safe_metadata={"timeout_ms": int(timeout_s * 1000)},
        )
        return (
            DetectorExecutionReport(
                detector.detector_id, detector.detector_version, ok=False, timed_out=True
            ),
            [timeout_finding],
        )
    except Exception as e:  # noqa: BLE001 — DET-014: isolate, never propagate
        # ERR-022: log only the exception *type*, never its message, since a
        # regex or parsing exception can embed fragments of the offending
        # content in its message.
        logger.warning(
            "detector raised",
            extra={"detector_id": detector.detector_id, "error_type": type(e).__name__},
        )
        return (
            DetectorExecutionReport(
                detector.detector_id,
                detector.detector_version,
                ok=False,
                error=type(e).__name__,
            ),
            [],
        )


class DetectorOrchestrator:
    def __init__(self, detectors: list[Detector], *, detector_timeout_ms: int = 250) -> None:
        self._detectors = detectors
        self._timeout_s = detector_timeout_ms / 1000

    async def run(self, content: NormalizedContent, plane: Plane, salt: str) -> OrchestratorResult:
        applicable = [d for d in self._detectors if plane in d.supported_planes]
        if not applicable:
            return OrchestratorResult(findings=())

        results = await asyncio.gather(
            *(_run_one(d, content, plane, salt, self._timeout_s) for d in applicable)
        )

        all_findings: list[Finding] = []
        all_reports: list[DetectorExecutionReport] = []
        for report, findings in results:
            all_reports.append(report)
            all_findings.extend(findings)

        return OrchestratorResult(findings=tuple(all_findings), reports=tuple(all_reports))
