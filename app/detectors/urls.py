"""`urls` detector. SPEC.md §6.4: "URL extraction | Flags private, link-local
and metadata-service addresses." Category: SCHEMA_VIOLATION.

This detector only *flags* such URLs as a finding for the policy engine to
act on — it never follows a link (SYS-013's SSRF prevention is enforced at
the provider-adapter boundary in a later phase, not here; DET-002 forbids
this module from performing I/O at all).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.detectors.base import Category, Confidence, Evidence, Finding, salted_excerpt_hash
from app.normalizer import NormalizedContent
from app.planes import Plane

DETECTOR_ID = "urls"
DETECTOR_VERSION = "1.0.0"

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)

# AWS/GCP/Azure metadata-service address — the classic SSRF exfiltration
# target, worth naming explicitly rather than relying on link-local alone.
_METADATA_SERVICE_HOST = "169.254.169.254"


def _is_flaggable_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in ("localhost", _METADATA_SERVICE_HOST):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # a hostname, not a literal address — not flagged here
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


class UrlsDetector:
    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    supported_planes = frozenset({Plane.input, Plane.context})

    def scan(self, content: NormalizedContent, plane: Plane, salt: str) -> list[Finding]:
        if plane not in self.supported_planes:
            return []
        findings: list[Finding] = []
        for m in _URL_RE.finditer(content.normalized):
            url = m.group(0)
            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                continue
            if not _is_flaggable_host(host):
                continue
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    detector_version=DETECTOR_VERSION,
                    category=Category.SCHEMA_VIOLATION,
                    score=0.7,
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        Evidence(
                            start=m.start(),
                            end=m.end(),
                            pattern_id="private_or_metadata_url_v1",
                            excerpt_hash=salted_excerpt_hash(url, salt),
                        ),
                    ),
                    safe_metadata={"host_class": "private_or_metadata"},
                )
            )
        return findings
