"""Material-argument hashing. SPEC.md APR-013.

"Material arguments are the normalized messages plus all tool-call
arguments — everything the reviewer's judgment depended on." Computed once
at approval creation time and re-computed immediately before resume; a
mismatch means the request changed after a human signed off on it, and
resume MUST refuse rather than act on the new content (APR-013).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def compute_material_args_hash(
    messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
) -> str:
    """SHA-256 of the canonicalised (messages, tools) pair. Deliberately
    excludes fields that never influenced the reviewer's judgment (e.g.
    `temperature`, `seed`) — only the content and tool surface a reviewer
    actually looked at (APR-013)."""
    material = {
        "messages": [{"role": m.get("role"), "content": m.get("content")} for m in messages],
        "tools": tools or [],
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
