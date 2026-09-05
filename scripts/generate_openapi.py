#!/usr/bin/env python3
"""Regenerate openapi.json from the real, running FastAPI application.

Phase 8 / WS-16 deliverable ("a generated OpenAPI document") and PLAN.md
§12's anti-drift automation item 3: "OpenAPI diff — regenerates openapi.json
from the running app and fails if it differs from the committed file, so the
API contract cannot change silently."

Background (docs/adr/0010): openapi.json was hand-authored at Phase 0, before
any route existed, as a design-time target for the 8 endpoints SPEC.md §4.1
names. Its own `description` field said as much: "In Phase 3+ this file MUST
be regenerated from the running FastAPI app... a diff fails CI." That never
happened through Phase 7 — this script and its CI wiring (Phase 8) are what
makes it happen from here on. The committed openapi.json is now this script's
own output, not a hand-maintained document (PLAN.md §12's table: "openapi.json
| The machine-readable API contract | Hand edits — it is generated").

Usage:
    python scripts/generate_openapi.py             # writes openapi.json
    python scripts/generate_openapi.py --check      # exits 1 if the
                                                      # committed file would
                                                      # change; prints a diff

No server process is started — app.main.create_app() is imported and its
FastAPI instance's own .openapi() method is called in-process, so this needs
no network, no port, and no running uvicorn.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENAPI_PATH = ROOT / "openapi.json"


def generate() -> dict:
    # Import here, not at module scope, so --help works even if app's
    # dependencies aren't importable for some reason, and so we control
    # exactly when app.main's module-level create_app() side effect runs.
    sys.path.insert(0, str(ROOT))
    from app.main import create_app

    app = create_app()
    schema = app.openapi()
    # FastAPI caches app.openapi_schema after the first call; we want a
    # deterministic, independently-reproducible document, so drop any
    # non-deterministic or environment-specific noise. There is none in
    # practice (no servers[], no timestamps) — this is a no-op safeguard.
    return schema


def canonical_json(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write; exit 1 if the generated document differs from the committed one.",
    )
    args = parser.parse_args()

    schema = generate()
    new_text = canonical_json(schema)

    if args.check:
        if not OPENAPI_PATH.exists():
            print(f"FAIL: {OPENAPI_PATH} does not exist")
            return 1
        old_text = OPENAPI_PATH.read_text()
        if old_text == new_text:
            print("OK: openapi.json matches the running application exactly")
            return 0
        print("FAIL: openapi.json is stale — it does not match the running application.")
        print("Run `python scripts/generate_openapi.py` to regenerate, then commit the result.")
        import difflib

        diff = difflib.unified_diff(
            old_text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile="openapi.json (committed)",
            tofile="openapi.json (generated from the running app)",
        )
        sys.stdout.writelines(diff)
        return 1

    OPENAPI_PATH.write_text(new_text)
    print(f"Wrote {OPENAPI_PATH} ({len(schema.get('paths', {}))} paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
