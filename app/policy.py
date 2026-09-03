"""Policy loading and validation. SPEC.md §7 (POL-014, POL-015, POL-020).

Full rule *evaluation* (the decision engine) is WS-05 / Phase 2. This module
only freezes and validates the *contract*: load YAML, validate against
policy.schema.json, and expose a stable, reproducible policy_version hash
(POL-015) — the piece WS-02 / Phase 1 needs so later phases have something
solid to build the decision engine against.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

logger = logging.getLogger("realguard.policy")

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "policies" / "policy.schema.json"


class PolicyLoadError(Exception):
    """Raised when a policy file fails to load or validate.

    Distinct from ConfigurationError: a bad POLICY_PATH is a startup failure
    (CFG-002), but this exception type is what carries the *why* so a caller
    can decide fail_open/fail_closed degraded behaviour (POL-009) rather than
    always hard-crashing the process.
    """


def _canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Stable serialization for hashing: sorted keys, compact separators, so
    the hash depends only on the document's *content*, not formatting.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def compute_policy_version(data: dict[str, Any]) -> str:
    """POL-015: SHA-256 of the canonicalised document, as `sha256:<hex>`."""
    digest = hashlib.sha256(_canonical_json_bytes(data)).hexdigest()
    return f"sha256:{digest}"


@dataclass(frozen=True)
class Policy:
    """A validated, loaded policy document."""

    path: str
    raw: dict[str, Any]
    policy_version: str

    @property
    def rules(self) -> list[dict[str, Any]]:
        return list(self.raw.get("rules", []))

    @property
    def defaults(self) -> dict[str, Any]:
        return dict(self.raw.get("defaults", {}))

    @property
    def detectors(self) -> dict[str, Any]:
        return dict(self.raw.get("detectors", {}))


def _load_schema() -> dict[str, Any]:
    # _SCHEMA_PATH is already a concrete filesystem Path (computed from
    # __file__), so this needs no importlib.resources indirection.
    schema: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text())
    return schema


def load_policy(policy_path: str, *, app_env: str = "development") -> Policy:
    """Load, schema-validate and hash a policy file.

    POL-020: an unknown key fails validation unconditionally (the schema sets
    additionalProperties:false everywhere); in a non-production environment
    we additionally log a WARNING before raising, so a typo'd rule key is
    loud in development rather than only failing a later CI run.
    """
    path = Path(policy_path)
    if not path.is_file():
        raise PolicyLoadError(f"policy file not found: {policy_path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"policy file is not valid YAML: {policy_path}: {e}") from e

    if not isinstance(raw, dict):
        raise PolicyLoadError(f"policy file does not contain a YAML mapping: {policy_path}")

    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(raw), key=lambda e: list(e.path))
    if errors:
        summary = "; ".join(f"{list(e.path)}: {e.message}" for e in errors[:5])
        if app_env != "production":
            logger.warning(
                "policy validation failed for %s (%d error(s)): %s",
                policy_path,
                len(errors),
                summary,
            )
        raise PolicyLoadError(
            f"policy file failed schema validation ({len(errors)} error(s)): {summary}"
        )

    version = compute_policy_version(raw)
    return Policy(path=policy_path, raw=raw, policy_version=version)


def validate_policy_dict(raw: dict[str, Any]) -> list[JsonSchemaValidationError]:
    """Validate an in-memory policy dict; returns the list of schema errors
    (empty if valid). Used by tests without touching the filesystem.
    """
    schema = _load_schema()
    validator = Draft202012Validator(schema)
    return sorted(validator.iter_errors(raw), key=lambda e: list(e.path))
