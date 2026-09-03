"""The four inspection planes. SPEC.md §1.2, §5's policy `plane` values.

Values match the lowercase strings used in policy YAML (`plane: [input,
context]`) so a Plane can be compared directly against a loaded rule's
`plane` list without translation.
"""

from __future__ import annotations

from enum import StrEnum


class Plane(StrEnum):
    input = "input"
    context = "context"
    response = "response"
    action = "action"
