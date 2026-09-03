"""Opaque, prefixed identifiers. SPEC.md API-004: `txn_`, `req_`, `apr_`,
`evt_`, etc. Clients MUST NOT parse them; we don't promise any particular
encoding beyond "URL-safe and collision-resistant enough for this MVP's
scale," so a 26-character base32 Crockford-ish token (ULID-shaped, but not a
strict ULID implementation) is used rather than a raw UUID4 for
lexicographic sortability by creation time, which is convenient for the
future `created_at`-ordered indexes in SPEC.md §10.
"""

from __future__ import annotations

import os
import time

_CROCKFORD32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode_crockford32(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        value, rem = divmod(value, 32)
        chars.append(_CROCKFORD32[rem])
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    """A monotonic-ish, sortable, opaque identifier: <prefix>_<26 chars>.

    First 10 chars encode milliseconds since epoch (48 bits, Crockford32);
    remaining 16 chars are cryptographically random (80 bits) — collision
    probability is negligible at this system's scale.
    """
    millis = int(time.time() * 1000)
    time_part = _encode_crockford32(millis, 10)
    rand_part = _encode_crockford32(int.from_bytes(os.urandom(10), "big"), 16)
    return f"{prefix}_{time_part}{rand_part}"


def new_transaction_id() -> str:
    return new_id("txn")


def new_request_id() -> str:
    return new_id("req")


def new_approval_id() -> str:
    return new_id("apr")


def new_event_id() -> str:
    return new_id("evt")
