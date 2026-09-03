# ADR 0002 — the `ALLOW` response body must be the OpenAI shape at top level

**Status:** Accepted
**Date:** 2026-09-03
**Phase:** 1 (Repository foundation and deterministic mock path)

## Context

SPEC.md §4.3's "Allowed request" example — and `openapi.json`'s `AllowedResponse`
schema built from it — wraps the OpenAI chat-completion object inside a `response`
field, alongside firewall metadata:

```json
{
  "decision": "ALLOW",
  "transformation": "NONE",
  "transaction_id": "txn_...",
  "response": { "id": "chatcmpl_...", "choices": [...], ... }
}
```

WS-03's acceptance criterion is explicit: *"an unmodified `openai` Python client can
call the endpoint."* PRD FR6 makes the same promise: *"exposes the same
`/v1/chat/completions` shape clients already use, so integration is a URL + key
swap, not a rewrite."*

Phase 1's end-to-end smoke test ran the real `openai` Python SDK against a live
`uvicorn` instance of this gateway — not `TestClient`, an actual HTTP round trip —
and it failed:

```pycon
>>> resp = client.chat.completions.create(model="qwen3:8b", messages=[...])
>>> resp.choices[0].message.content
TypeError: 'NoneType' object is not subscriptable
```

The SDK's `ChatCompletion` model parses the top-level JSON body directly as the
completion object. With the completion nested under `response`, every field the
SDK expects at top level (`id`, `object`, `created`, `model`, `choices`, `usage`)
is `None`. This is not a client-side integration mistake — it is what "unmodified
client" means: no code, no manual unwrapping. The wrapped shape silently breaks the
single most-quoted value proposition in both PRD and README ("just change
`base_url`").

## Decision

The `ALLOW` response body **is** the OpenAI chat-completion object at top level.
Firewall metadata moves to one additional top-level field, `firewall`, which is
tolerated and preserved (`.model_extra`) by the real SDK — verified empirically,
not assumed:

```pycon
>>> ChatCompletion.model_validate({..., "firewall": {...}}).choices[0].message.content
'hi'
>>> ChatCompletion.model_validate({..., "firewall": {...}}).model_extra
{'firewall': {...}}
```

New shape:

```json
{
  "id": "chatcmpl_01HQ8XKJ4M2N7P9R3T5V6W8Y10",
  "object": "chat.completion",
  "created": 1772409600,
  "model": "qwen3:8b",
  "choices": [ { "index": 0, "message": {"role": "assistant", "content": "..."}, "finish_reason": "stop" } ],
  "usage": { "prompt_tokens": 18, "completion_tokens": 16, "total_tokens": 34 },
  "firewall": {
    "decision": "ALLOW",
    "transformation": "NONE",
    "transaction_id": "txn_01HQ8XKJ4M2N7P9R3T5V6W8Y10",
    "risk_level": "NONE",
    "reason_codes": [],
    "policy_hits": [],
    "policy_version": "sha256:4f1c9a2e",
    "degraded": false,
    "mode": "live",
    "timings_ms": {"detection": 4, "policy": 1, "upstream": 812, "output_guard": 3, "firewall_added": 8}
  }
}
```

`transaction_id` and `mode` also continue to be duplicated into the
`X-RealGuard-Transaction-Id` / `X-RealGuard-Mode` response headers (API-002), so a
caller that wants firewall metadata without touching the body at all can read it
from headers alone.

## Why `DENY` (403) and `NEED_APPROVAL` (202) were left unchanged

Tested empirically, not assumed, against a live server with the real SDK:

- **`DENY` (403):** a 4xx status is *not* a 2xx, so the SDK raises
  `openai.APIStatusError` before attempting any `ChatCompletion` parsing —
  `e.status_code` and `e.body` carry the DENY envelope cleanly. This is the
  idiomatic pattern (identical to how a caller already handles OpenAI's own
  `400 content_policy_violation`). §4.3's `DeniedResponse` shape is correct as
  specified — no change.
- **`NEED_APPROVAL` (202):** also tested — a 202 *is* 2xx, so the SDK does **not**
  raise; it attempts `ChatCompletion` parsing on the `NeedApprovalResponse` body
  and produces a `ChatCompletion` with every OpenAI field `None` (no crash, but a
  confusing object). This is a **known, accepted limitation**, not a new defect:
  SPEC.md §3.3's own sequence diagram and PLAN.md's persona descriptions already
  require a caller using approvals to poll `poll_url` separately — a synchronous
  chat call fundamentally cannot represent "a human will decide this later"
  without the caller doing something different from a normal completion call.
  The "URL + key swap, no rewrite" promise was always scoped to the `ALLOW` path;
  `DENY` and `NEED_APPROVAL` inherently require the caller to branch on status,
  exactly as any gateway that can block or hold a request does. **Action taken:**
  README §12 (Demonstrations) and §13 (API reference) MUST tell integrators
  explicitly that a 2xx status is not sufficient evidence of a normal completion —
  check for `NEED_APPROVAL` via the raw response before trusting `.choices` — so
  this doesn't surprise anyone at integration time the way it surprised Phase 1's
  own smoke test.

## Consequences

- SPEC.md §4.3's "Allowed request" example updated to the new shape.
- `openapi.json`'s `AllowedResponse` schema updated: OpenAI completion fields
  promoted to top level, `firewall` demoted to a single metadata field.
- `app/schemas.py::AllowedResponse` and `app/main.py`'s handler updated to match
  and re-verified against the real SDK (not `TestClient` alone) after the fix.
- No change to `DeniedResponse`, `NeedApprovalResponse`, the verdict set, the
  transformation set, the reason-code taxonomy, the eight-endpoint surface, or
  any resolved decision in PLAN.md §16.
- This is exactly the class of finding Phase 1's exit gate exists to catch:
  PLAN.md §6 Phase 1 says "an unmodified `openai` Python client can talk to it" as
  a *manual validation* step, deliberately distinct from the automated checks —
  and it was the manual step, run against a real server, that caught this.
