# ADR 0003 — Phase 2 detector set and corpus scope

**Status:** Accepted
**Date:** 2026-09-03
**Phase:** 2 (Input inspection and policy decisions)

## Context

Two planning-document inconsistencies surfaced while starting Phase 2, both caught by
cross-checking PLAN.md against SPEC.md before writing code rather than after.

**1. WS-04's deliverable list doesn't match SPEC.md §6.4's required-detector table.**
PLAN.md WS-04 lists: "`prompt_injection`; `pii`; `secrets`; `topics`; `urls`; `schema`;
`length`." SPEC.md §6.4's normative table lists nine `detector_id`s:
`prompt_injection`, `indirect_injection`, `pii`, `secrets`, `topics`, `urls`,
`system_prompt_leak`, `schema`, `tool_calls`. WS-04's list is missing
`indirect_injection`, `system_prompt_leak` and `tool_calls`, and includes `length`,
which is not a `detector_id` anywhere in SPEC.md — the byte-count check the name
suggests is already the `payload_limit` policy rule's `bytes_gt` condition, evaluated
directly against the normalizer's byte count with no detector module involved.

**2. WS-08 (Tool-call / action inspection) was never assigned to a phase.**
It has its own WBS section (PLAN.md WS-08) but the Phase 0–9 table in PLAN.md §6
never names it in any phase's task list — an oversight, not a deliberate deferral.

## Decision

**Detector set:** SPEC.md governs behaviour, so its nine-detector table is authoritative.
`length` is dropped (it was never a real detector). The remaining eight split across two
phases by which plane they inspect and what infrastructure they depend on:

| Detector | Plane | Phase | Why |
|---|---|---|---|
| `prompt_injection` | input, context | **2** | No dependency beyond the normalizer |
| `indirect_injection` | context | **2** | Same pattern families, context-only; natural pair with `prompt_injection` |
| `pii` | any | **2** | No dependency beyond the normalizer |
| `secrets` | any | **2** | No dependency beyond the normalizer |
| `topics` | input, context | **2** | Policy already carries word lists (ADR 0001 addendum) |
| `urls` | input, context | **2** | No dependency beyond the normalizer |
| `schema` | any | **2** | No dependency beyond the normalizer |
| `system_prompt_leak` | response | 3 | Inherently response-plane — pairs with the output guard (WS-07), which doesn't exist until Phase 3 |
| `tool_calls` | action | 3 | `DENY` verdicts (TOL-002/003/004) need no new infrastructure and *could* ship in Phase 2, but `NEED_APPROVAL` (TOL-001) needs WS-09's approval persistence (Phase 4); shipping the detector split across two phases for one corpus bucket adds more complexity than it removes, so the whole detector moves to Phase 3 alongside WS-08 |

**Corpus scope for Phase 2:** exactly the six buckets Phase 2's own automated-check
wording in PLAN.md §6 already names ("the injection, encoding, PII, secret and benign
corpus buckets pass") — `BENIGN`, `DIRECT_INJECTION`, `INDIRECT_INJECTION`,
`ENCODED_INJECTION`, `PII_INPUT`, `SECRET_INPUT` = 12+10+4+6+6+4 = **42 of 54 cases**.
`TOOL_ABUSE` (4), `OUTPUT_LEAKAGE` (4) and `LEAK_OUTPUT` (4) — 12 cases — are out of
scope for this phase and complete in Phase 3, per the PLAN.md Phase 3 edit accompanying
this ADR.

**PLAN.md fix:** Phase 3's task list now explicitly names WS-08, and its automated
checks now name the `TOOL_ABUSE` bucket split (three `DENY` cases complete; TOL-001's
decision is verified but its full API round-trip waits for Phase 4).

## Addendum — `prompt_injection` vs `indirect_injection` plane ownership

SPEC.md §7.1's example policy declares `deny_prompt_injection` with `plane: [input,
context]`, which could be read as "the `prompt_injection` detector scans context too."
Taken literally, that would make every indirect-injection corpus case (IND-001…004)
trigger **both** `PROMPT_INJECTION` and `INDIRECT_INJECTION` findings on the same text,
since both detectors would then match the same context-plane content with overlapping
pattern families — `deny_prompt_injection` and `deny_indirect_injection` firing
together on every case, with redundant reason codes that tell a reviewer nothing
`INDIRECT_INJECTION` alone doesn't already say more precisely (namely: this came from
untrusted retrieved/tool/replayed content, not from the live user).

**Decision:** `prompt_injection.supported_planes = {input}` only;
`indirect_injection.supported_planes = {context}` only. Each context-plane injection
produces exactly one category (`INDIRECT_INJECTION`), matching the IND-001…004
expectations already authored in the Phase 0 corpus — no corpus change needed.
`deny_prompt_injection`'s `plane: [input, context]` declaration in the policy is
harmless, deliberately defensive breadth (POL-017 requires an explicit plane on every
rule; declaring context here costs nothing since `prompt_injection` never actually
produces a context-plane finding) rather than a claim that both detectors must
overlap.

## Consequences

- `app/detectors/` gains seven modules in Phase 2: `prompt_injection.py`,
  `indirect_injection.py`, `pii.py`, `secrets.py`, `topics.py`, `urls.py`, `schema.py`.
  `system_prompt_leak.py` and `tool_calls.py` are Phase 3 work.
- The golden-corpus test runner (`tests/test_golden_corpus.py`) is introduced in Phase 2
  scoped to the 42 in-scope cases, with the 12 out-of-scope cases explicitly marked
  `pytest.mark.skip(reason="Phase 3/4 — see ADR 0003")` rather than silently absent, so
  the corpus file's full 54-case meta-test (TST-023, already passing since Phase 0)
  stays the source of truth for total count while the *runner* is honest about what it
  currently exercises.
- No change to the API surface, verdict set, transformation set, reason-code taxonomy,
  the corpus case count or its bucket distribution, or any resolved decision in
  PLAN.md §16.
