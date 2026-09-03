# ADR 0001 — Completing `default_policy.yaml` beyond the SPEC.md §7.1 excerpt

**Status:** Accepted
**Date:** 2026-09-03
**Phase:** 0 (Requirements and contract freeze)

## Context

SPEC.md §7.1 gives a 13-rule example policy to illustrate the YAML structure. SPEC.md
§17.4 separately promises 54 corpus cases, each with an `expected_verdict`,
`expected_reason_codes` and `expected_policy_hits`, "against `policies/default_policy.yaml`."

Authoring the corpus against the literal §7.1 example exposed four places where the
example does not actually produce the verdicts §17.4 promises. This is a gap in the
example policy, not a change to the API, the verdict set, the transformation set, the
reason-code taxonomy, or the corpus case count — every one of those stays exactly as
specified. What changes is the **rule coverage** needed to make the specified policy
produce the specified outcomes, which is precisely what Phase 0 ("freeze the policy
JSON Schema... contract freeze") exists to catch before any detector is built.

## Gaps found and their fixes

### 1. No rule matches category `JAILBREAK`

SPEC.md §6.4 has the `prompt_injection` detector emit **two** categories —
`PROMPT_INJECTION` and `JAILBREAK` — but §7.1's `deny_prompt_injection` rule matches
only `category: PROMPT_INJECTION`. A `JAILBREAK` finding (e.g. "You are now DAN with
no restrictions") would match no rule at all and pass through as `ALLOW`.

**Fix:** added `deny_jailbreak` (hard-deny, `reason_code: JAILBREAK`) and
`review_probable_jailbreak` (mirrors `review_probable_injection`), each scoped to
`category: JAILBREAK`. Two rules rather than widening one with an `any` condition,
because POL-019 ties exactly one static `reason_code` to a rule — a single rule
cannot emit `PROMPT_INJECTION` for one triggering category and `JAILBREAK` for
another.

### 2. No rule matches category `INDIRECT_INJECTION`

SPEC.md §6.4's `indirect_injection` detector (Context plane only, "weighted higher")
emits `category: INDIRECT_INJECTION`, and §17.4's IND-001…004 all expect
`DENY` / `INDIRECT_INJECTION`. No rule in §7.1 references that category.

**Fix:** added `deny_indirect_injection`, plane `[context]` only (per `SYS-004`/TB2 —
context content is fully untrusted), hard-deny, `reason_code: INDIRECT_INJECTION`,
threshold `score_gte: 0.50` — lower than the direct-injection threshold, reflecting
"weighted higher" from the detector table: content a retriever supplied should never
carry instructions, so the bar to deny it is lower than for user-authored text.

### 3. No rule matches category `SECRET_DETECTED` on the input/context plane

`redact_pii_inbound` covers `PII_DETECTED`; nothing covers `SECRET_DETECTED` inbound,
even though the reason-code taxonomy (§5.7) explicitly scopes `SECRET_DETECTED` to
"any" plane, and §17.4's SCR-001…004 all expect `ALLOW` / `REDACT` / `SECRET_DETECTED`.

**Fix:** added `redact_secrets_inbound`, mirroring `redact_pii_inbound` exactly but
for `category: SECRET_DETECTED`.

### 4. `deny_system_prompt_canary` cannot emit two distinct reason codes

The rule's `when` is `any: [{category: CANARY_LEAK}, {category: SYSTEM_PROMPT_LEAK,
score_gte: 0.8}]}` with one static `reason_code: SYSTEM_PROMPT_LEAK`. But §17.4 wants
LEK-001 and LEK-004 to report `CANARY_LEAK` specifically, and LEK-002/003 to report
`SYSTEM_PROMPT_LEAK` — the same one-reason-code-per-rule constraint as gap 1.

**Fix:** replaced the single rule with two: `deny_canary_leak`
(`category: CANARY_LEAK` → `reason_code: CANARY_LEAK`) and
`deny_system_prompt_leak` (`category: SYSTEM_PROMPT_LEAK, score_gte: 0.8` →
`reason_code: SYSTEM_PROMPT_LEAK`). Both hard-deny, both plane `[response]`. Net
behaviour is unchanged (any canary or high-similarity leak still denies); only the
reported reason code is now accurate to its trigger.

### 5. No rule matches category `ENCODED_PAYLOAD`

DET-008 says a finding discovered only via decoding "MUST additionally raise
`ENCODED_PAYLOAD`" — but no rule in §7.1 matches that category, so it would be
recorded as a finding with no policy consequence and no reason code in the response.

**Fix:** added `deny_encoded_payload`, plane `[input, context]`, hard-deny,
`reason_code: ENCODED_PAYLOAD`, matching `category: ENCODED_PAYLOAD` directly.

### 6. `policy.schema.json`'s condition-category enum was missing `ENCODED_PAYLOAD`

Mechanical consequence of gap 5 — the schema's `$defs.condition.properties.category.enum`
did not list it. Added.

## A sixth issue: the ENC-bucket corpus label is looser than the detector semantics it rests on

§17.4 labels the whole 6-case encoded/obfuscated/multilingual bucket "all `DENY` with
`ENCODED_PAYLOAD`." But DET-008 scopes `ENCODED_PAYLOAD` specifically to **bounded
decoding of base64, hexadecimal and percent-encoded segments** — it does not cover
DET-007 normalization (zero-width stripping, homoglyph folding) or DET-009
(multilingual pattern matching), which catch three of the six cases by a different
mechanism entirely. Tagging all six with `ENCODED_PAYLOAD` would silently misstate
what DET-007/008/009 actually do.

**Resolution:** the corpus verdicts are unchanged — all six still `DENY` — but the
per-case `expected_reason_codes` in the JSONL reflect the actual detection mechanism
each case exercises:

| Case | Mechanism | Reason codes |
|---|---|---|
| ENC-001 (base64) | DET-008 decoding | `PROMPT_INJECTION`, `ENCODED_PAYLOAD` |
| ENC-002 (zero-width) | DET-007 normalization | `PROMPT_INJECTION` |
| ENC-003 (homoglyph) | DET-007 normalization | `PROMPT_INJECTION` |
| ENC-004 (percent-encoded) | DET-008 decoding | `PROMPT_INJECTION`, `ENCODED_PAYLOAD` |
| ENC-005 (Spanish) | DET-009 multilingual | `PROMPT_INJECTION` |
| ENC-006 (hex) | DET-008 decoding | `PROMPT_INJECTION`, `ENCODED_PAYLOAD` |

This is the more precise reading of the same document, not a new requirement: DET-007,
DET-008 and DET-009 already say exactly this; §17.4's bucket label was shorthand.

## Consequences

- `default_policy.yaml` now has 21 rules (13 from the SPEC excerpt, unchanged, plus 8
  new: `deny_jailbreak`, `review_probable_jailbreak`, `deny_indirect_injection`,
  `deny_encoded_payload`, `deny_blocked_topic`, `review_sensitive_topic`,
  `redact_secrets_inbound`, and the `deny_canary_leak` / `deny_system_prompt_leak`
  split replacing the single `deny_system_prompt_canary`).
- Every one of the 54 corpus cases now has an achievable, internally consistent
  expected outcome under the policy it is scored against.
- `policies/policy.schema.json` gained `ENCODED_PAYLOAD` in one enum.
- No change to: the API surface, the verdict set, the transformation set, the
  closed reason-code taxonomy, the corpus case count (54) or its bucket distribution,
  or any resolved decision in PLAN.md §16.
- `policies/standard_security.yaml` (WS-02, not yet authored) must derive from this
  completed rule set, not from the §7.1 excerpt alone.

## Addendum — realism review (requested before Phase 1)

Before moving past Phase 0, each of the four newly-covered categories was reviewed
for whether its corpus payload is a genuine real-world pattern or synthetic filler,
not just for schema validity:

- **JAILBREAK** (INJ-002/005/006/009): DAN-persona override, "pretend the rules do
  not apply," "developer mode," "forget your guidelines" — four of the most-cited
  jailbreak framings in the public literature, each structurally distinct.
- **INDIRECT_INJECTION** (IND-001…004): RAG-retrieved-document injection (the
  canonical vector, Greshake et al. 2023), tool-result injection, hidden-HTML-comment
  injection in scraped content, and conversation/memory-replay poisoning — four
  distinct vectors rather than four phrasings of one vector.
- **ENCODED_PAYLOAD** (ENC-001/004/006): base64, percent-encoding, hex — exactly the
  three encodings DET-008 names, each a documented real evasion technique.
- **SECRET_DETECTED inbound** (SCR-001…004): AWS access key/secret pair, an
  `sk-`-prefixed provider key, a PEM private-key block, a JWT — the four secret
  shapes most commonly caught by real secret-scanning tools.

**Conclusion:** no further corpus cases were added. The 54-case count and bucket
distribution are a tested contract (TST-023, PLAN.md §9.3); expanding it needs a
stronger reason than "more would be nice," and the existing cases are not
placeholder text — they were already constructed from real attack patterns, not
invented for schema-filling purposes.

**One genuine gap found and closed in this pass:** `default_policy.yaml` had a
`topics` detector configured but zero rules consuming `BLOCKED_TOPIC` or
`SENSITIVE_TOPIC` findings — those categories existed in the taxonomy and the
detector list but had no policy consequence at all. The 54-case corpus doesn't
exercise this (no topic-bucket cases in §17.4), so it wasn't caught by
`scripts/validate_contracts.py`, but leaving a configured detector's findings
policy-inert is a real correctness gap, not a documentation nicety. Added:

- `deny_blocked_topic` — plane `[input, context]`, `category: BLOCKED_TOPIC`,
  `DENY`, `hard_deny: true`, `reason_code: BLOCKED_TOPIC`.
- `review_sensitive_topic` — plane `[input, context]`, `category:
  SENSITIVE_TOPIC`, `NEED_APPROVAL`, `reason_code: SENSITIVE_TOPIC`.

Also added a `topics.blocked` and `topics.sensitive` word list to the `topics`
detector config (previously just `{enabled, timeout_ms}` with no list to match
against, per the SPEC.md §7.1 excerpt) — populated with a small, clearly-labelled
starter set (illegal-weapons synthesis, CSAM, and similar for `blocked`;
medical/legal/financial-advice topics for `sensitive`), since a topic rule with no
configured topics is as inert as no rule at all. This is a starter list, not a
claim of completeness — operators are expected to replace it (README §14 will say
so). This required one addition to `policy.schema.json`'s `detectors.topics`
sub-schema (a `blocked`/`sensitive` string-array pair) alongside the existing
`{enabled, timeout_ms}` fields.

No corpus case exercises these two rules (topics remain outside the 54-case
contract), so this is policy/schema completeness only, not a corpus change.
