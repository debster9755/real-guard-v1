---
name: Detector gap
about: An attack, encoding, or evasion technique that real-guard-v1's detectors miss
title: "[DETECTOR GAP] "
labels: detector-gap
assignees: ''
---

## Summary

What kind of payload gets through undetected (or is mis-classified), in one
sentence.

## The payload

The exact input (or output-plane content, if this is a response-side gap)
that should have been caught. If it contains a real secret or real personal
data, replace it with an equivalently-shaped fake value before posting —
this tracker is public. State clearly if you've already done this.

```
<payload here>
```

## Which category should this fall under?

One of: `DIRECT_INJECTION`, `INDIRECT_INJECTION`, `ENCODED_INJECTION`,
`PII_INPUT` / `PII_OUTPUT`, `SECRET_INPUT` / `SECRET_LEAK`,
`OUTPUT_LEAKAGE`, `LEAK_OUTPUT`, `TOOL_ABUSE`, or "not sure — describe it".

## What real-guard-v1 actually did

The verdict, reason codes, and transformation you observed (from the
response body's `firewall` object), or "nothing — it reached the model /
the client unmodified."

## What you expected

The verdict you believe this should have received, and why — reference the
relevant SPEC.md detector requirement (`DET-0xx`) if you know it.

## Proposed corpus case (optional)

This project treats its 54-case golden corpus
(`tests/data/golden_corpus.jsonl`) as the floor, not the ceiling, for attack
recall (PLAN.md §11 R2). If you'd like to propose a new corpus case for
this gap, sketch it here — a maintainer will still need to land it via a
documented ADR (see `CONTRIBUTING.md`), since the corpus is frozen and
schema-validated.

## Environment

- real-guard-v1 version / commit SHA:
- Provider in use: mock / Ollama (`qwen3:8b`) / other OpenAI-compatible upstream
