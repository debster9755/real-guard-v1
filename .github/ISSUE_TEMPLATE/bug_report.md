---
name: Bug report
about: Something in real-guard-v1 does not behave as SPEC.md or the README says it should
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear, concise description of what is wrong.

## Steps to reproduce

1.
2.
3.

Include the exact request (curl command, or a minimal Python snippet using
the `openai` client) and the exact response you got, if applicable. Please
redact any real API key, upstream URL, or personal data before pasting —
this tracker is public.

## Expected behaviour

What SPEC.md, the README, or common sense says should have happened, with a
section reference if you have one (e.g. "SPEC.md §4.3").

## Actual behaviour

What actually happened — full error body / status code / log line, not a
paraphrase.

## Environment

- real-guard-v1 version / commit SHA:
- Deployment mode: `docker compose up` (mock) / `ollama-host` profile / running from source
- OS:
- Python version (if running from source):

## Does this affect the 54-case golden corpus?

- [ ] Yes — one or more corpus cases now behave differently than
      `tests/data/golden_corpus.jsonl` expects (please name the case IDs)
- [ ] No
- [ ] Not sure

## Additional context

Anything else that would help — a policy file you're using (if customised),
whether this only happens under load, whether it's new since a specific
version, etc.
