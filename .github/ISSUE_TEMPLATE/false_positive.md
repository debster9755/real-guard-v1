---
name: False positive
about: Legitimate, benign traffic was denied, redacted, or held for approval incorrectly
title: "[FALSE POSITIVE] "
labels: false-positive
assignees: ''
---

## Summary

What legitimate request or response got the wrong verdict, in one sentence.

## The payload

The exact input (or output-plane content) that was wrongly flagged. If it
contains real personal data, a real secret, or anything sensitive, replace
it with an equivalently-shaped fake value before posting — this tracker is
public. State clearly if you've already done this.

```
<payload here>
```

## What real-guard-v1 did

The verdict, reason codes, policy hits, and transformation from the
response body's `firewall` object (or the dashboard's approval-queue entry,
if this produced a `NEED_APPROVAL`).

## Why this is a false positive

Explain why this content is benign — domain context the detectors can't be
expected to know (e.g. legitimate technical vocabulary that resembles an
injection pattern, a genuinely low-value tool call flagged as high-value,
etc.).

## Does this affect the 54-case golden corpus?

- [ ] Yes — this is the same shape as an existing benign corpus case
      (please name the case ID) that is now failing
- [ ] No — this is a new benign shape not currently represented in the
      corpus
- [ ] Not sure

## Suggested policy or detector change (optional)

If you have a concrete suggestion — a policy rule adjustment, an allowlist
entry, a detector threshold — describe it here. Note that any change
affecting the frozen corpus or the policy schema needs a documented ADR
(see `CONTRIBUTING.md`), not a silent edit.

## Environment

- real-guard-v1 version / commit SHA:
- Deployment mode: `docker compose up` (mock) / `ollama-host` profile / running from source
- Policy file in use: default (`policies/default_policy.yaml`) / custom (attach or describe)
