# GitHub repository metadata (draft — not yet applied)

This file drafts the exact text the actual publication step (Phase 9's
go-ahead, not yet given) would feed to `gh repo create` / `gh repo edit`. It
is not consumed automatically by anything; it exists so the description and
topics can be reviewed before they are ever typed into a real command.
Source: PLAN.md §13, "Public-repository hygiene".

## Description

> Open-source AI Firewall for LLM and agent traffic — inspects, transforms,
> and (where policy requires) holds for human approval every request and
> response passing through an OpenAI-compatible API, with a frozen 54-case
> behavioural test corpus and a full audit trail.

(280 characters including this parenthetical note removed; the line above
alone is 217 characters, within GitHub's description limit.)

## Topics

Exactly the six PLAN.md §13 names, no more, no fewer:

- `ai-security`
- `llm-security`
- `prompt-injection`
- `firewall`
- `fastapi`
- `guardrails`

## Other repository settings named in PLAN.md §13

- **Visibility:** public
- **Licence:** MIT (already present at `LICENSE`, root)
- **Discussions:** off for the MVP
- **Secret scanning:** on
- **Push protection:** on
- **Dependabot:** on for pip, GitHub Actions, and Docker ecosystems
- **Branch protection on `main`:** no direct pushes; PR required; all
  required checks green (`lint`, `types`, `test`, `docker-smoke`, `docs`,
  `security`); conversations resolved; linear history; force-push and
  branch deletion blocked

The exact `gh` commands that would apply these are listed in the calling
report's "Ready for your explicit go-ahead" section — this file is the
reviewable content, not the executable step.
