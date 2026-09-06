# ADR 0013: Phase 9 publication — real-guard-v1 goes public

## Status

Accepted. Implemented and verified end to end: the repository was created,
pushed, protected, tagged, and released for real. This is the one ADR in
this project's history that records an actually-executed, irreversible
publication, not a drafted or withheld one.

**Real repository URL:** https://github.com/debster9755/real-guard-v1
**Real release URL:** https://github.com/debster9755/real-guard-v1/releases/tag/v0.1.0

## Context

Every prior phase (0 through the ADR 0012 Playwright gap-closure) explicitly
withheld the one step this project's governing instructions gated on a
separate, explicit go-ahead: creating the real GitHub repository and
pushing. `docs/release/repo-metadata.md`, `docs/release/v0.1.0-tag-message.txt`,
and `docs/release/v0.1.0-notes.md` were drafted content, reviewed but never
applied; `git remote -v` and `git tag` were confirmed empty at the start of
every phase including this one's own pre-flight.

The user was asked by name which of "all of it, a subset, or ... first
draft the missing dependabot.yml" they wanted, and replied "proceed with
phase 9" — the specific, separate authorization this project's own rules
required before any repository creation or push. This ADR documents that
authorized execution.

## Decision

Publish `real-guard-v1` to `github.com/debster9755/real-guard-v1` following
PLAN.md §13 exactly: public visibility, MIT licence (already present),
Discussions off, secret scanning + push protection + vulnerability alerts +
Dependabot security fixes on, Dependabot version updates for pip/
github-actions/docker, branch protection on `main`, tag `v0.1.0`, and a
GitHub release — in the safe order the calling task specified, verifying
each step's real output before the next, with an explicit hard-stop
condition on a red first CI run unless the cause was a genuine, narrow,
safe fix.

### Gap closed before publication: `.github/dependabot.yml`

The Phase 9 preparation report (ADR 0011) flagged this as drafted-but-not-
built. Added it (commit `710be97`) before repository creation, covering
exactly the three ecosystems PLAN.md §13 names — `pip` (root
`pyproject.toml`), `github-actions` (`.github/workflows/*.yml`), and
`docker` (root `Dockerfile`) — each weekly, `open-pull-requests-limit: 10`,
with distinct commit-message prefixes and labels. Validated as well-formed
YAML with the expected structure before committing. Landed in the very
first push, as intended.

### The real repository

Created via `gh repo create debster9755/real-guard-v1 --public --source=.
--remote=origin` with the exact description from `docs/release/repo-
metadata.md`; topics added in one `gh repo edit` call
(`ai-security`, `llm-security`, `prompt-injection`, `firewall`, `fastapi`,
`guardrails`). Both confirmed applied via a fresh `gh repo view --json
description,repositoryTopics,url`.

### Security posture

`gh api -X PATCH .../security_and_analysis` (explicitly enabling secret
scanning + push protection) returned `422 Invalid security_and_analysis
payload` — not a real failure: a follow-up `GET repos/.../` showed both
were already `"enabled"`, GitHub's current default for new public
repositories on this account tier, so there was nothing left for the PATCH
to change. `PUT .../vulnerability-alerts` and `PUT .../automated-security-
fixes` both returned `204 No Content`. `gh repo view --json
hasDiscussionsEnabled` confirmed `false` (PLAN.md §13's "Discussions off
for the MVP"), matching GitHub's default with no action needed.

### The first real CI run — red, with two genuine, narrow fixes

The push (`git push -u origin main`, 15 commits) triggered this workflow's
first-ever execution on a real GitHub-hosted runner, and this repository's
first-ever genuinely fresh checkout. Both jobs' **real** names, as GitHub
actually reported them (confirmed via `gh api .../commits/main/check-runs`,
not assumed from the workflow file's job ids):

- `lint, type-check, test`
- `security (pip-audit, Trivy, gitleaks)`

The first run (`33980576710`) failed both jobs:

**1. `security` job — `gitleaks (full-history secret scan)` step.**
`gitleaks/gitleaks-action@v2`'s real `action.yml` (fetched directly from
`github.com/gitleaks/gitleaks-action` to confirm, not guessed) declares no
`inputs:` at all. The workflow's `args: detect --source . -v --baseline-
path ...` was silently ignored (`Unexpected input(s) 'args', valid inputs
are ['']`), so the action fell back to its own default push-event
before/after diff — which is itself invalid on a repository's first-ever
push: `fatal: ambiguous argument '<root-commit>^..<head>': unknown
revision` (the root commit has no parent to diff from). No static YAML
parse could have caught either problem; both are runtime facts about a
third-party action's real schema and a real push event's shape.

*Fix (commit `2f450e3`):* replaced the action with a direct, pinned
download of the real `gitleaks` 8.30.1 Linux x64 release binary (the same
version this project verifies with locally; asset filename confirmed via
`gh api repos/gitleaks/gitleaks/releases/tags/v8.30.1` before writing the
URL), running the exact full-history, baseline-checked command already
verified throughout Phase 9: `gitleaks detect --source . -v --baseline-
path docs/security/gitleaks-baseline.json`.

**2. `lint, type-check, test` job — `pytest with coverage` step.**
`tests/test_cli.py::test_cli_main_writes_jsonl_to_stdout` writes sample
audit events into its own isolated `tmp_path` SQLite engine, then calls
`main(["export-audit", "--format", "jsonl"])` — but `app/cli.py`'s `main()`
builds a *separate* engine from `load_settings().DATABASE_URL`, which this
test never overrides (unlike every test using the `client`/`client_factory`
fixture in `tests/conftest.py`, which does monkeypatch it). Settings'
real default, `sqlite:///./data/realguard.db`, is gitignored and had
silently accumulated 93 leftover rows from months of local `pytest`/
`uvicorn` runs on the development machine — enough to satisfy `len(lines)
>= 2` regardless of what the test itself wrote. This is not a sandbox-vs-
runner environment quirk in the usual sense; it is a genuine, pre-existing
test-isolation defect that had always been masked by every local run this
repository had ever had, surfaced for the first time by a truly fresh
checkout (CI's, for the first time in this project's history).

*Fix (commit `2f450e3`):* monkeypatch `DATABASE_URL` to the same
`tmp_path` SQLite file the test's own `_engine(tmp_path)` already writes
to, before calling `main()`. Verified genuinely fixed, not incidentally:
moved `data/realguard.db` out of the way locally (simulating a fresh
checkout) and reran `tests/test_cli.py` alone — all 5 tests passed on
their own merits with zero leftover state present.

Both fixes are narrow, targeted to the exact broken step/test — no check
was disabled, no assertion loosened, no scope creep into unrelated files.
Re-verified before the second push: `ruff check .` clean, `mypy app` clean
(42 files), `scripts/validate_contracts.py` all pass, `ci.yml` re-parses as
valid YAML, full local `pytest` 456 passed / 1 failed (unrelated — see
below) / 2 warnings.

The second run (`33981182654`), after the fix, passed both jobs cleanly:
`lint, type-check, test` in 1m44s, `security (pip-audit, Trivy, gitleaks)`
in 1m7s — confirmed via `gh run watch --exit-status` and cross-checked
against `gh api .../commits/main/check-runs`.

**Noted, not fixed (out of CI's path):** `tests/test_ollama_live.py::
test_benign_request_allowed_by_real_model` failed twice locally in this
session with `UpstreamTimeoutError` against this sandbox's own real local
Ollama server — a live-model timeout flake specific to this machine's
Ollama instance, not a code defect (the same test suite passed 457/457
including this exact test in the pre-flight run before any changes in this
phase). It self-skips cleanly on the actual GitHub-hosted CI runner (no
Ollama there), per this workflow's own documented contract, and both real
CI runs above confirm CI is unaffected.

### Branch protection

Applied to `main` via `gh api -X PUT .../branches/main/protection` with a
JSON body (the `-f`/`-F` flag syntax does not nest JSON objects the way an
`--input` file does — the first attempt with `-f required_status_checks='{...}'`
was rejected by GitHub's schema validator as a string where an object was
required):

- `required_status_checks`: `strict: true`, contexts = the two real job
  names above
- `enforce_admins: true`
- `required_pull_request_reviews.required_approving_review_count: 1`
- `restrictions: null`
- `required_linear_history: true`
- `allow_force_pushes: false`, `allow_deletions: false`

Verified applied as intended via a fresh `GET .../branches/main/protection`.

### Tag and release

`git tag -a v0.1.0 -F docs/release/v0.1.0-tag-message.txt` (the drafted
message, used verbatim), pushed. `gh release create v0.1.0 --notes-file
docs/release/v0.1.0-notes.md` (the drafted notes, used verbatim) —
release live at the URL above.

### Fresh-clone exit gate — the real one, for the first time

`git clone https://github.com/debster9755/real-guard-v1
/tmp/rg-fresh-clone-real`, `docker compose up --build -d`: image built
clean, container started. `curl http://localhost:8000/healthz` →
`{"status":"ok"}` (200). `curl http://localhost:8000/readyz` →
`{"ready":true,"mode":"mock","dependencies":{"database":"ok","policy":"ok","provider":"ok"}}`
(200). `docker compose down` clean; `/tmp/rg-fresh-clone-real` removed
afterward.

### Manual/mechanical README verification

Six fenced ` ```mermaid ` blocks confirmed present verbatim in the real
published files: 4 in `README.md` (lines 70, 150, 226, 254) + 2 in
`docs/architecture.md` — matching ADR 0012's "all 6" exactly, fetched
directly from `raw.githubusercontent.com/debster9755/real-guard-v1/main/`
(not the local working tree) via `curl`, both returning HTTP 200 with the
same counts as the local files. A human visual check of actual GitHub
rendering is the honest next step beyond this mechanical check; the direct
URL is https://github.com/debster9755/real-guard-v1.

## Consequences

- `real-guard-v1` is now real, public, and irreversibly published — a
  fact, not a plan, for the first time in this project's history.
- Dependabot is active immediately: several `deps(pip)` PRs opened
  against the *pre-fix* CI configuration within minutes of the first push
  and failed CI (inheriting the two bugs this ADR fixes) — expected and
  harmless; a future rebase or Dependabot's own automatic update will pick
  up the fixed workflow. Not addressed further by this ADR; the user can
  triage those PRs directly.
- Branch protection now requires a PR + 1 approving review + both real CI
  checks green before any change lands on `main`, including from the
  publishing session itself (`enforce_admins: true`) — Step 11's
  documentation update must go through a PR, not a direct push, as a
  direct consequence of this ADR's own decision.
- The gitleaks step no longer depends on a third-party action's default
  (and, for this repository's shape, broken) behavior; it now runs the
  exact pinned binary and command this project has verified locally
  throughout Phase 9, with no loss of coverage.
- `tests/test_cli.py::test_cli_main_writes_jsonl_to_stdout` is now a
  genuine, isolated test of the code path it claims to test, independent
  of any developer machine's local state.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
