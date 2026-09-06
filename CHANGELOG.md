# Changelog

All notable changes to this project are documented here, in [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/) format.

**Framing note** (see `docs/adr/0010` decision 4, superseded by
`docs/adr/0013`): `v0.1.0` was tagged and released for real on 2026-09-05
— see [the GitHub release](https://github.com/debster9755/real-guard-v1/releases/tag/v0.1.0).
Everything that had accumulated under `[Unreleased]` through Phase 9 (the
Playwright gap-closure and the dependabot/CI fixes that followed it) is
now filed under the dated `[0.1.0]` heading below, broken into per-phase
subsections ordered most-recent-first. Each subsection cites its ADR
(where one exists) and the short commit SHA that landed it (`git log
--oneline` on `main`).

## [Unreleased]

### `/console` — a React/Next.js reviewer SPA, additive to `/dashboard` (`docs/adr/0014`)

A second, richer reviewer UI over the same backend, explicitly requested by
name. `/dashboard` is untouched — same routes, same templates, same tests,
same `docs/adr/0006` guarantees — and still needs no Node toolchain.

- **Added** `app/console_api.py`: seven JSON routes under `/console/api`
  (`login`, `logout`, `session`, `approvals`, `decisions`,
  `approvals/{id}/decide`, `stats`), registered from `app/main.py` alongside
  `register_dashboard_routes(app)`. Zero new business logic — every route is
  a thin wrapper over an existing `app/approvals.py` / `app/auth.py` call,
  and `/console/api/stats` reshapes the same `CollectorRegistry` that
  `/metrics` serves rather than measuring anything itself. A **separate**
  session cookie, `rg_console_session` at `Path=/console/api`, deliberately
  distinct in both name and path from the dashboard's `rg_session` at
  `Path=/dashboard`, so the two UIs' sessions never interact. `SEC-005`,
  `SEC-006` and `SEC-007` are enforced identically to the dashboard's, by
  the same unmodified `app/session.py` primitives.
- **Added** `web/`: a Next.js 15 App Router SPA (TypeScript, Tailwind,
  `recharts`) with `output: 'export'`. Four screens — sign-in, overview with
  two charts, the approval queue with a review modal, and decision history.
  `basePath: '/console'` with the exported `out/` mounted at `/console`;
  the no-basePath alternative emits root-absolute `/_next/…` asset URLs that
  a `/console` mount does not cover, which was verified by building both and
  curling the result rather than reasoned about. The six UI primitives
  (Button, Card/StatCard, Badge, Table, Modal, Tabs) are hand-rolled local
  components in shadcn's composition spirit, with no Radix dependency tree,
  in this project's own indigo-on-slate palette with real light and dark
  themes.
- **Found and fixed** a real CSP defect before it shipped, of exactly the
  class `docs/adr/0012` caught once already: Next.js's static export inlines
  its bootstrap payload as `<script>` blocks — **40 of them across 6
  documents** — every one of which `app/main.py`'s
  `Content-Security-Policy: default-src 'self'` (`SEC-008`, no
  `unsafe-inline`) refuses in a real browser, rendering a blank page while
  every `curl`/`TestClient` check kept passing.
  `web/scripts/externalize-inline.mjs` rewrites them into real same-origin
  files at build time and **exits non-zero if any survives**, so a future
  Next upgrade fails the build rather than shipping a page the browser will
  not run. The CSP header itself was not weakened.
- **Added** `tests/test_console_api.py` (34 tests, plain `TestClient`) and
  `tests/test_console_browser.py` (2 tests, the existing `browser` marker,
  `docs/adr/0012`'s pattern) — a real `uvicorn` process and a real Chromium
  driven through sign-in, the queue, and an approve that resumes a real held
  request, asserting zero `securitypolicyviolation` events fired.
- **Added** 5 real screenshots under `docs/screenshots/console-*.png`,
  captured by that browser run, inspected rather than merely confirmed to
  exist. Two real defects were found by looking at them and are fixed here:
  the charts rendered empty axes because `recharts` animates bars up from
  zero width (now `isAnimationActive={false}`, with a test asserting a bar
  has non-zero width), and the queue table overflowed its container (now
  relative "4m ago" / "in 59m" timestamps, with the exact values in
  `title` attributes and in the review modal).
- **Changed** `Dockerfile`: one `web-builder` stage on `node:22-slim`,
  pinned by digest the same way the Python base already is, copying only
  `/web/out` into the runtime stage. Measured: a cold no-cache build goes
  from **17.7s to 27.8s** (+10.1s) and the image from **341MB to 345MB**
  (+4MB). No Node, `npm` or `node_modules` exists in the runtime image —
  verified with `command -v node` inside the running container.
- **Changed** `.github/workflows/ci.yml`: a Node 22 setup plus
  `npm ci && npm run lint && npm run build` step **inside the existing
  "lint, type-check, test" job**, not a new job — branch protection requires
  that exact context name, and a separate job would be reported but not
  required, letting a frontend break merge.
- **Changed** `openapi.json` (regenerated by `scripts/generate_openapi.py`,
  11 paths to 18) and `scripts/validate_contracts.py`'s documented-path
  allowlist. The console routes are published in the OpenAPI document for
  the same reason the `/dashboard` routes already are. The addition is
  strictly additive and was verified as such: every pre-existing path's
  spec, and every component schema, is byte-identical — `/v1/firewall/*`,
  `/healthz`, `/readyz`, `/metrics` and `/dashboard` are unchanged, and the
  54-case corpus is untouched. `validate_contracts.py` failing on the new
  routes on its first run is that check working as designed; the allowlist
  was extended deliberately, exactly as ADR 0006 extended it for the
  dashboard.
- **Changed** `.dockerignore` and `.gitignore` to exclude
  `web/node_modules`, `web/.next` and `web/out`. `node_modules` is never
  committed and never enters the Docker build context; the `web-builder`
  stage runs its own `npm ci` from the committed lockfile.
- **Known limitation, named rather than omitted:** the `Dockerfile` cannot
  skip its `web-builder` stage conditionally in this MVP, so building the
  image from source now requires Node 22 even for an operator who only wants
  `/dashboard`. Running a pre-built image requires no Node at all. The
  review modal is also not a focus trap (Escape closes it; focus is not
  confined to the dialog).

## [0.1.0] - 2026-09-05

### Phase 9 publication (`docs/adr/0013`)

The repository was created, pushed, protected, tagged, and released for
real, following the explicit go-ahead ("proceed with phase 9").

- **Created** `github.com/debster9755/real-guard-v1` (public), with the
  description and six topics drafted in `docs/release/repo-metadata.md`.
- **Enabled** secret scanning, push protection, vulnerability alerts, and
  automated (Dependabot) security fixes; confirmed Discussions off, per
  `PLAN.md` §13.
- **Fixed two genuine bugs found only by the repository's first-ever real
  CI run against its first-ever genuinely fresh checkout** — a
  `gitleaks/gitleaks-action@v2` input-schema mismatch (its `action.yml`
  accepts no custom inputs, so this workflow's `--baseline-path` was
  silently ignored, and its default push-event diff is itself invalid on
  a repository's first push) and a latent `tests/test_cli.py` isolation
  bug (a test exported audit rows from the developer machine's real,
  gitignored default database rather than the tmp-path rows it had just
  written, always passing locally only because 93 leftover rows had
  quietly accumulated there over months). Full account, including the
  real CI job names and both fixes, in `docs/adr/0013`.
- **Applied branch protection** to `main`: both real CI jobs (`lint,
  type-check, test`; `security (pip-audit, Trivy, gitleaks)`) required
  and strict, 1 required approving review, `enforce_admins`, linear
  history, no force-push or deletion.
- **Tagged and released** `v0.1.0` — [github.com/debster9755/real-guard-v1/releases/tag/v0.1.0](https://github.com/debster9755/real-guard-v1/releases/tag/v0.1.0).
- **Ran the real fresh-clone exit gate** for the first time against the
  actual public URL: `docker compose up --build -d` against a genuine
  `git clone`, `/healthz` and `/readyz` both `200`, `docker compose down`
  clean.

### Dependabot configuration — closing the last named Phase 9 gap

- **Added** `.github/dependabot.yml`, covering the three ecosystems named
  in `PLAN.md` §13 ("Dependabot: on for pip, GitHub Actions, and Docker
  ecosystems"): `pip` (root `pyproject.toml`), `github-actions` (workflows
  under `.github/workflows/`), and `docker` (the root `Dockerfile`). All
  three on a weekly schedule, `open-pull-requests-limit: 10`, distinct
  commit-message prefixes and labels per ecosystem. This was the one gap
  flagged, but not yet built, by the Phase 9 preparation report
  (`docs/adr/0011`); it is committed here, before repository creation, so
  it is part of the very first push.

### Playwright browser verification — closing a Phase 9 gap (`docs/adr/0012`)

Additional, explicitly-authorized verification work closing the one named
gap `docs/adr/0011`'s own "Manual validation" line and `docs/adr/0010`
decision 5 both left open: no headless-browser tooling was available to
actually render and verify the reviewer dashboard. **Not** the withheld
publication step — no repository created, no push, no tag; `git remote -v`
and `git tag` remain empty.

- **Added** `playwright==1.55.0` (pinned) to `pyproject.toml`'s dev
  dependencies, a real local Chromium (`playwright install chromium`), and
  a `browser` pytest marker mirroring the `docker`/`ollama` skip-clean
  contract exactly — both its skip and pass branches verified for real
  (forced-unavailable → skipped; normal → passed).
- **Found and fixed** a real, previously-undetected CSP defect: the
  vendored `htmx.min.js` (1.9.12) injects an inline `<style>` block by
  default, silently refused by `app/main.py`'s strict
  `Content-Security-Policy: default-src 'self'` header — invisible to
  every prior `TestClient`/`curl`-driven check, caught only by a real
  browser's own CSP enforcement. Fixed with one line in
  `app/templates/dashboard/base.html` (htmx's own
  `<meta name="htmx-config">` mechanism, disabling the one unused feature
  responsible) — no CSP loosening, no functional change.
- **Added** `tests/test_dashboard_browser.py` (real login → CSP → HTMX
  DOM-swap → screenshot flow, one real `uvicorn` + one real Chromium
  session) and `tests/test_mermaid_rendering_browser.py` (a bonus: all 6
  README/`docs/architecture.md` Mermaid diagrams re-verified by actually
  rendering them with the real Mermaid JS library in a real browser, a
  meaningfully different check than the existing `mmdc` syntax-only
  validation).
- **Added** `docs/screenshots/` — 3 real dashboard PNGs (login, queue,
  post-decision) and 6 real Mermaid-diagram PNGs, all actually opened and
  inspected, not merely confirmed to exist.
- **Updated** the README's "Dashboard" and "Limitations" sections to
  reference the real screenshots instead of the prior honest "no rendered
  screenshot" gap language.

### Phase 9 — release preparation (`docs/adr/0011`)

Preparation only — **not** the publication step. `v0.1.0` is not tagged,
no GitHub repository exists yet, and this entry does not claim otherwise;
see `docs/adr/0011` for the full account and the completion report for
what explicitly still requires the user's separate go-ahead.

- **Added** a real full-history `gitleaks` scan (tool installed for this
  phase): 16 findings, each individually confirmed as a test fixture or
  documentation example, none a real credential. Added
  `docs/security/gitleaks-baseline.json` (gitleaks' own baseline
  mechanism) so these reviewed findings don't re-flag on every future
  scan, and a `gitleaks` step to `.github/workflows/ci.yml`'s `security`
  job — closing the gap ADR 0008 explicitly deferred to this phase.
- **Fixed** a real, pre-existing invalid-YAML defect in
  `.github/workflows/ci.yml` (an unquoted step name containing a bare
  `": "` sequence) that would have broken the `lint-type-test` job the
  first time a real GitHub Actions runner ever parsed it — never caught
  before because this repository's CI has never actually run on GitHub.
- **Fixed** `docs/threat-model.md` THR-016, which claimed a "pinned
  hashes" control that was never implemented; corrected to state what
  actually exists (pinned version ranges) and named the gap as a residual
  risk instead.
- **Added** `.github/ISSUE_TEMPLATE/{bug_report,detector_gap,false_positive}.md`
  and `.github/PULL_REQUEST_TEMPLATE.md` (with a corpus-impact checkbox) —
  WS-18 deliverables, previously unbuilt.
- **Added** drafted, unpublished release content for review:
  `docs/release/repo-metadata.md`, `docs/release/v0.1.0-notes.md`,
  `docs/release/v0.1.0-tag-message.txt`.
- **Re-verified fresh**, this phase, not cited from earlier reports:
  `pip-audit` (zero vulnerabilities, production dependency set), Ruff,
  `ruff format --check`, mypy strict, `scripts/validate_contracts.py`, the
  full pytest suite (451 passed), the coverage gate (93.4% line / 81.8%
  branch), a live `docker compose up --build` plus an unmodified `openai`
  client call against it, all 8 canonical endpoints, the full
  ALLOW/DENY/NEED_APPROVAL lifecycle including a real process
  restart-and-resume with idempotent replay, both dashboard approve and
  deny paths, and all 6 Mermaid diagrams rendered via `mmdc`.
- **Confirmed a known, still-open gap, not a new one**: the
  `test_benign_request_allowed_by_real_model` Ollama live test remains
  flaky in this environment (real `qwen3:8b` "thinking" latency
  occasionally exceeding the test's own timeout) — the same failure mode
  ADR 0008 and ADR 0009 already documented, characterized further here
  with a direct-Ollama timing measurement (132.35s for the exact failing
  prompt), not fixed.
- **Decided**, and documented as a judgment call rather than either
  silently expanding or silently skipping: dependency hash-pinning stays
  an explicit, named residual risk past `v0.1.0` — §15/§13's literal text
  does not make it a Phase 9 blocker, only "zero high/critical
  vulnerabilities" is.

### Phase 7 — benchmarking, coverage gate, adversarial review (`b654ac9`, `docs/adr/0009`)

- **Added** `scripts/benchmark.py`, generating `docs/benchmarks.md` from a
  real 1,000-request-per-shape run against a real `uvicorn` process in mock
  mode (PLAN.md §10.1 methodology): firewall-added p50/p95/p99 latency for
  a benign `ALLOW`, a `DENY`, a `REDACT`-transformed `ALLOW`, and a
  `NEED_APPROVAL` creation, plus throughput and an estimated-cost-avoided
  figure, explicitly labelled as a derived estimate rather than an
  observation.
- **Added** a CI-enforced coverage gate (`scripts/check_coverage_gates.py`)
  — ≥ 85% line, ≥ 75% branch (PLAN.md §10.2 G14).
- **Added** `tests/test_adversarial.py` (16 tests) pinning the outcome of
  thirteen deliberate detector-evasion attempts: seven confirmed real gaps
  now fixed (Unicode confusables and invisible characters missing from the
  normalizer's tables; an SSN/IBAN separator or case variant; an AWS STS
  temporary-key prefix; a SQL-comment-prefixed destructive statement; a
  whitespace-doubled shell command), four confirmed real gaps left open and
  documented as residual risks (SPEC.md §19.5).
- **Added** a Hypothesis property test in `tests/test_orchestrator.py`
  covering SPEC.md TST-020 (no detector exceeds its deadline on adversarial
  input).
- **Changed** `tests/test_normalizer.py`/`tests/test_orchestrator.py`'s
  Hypothesis `max_examples`, raised across every property test this phase.

### Phase 6 — rate limiting, metrics, structured audit, security scanning (`a6139de`, `docs/adr/0008`)

- **Added** a persisted, per-identity fixed-window rate limiter
  (`app/ratelimit.py`) — `429 RATE_LIMITED` with a genuine `Retry-After`,
  scoped and configured by `policies/default_policy.yaml`'s
  `rate_limit_default` rule.
- **Added** `GET /metrics` — Prometheus text exposition, 25 metrics
  matching SPEC.md §13.1's catalogue exactly, gated by
  `METRICS_REQUIRE_AUTH`.
- **Added** structured JSON logging (`app/logging_config.py`) through a
  code-enforced field allowlist of exactly SPEC.md §12.2's 27 fields —
  never request/response content, a key, a session cookie, or a CSRF
  token.
- **Added** a `decision` audit event for every verdict (`ALLOW`, `DENY`,
  and `NEED_APPROVAL`), not only `NEED_APPROVAL` (`PRV-009`).
- **Added** `python -m app.cli export-audit` (JSONL export, `--since`/
  `--until`).
- **Added** `pip-audit` and Trivy scanning to CI (`.github/workflows/ci.yml`'s
  `security` job); found and fixed a Dockerfile issue (removed `pip`'s own
  vendored `msgpack`/`setuptools` copies from the runtime image) during a
  real Trivy scan against the built image.

### Phase 5 — Ollama compose profile, startup preflight, Docker deployment (`5603705`, `docs/adr/0007`)

- **Added** a real multi-stage `Dockerfile` (non-root, fixed UID `10001`,
  pinned `python:3.12-slim` base-image digest, `HEALTHCHECK` against
  `/healthz`) and `docker-compose.yml` with `mock` (default) and
  `ollama-host` profiles.
- **Added** a startup preflight against a host Ollama's `GET /api/tags`,
  feeding `/readyz`'s `provider` field.
- **Added** `tests/test_ollama_live.py` (4 tests, `ollama` marker,
  self-skips when no local `qwen3:8b` is reachable) and
  `tests/test_docker_smoke.py` (5 tests, `docker` marker) driving the real
  built image over real HTTP.
- **Fixed** a real Docker Compose behaviour: SPEC.md's own example command
  (`docker compose --profile ollama-host up`, no service name) would also
  start the profile-less `firewall` (mock) service and collide on port
  8000 — documented and worked around with an explicit service name in the
  README and this ADR, rather than silently assumed correct.

### Phase 4 — reviewer dashboard, session-cookie auth, CSRF, security headers (`6ec5aad`, `docs/adr/0006`)

- **Added** a server-rendered reviewer dashboard at `/dashboard` — login,
  queue with a status filter, inline approve/deny — with no build step, no
  JavaScript framework, and no third-party CDN dependency (HTMX and a small
  `json-enc` extension vendored under `app/static/vendor/`).
- **Added** session-cookie authentication for reviewers (`SEC-005`) and
  CSRF protection on every state-changing dashboard request (`SEC-007`).
- **Added** the four mandatory security headers system-wide (`SEC-008`):
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Content-Security-Policy` (no `unsafe-inline`); `Strict-Transport-Security`
  added in production only.
- **Fixed** a CSP-vs-inline-handler defect found while verifying the
  templates against the `Content-Security-Policy` header's real semantics
  — inline `onchange` handlers and inline `style` attributes moved into
  vendored CSS classes.

### Phase 3 — output guard, tool-call inspection, generic provider adapter (`cddc2d3`, `docs/adr/0005`)

- **Added** the output guard (`app/outputguard.py`) — PII, secrets,
  system-prompt-leak, and canary-token detection on every response, before
  the client ever sees it, on every return path including the
  approval-resume path (`SYS-014`, one shared function).
- **Added** tool-call inspection (`app/detectors/tool_calls.py`) — an
  allowlist, high-value-transfer, destructive-SQL, and destructive-shell
  rule against parsed `tools[]`/`tool_calls[]`.
- **Added** a real generic OpenAI-compatible provider adapter
  (`app/providers/openai_compatible.py`) — optional; mock mode remains the
  default.
- **Result**: all 54 golden-corpus cases now pass end to end for the first
  time (the `OUTPUT_LEAKAGE`, `LEAK_OUTPUT`, and `TOOL_ABUSE` buckets ADR
  0003 had deferred).

### Approval workflow MVP — `NEED_APPROVAL` is real, not a stub (`37dcd6f`, `docs/adr/0004`)

- **Added**, pulled forward from its originally planned phase at the
  user's direction: a real, persisted `NEED_APPROVAL` workflow — durable
  approval storage before the `202` response is sent (`APR-005`), the full
  8-state approval state machine with restart recovery, idempotency keys,
  replay prevention, exactly-once resume, and invalidation when material
  tool-call arguments change between creation and decision.
- **Added** the confused-deputy control: a service key cannot decide its
  own or any approval (`SEC-006`); a reviewer key cannot self-approve a
  request it created (`APR-009`).

### Phase 2 — input inspection and policy decisions (`d90a3c0`, `docs/adr/0001`, `docs/adr/0002`, `docs/adr/0003`)

- **Added** full input-plane inspection: prompt injection, jailbreak,
  indirect injection, encoded-payload detection, and inbound PII/secret
  detection, wired into the deterministic policy engine.
- **Added** policy-driven `ALLOW`/`DENY` decisions and `REDACT`
  transformation.
- **Fixed** several gaps found while completing `default_policy.yaml`
  beyond SPEC.md §7.1's excerpt (`docs/adr/0001`): missing rules for
  `JAILBREAK`, `INDIRECT_INJECTION`, `ENCODED_PAYLOAD`, and inbound
  `SECRET_DETECTED`; a rule that tried to emit two different reason codes,
  which `POL-019` forbids.
- **Decided** (`docs/adr/0002`) that the `ALLOW` response body must be the
  OpenAI chat-completion shape at the top level, for real `openai` SDK
  client compatibility.

### Phase 1 — repository foundation and deterministic mock path (`1aa3edd`)

- **Added** the FastAPI gateway skeleton, the deterministic `MockProvider`
  (no network, no API key required), and the project's dev tooling
  baseline (Ruff, mypy strict on `app/`, pytest).

### Phase 0 — freeze contracts: policy schema, corpus, OpenAPI (`5105006`, `69e01bc`)

- **Added** the frozen artifacts every later phase builds against: the
  policy JSON Schema (`policies/policy.schema.json`), the hand-authored
  `openapi.json` design target, and the 54-case golden corpus
  (`tests/data/golden_corpus.jsonl`).
- **Added** a realism-review addendum (`69e01bc`) closing a gap in the
  topics policy found while re-reading the frozen contracts before Phase 1
  began.

---

## Phase 8 — README, demonstrations, and release hardening (`docs/adr/0010`)

- **Added** `docs/architecture.md`, `docs/threat-model.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, this `CHANGELOG.md`.
- **Changed** `README.md`, restructured to SPEC.md §18's exact 20-section
  order; every already-verified Phase 0-7 command/output pair preserved,
  reorganized rather than rewritten.
- **Changed** `openapi.json` — regenerated from the real running
  application for the first time since Phase 0 (previously hand-authored
  and stale by three routes; see `docs/adr/0010` decision 1).
- **Added** `scripts/generate_openapi.py` (`--check` mode is the new
  OpenAPI-drift CI check named in `PLAN.md` §12's anti-drift automation).
- **Added** a README command-extraction test, an internal-link checker, and
  a placeholder grep, wired into CI alongside the existing
  `scripts/validate_contracts.py` job.
- This phase's own commit and exact command output are recorded in its
  completion report, not restated here to avoid the two drifting apart —
  see `git log` for the commit this entry corresponds to once committed.
