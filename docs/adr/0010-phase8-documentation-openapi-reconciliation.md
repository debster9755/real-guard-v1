# ADR 0010: Phase 8 — README restructure, OpenAPI reconciliation, and the new documentation set

## Status

Accepted. Implemented and verified end to end: `README.md` restructured to
SPEC.md §18's exact 20-section order with every already-verified Phase 0-7
command/output pair preserved; `docs/architecture.md`, `docs/threat-model.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md` all
newly written; `openapi.json` regenerated from the real running application
for the first time since Phase 0 and a CI-enforced drift check
(`scripts/generate_openapi.py --check`) added so it cannot go stale again;
a README command-extraction test, a link checker, and a placeholder grep now
run in CI alongside the existing contract-validation script.

## Context

PLAN.md §6's Phase 8 section, quoted verbatim:

> **Preconditions** — Phase 7 gate; measurements exist.
> **Tasks** — WS-16; final configuration review; `CHANGELOG.md`.
> **Deliverables** — the complete documentation set; a generated OpenAPI
> document.
> **Automated checks** — README command tests; link check; placeholder grep;
> docs-drift checks.
> **Manual validation** — a colleague follows the quick start on a clean
> machine without asking a question.
> **Exit gate** — every README number traces to `docs/benchmarks.md`; no
> placeholder text remains.

WS-16's acceptance criteria (PLAN.md's WBS section) name the same deliverable
list plus: "every README command is executed by CI (`DOC-004`); every number
in the README traces to `docs/benchmarks.md`; no `TODO`, `TBD` or placeholder
survives."

Before writing anything, the repository was checked for what already existed
versus what this phase still had to build:

- `README.md` already held substantial real, Phase-0-through-7-verified
  content (quick start, all eight approval-workflow scenarios, the
  dashboard walkthrough, rate limiting, observability, Ollama/Docker
  deployment, a benchmarks reference, limitations) but in an order that does
  not match SPEC.md §18's `DOC-001` list, and with several required sections
  (badges, a top-problems-to-controls table, a full 8-endpoint-plus API
  reference table, a policy-YAML walkthrough, a security/privacy section, a
  roadmap, contributing/disclosure links) missing outright.
- None of `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CHANGELOG.md`, `docs/architecture.md`, `docs/threat-model.md` existed
  (confirmed with `ls`, not assumed).
- `openapi.json` still carried its Phase-0 hand-authored content and its own
  `description` field's promise — "In Phase 3+ this file MUST be
  regenerated from the running FastAPI app and diffed against this
  committed copy — a diff fails CI" — had never been carried out through
  Phase 7.
- No README command-extraction test, link checker, or placeholder grep
  existed anywhere in `tests/` (`pyproject.toml`'s `docs` pytest marker was
  already reserved — "README command extraction tests (Phase 8)" — but
  unused).
- `.env.example` and `app/config.py`'s `Settings` class were compared
  field-by-field: no drift found. Every one of the 27 non-derived `Settings`
  fields (`APP_ENV` through `OLLAMA_PREFLIGHT_ENABLED`) already has a
  matching, accurately-commented entry in `.env.example`. Nothing needed
  fixing here — the "final configuration review" task's finding is a clean
  bill, not a silent skip; recorded as such rather than left unstated.

## Decisions

### 1. `openapi.json` becomes a generated artifact, not a hand-authored one — reconciled against the real running app

PLAN.md §12's own documentation-ownership table already settled the target
state: "`openapi.json` | The machine-readable API contract | Hand edits — it
is generated." Its anti-drift automation list names the mechanism: "OpenAPI
diff — regenerates `openapi.json` from the running app and fails if it
differs from the committed file." Phase 8 is the first phase to actually do
this.

**What was found.** Pulling `app.main.create_app().openapi()` from the real,
in-process application and diffing it against the committed `openapi.json`
showed two real differences, not one:

1. **Three extra paths.** The generated document has 11 paths; the
   hand-authored one had 8. The three additions — `POST /dashboard/login`,
   `POST /dashboard/logout`, `POST
   /dashboard/approvals/{approval_id}/decide` — are real, tested,
   documented (README's "Reviewer dashboard" section, present since Phase 4)
   routes that ADR 0006 added for the session-cookie dashboard flow. They
   were never route aliases or duplicates of the 8 canonical
   `SPEC.md §4.1` endpoints — none of them bypasses inspection, policy
   evaluation, or the output guard; `POST
   /dashboard/approvals/{approval_id}/decide` calls the exact same
   `app.approvals.decide_and_resume()` the canonical `POST
   /v1/firewall/approvals/{id}/decision` endpoint does (ADR 0006 §3). But
   `API-001`'s literal text — "These are the only routes the MVP
   exposes" — has read as false since Phase 4 without any ADR saying so.
   This ADR is that record. **Decision:** the three dashboard-support routes
   are correct, intentional, and stay. `SPEC.md` itself is not edited (it is
   the frozen normative contract per this project's governing rules, and
   amending `API-001`'s prose is a bigger, separate judgment call than this
   phase's scope); instead, `scripts/validate_contracts.py`'s openapi check
   now asserts the true shape explicitly — the 8 canonical paths are all
   present, exactly 3 additional dashboard-support paths exist, and nothing
   else does — so a genuinely new, undocumented route would still fail CI.
2. **Cosmetic differences.** Path-parameter names (`{id}` in the hand-
   authored file vs. the real `{transaction_or_request_id}` /
   `{approval_id}` FastAPI infers from the actual handler signatures) and
   the `info.description` field (the hand-authored file's own
   self-referential "MUST be regenerated" sentence, now obsolete). Both
   are cosmetic — no behavioural contract changed — but a byte-for-byte
   diff check does not distinguish cosmetic from substantive drift, which
   is exactly the point of having one.

**Resolution.** `scripts/generate_openapi.py` was added: it imports
`app.main.create_app()` in-process (no server, no port) and either writes
its `.openapi()` output as the canonical `openapi.json` or, with `--check`,
diffs the generated document against the committed one and exits non-zero
with a unified diff on any difference. `openapi.json` was regenerated for
real from the live application (confirmed: `python scripts/generate_openapi.py
--check` now passes) and is wired into CI as a new step alongside the
existing `scripts/validate_contracts.py` job — see the CI change below.
Going forward, `openapi.json` is generated, exactly as PLAN.md §12 always
said it should be; a future route addition that isn't regenerated and
committed now fails CI instead of silently drifting for seven more phases.

### 2. The "top problems and controls" table is sourced from SPEC.md §19.4, not from `PRD-claude.md`

`DOC-001` item 3 asks for "a table mapping each PRD §5 use case to the
control that addresses it and the corpus case that proves it." `PRD-claude.md`
is named throughout `PLAN.md` as an external input document — its own
documentation-ownership table calls it "the original product requirements,
preserved as the historical source" with "edits" listed as what it must not
contain, i.e. it is explicitly *not* a living, in-repository document, and it
is not present anywhere in this repository (confirmed by directory listing —
it never was checked in; only its resolved conclusions, as `PLAN.md` §16's
resolved-decisions table and the `R`-numbered rows in §11, made it into
version control). There is therefore no PRD §5 text in this repository to
build a literal PRD-use-case table from without inventing one, which this
project's standing rule against invented content forbids.

**Decision:** the README's "Top problems and controls" table is built
instead from `SPEC.md §19.4` (threats and controls) cross-referenced against
`tests/data/golden_corpus.jsonl` — the closest in-repository equivalent to
"a real-world problem, the control that addresses it, and the corpus case
that proves it," using only real threat IDs, real policy rule ids, and real
corpus case ids already in this repository. Each row is phrased as a
concrete scenario (matching the spirit of PRD-style use cases, e.g. "a
wire-transfer tool call above the configured threshold") rather than as an
abstract threat-ID label, but the control and the corpus case cited are
exact, verifiable references — nothing is invented, and every corpus case ID
cited actually carries the payload and expected verdict described.

### 3. `docs/architecture.md` and `docs/threat-model.md` are synthesis, not new invention — and say so

Both documents are explicitly framed at the top as derived from, and
subordinate to, `SPEC.md` (`§1.4`/`§2` for architecture, `§19` for the threat
model) and the ADRs — consistent with PLAN.md §12's ownership table
("`docs/architecture.md` | Component internals, data flow, migration paths |
Requirements" and "`docs/threat-model.md` | Assets, boundaries, actors, abuse
cases, controls, residual risk | Implementation detail"). Where SPEC.md is
normative and this repository's other governing rules forbid re-deriving
requirements, these two documents restate and organize already-agreed
content; they do not introduce a single new requirement, control, or residual
risk beyond what SPEC.md §19.4/§19.5 and the nine existing ADRs already
established. `docs/threat-model.md` reproduces Phase 7's four real residual
risks (SPEC.md §19.5) verbatim rather than paraphrasing them, since
paraphrasing a residual-risk statement risks quietly softening or sharpening
its scope.

### 4. `CHANGELOG.md` uses a single `[Unreleased]` section, broken into per-phase subsections, most recent first

Keep a Changelog format (PLAN.md §13: "`CHANGELOG.md` in Keep a Changelog
format") reserves dated `## [x.y.z] - YYYY-MM-DD` headings for actual tagged
releases. `v0.1.0` is Phase 9's own deliverable (PLAN.md §13's Versioning
section: "MVP ships as `v0.1.0`") — nothing has been tagged or released yet,
so writing a `## [0.1.0]` heading now would assert a release that has not
happened. **Decision:** everything shipped so far lives under a single `##
[Unreleased]` heading, broken into `### Phase 7` down to `### Phase 0`
subsections (most recent first, matching Keep a Changelog's own
newest-first convention), each summarizing that phase's real, shipped
changes under standard `Added`/`Changed`/`Fixed` labels where they clarify
anything, with its ADR and short commit SHA cited. This keeps the file
honest about release status while still giving a reviewer the same
phase-by-phase narrative the README's own Status section and the ADRs
already carry, in one place, chronologically ordered.

### 5. The dashboard section ships without a rendered screenshot

`DOC-001` item 11 asks for "screenshot, login, the approve/deny walkthrough."
This environment has no headless-browser or HTML-rendering tool available
(`playwright`, `chromium`, `wkhtmltoimage` and equivalents were checked for
and are not installed, and installing a browser binary was judged out of
scope for a documentation phase). Generating a screenshot image without one
would mean fabricating an image — describing a UI state that was never
actually rendered and captured — which this project's "invent nothing"
discipline forbids as firmly for an image as for a number. **Decision:** the
dashboard section keeps the existing, real, `curl`-captured HTTP
walkthrough (login exchange, the queue page's raw HTML including its CSRF
token, the CSP/security headers, the approve/deny round trip) that Phase 4
already verified end to end, and states plainly, once, that no rendered
screenshot is included because no tool to honestly produce one is available
in this environment — rather than silently omitting the gap or filling it
with an invented image.

### 6. Rate limiting and observability content nest under "API reference" rather than adding new top-level sections

`DOC-001` fixes 20 section headings in order but does not forbid
subsections within them. Rate limiting (a `429` behaviour of `POST
/v1/chat/completions`) and observability (`GET /metrics`, structured logs,
audit export — themselves largely `GET`/CLI surface area adjacent to the
API) do not map cleanly onto any of the other 19 required headings, and
inventing two new top-level sections not in `DOC-001`'s list would be a
larger, unrequested structural deviation than folding them into the
existing "API reference" section as subsections. **Decision:** both remain
full subsections (not shortened or dropped) under "API reference," in the
same place a reader looking for "what happens when I call this endpoint too
often" or "how do I see what happened" would naturally look right after the
endpoint table itself.

### 7. The phase-by-phase "Status" narrative moves to `CHANGELOG.md`; the Hero keeps one short pointer

The pre-Phase-8 README carried a long, valuable "Status" section narrating
what each phase actually shipped. `DOC-001`'s 20-section list has no
"Status" heading, and that narrative is now real content this phase
purpose-built a home for: `CHANGELOG.md`'s per-phase subsections. Repeating
it in full inside the README as well would create exactly the kind of
two-places-that-can-drift problem this project's own anti-drift discipline
exists to avoid. **Decision:** the Hero section keeps one short paragraph
("Phases 0-8 complete; nothing here is aspirational; see `CHANGELOG.md`
for the full phase-by-phase history and `docs/adr/` for the reasoning
behind every decision") and the full narrative lives in `CHANGELOG.md`
alone.

## Verified, not merely asserted

- `DOC-002` (Mermaid diagrams render on GitHub without a plugin): all six
  Mermaid blocks across `README.md` and `docs/architecture.md` (the system
  diagram, both approval-workflow sequence diagrams, the "what it does"
  overview flowchart, and the approval state machine, once each) were
  actually rendered with `npx @mermaid-js/mermaid-cli` (real tool, real
  run, not a manual grammar review substituted for one) — all six produced
  a valid, non-trivial SVG with no syntax error.
- `python scripts/generate_openapi.py --check`: passes against the
  regenerated `openapi.json` (confirms the committed file now matches the
  live application byte-for-byte).
- `python scripts/validate_contracts.py`: all checks pass, including the
  updated openapi-path check (8 canonical + 3 dashboard-support = 11,
  asserted explicitly rather than a bare count).
- `pytest -m "not docker and not ollama"`: **442 passed**, 0 failed (up
  from 394 before this phase — 48 new tests across
  `tests/test_readme_commands.py`, `tests/test_docs_links.py`,
  `tests/test_docs_placeholders.py`, `tests/test_docs_numbers.py`, and
  `tests/test_docs_no_overclaiming.py`). Full suite, every marker, one
  process, both Docker and a real local Ollama available: **451 passed**,
  0 failed, 0 skipped.
- `ruff check .`, `ruff format --check .`, `mypy app` (strict): all clean.
- Every internal Markdown link introduced or preserved in this phase's
  documentation was checked to resolve to a real file/anchor in this
  repository by the new link-checking test — see the completion report.
- A grep for `TODO`, `TBD`, `XXX`, `FIXME`, `<placeholder>` across every
  published Markdown file (`README.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `docs/*.md`) returns nothing — see
  the completion report for the exact command and output.

## Consequences

- `openapi.json` is now a generated artifact with a CI-enforced drift check;
  a future phase that adds, removes, or renames a route without running
  `scripts/generate_openapi.py` fails CI instead of leaving `openapi.json`
  stale for another seven phases.
- `API-001`'s literal text ("These are the only routes the MVP exposes") is
  now known, documented, and explicitly reconciled to be inaccurate as
  written against the three dashboard-support routes — a real, if narrow,
  SPEC-vs-implementation gap that this ADR records rather than silently
  papers over. `SPEC.md` itself is left unedited, consistent with this
  project's rule against changing the frozen contract without a separate,
  explicit decision to do so; a future ADR could formally amend `API-001`'s
  wording if that is ever judged worth doing.
- The README, `docs/architecture.md`, `docs/threat-model.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and
  `CHANGELOG.md` are the complete WS-16 documentation set; nothing named in
  PLAN.md §6 Phase 8 or the WS-16 deliverable list remains unwritten.
- The dashboard section's missing screenshot is a real, named, minor gap —
  not a blocker for this phase's exit gate (which is about README numbers
  tracing to `docs/benchmarks.md` and no placeholder text, neither of which
  a screenshot affects) but worth a human's five minutes with a real
  browser before any public release.
