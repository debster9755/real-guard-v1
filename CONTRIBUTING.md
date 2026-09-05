# Contributing

This describes how this repository has actually been built through Phase 8
— the real, practiced discipline across ten ADRs — not an idealized process
written in the abstract.

## Governing documents, in order of authority

1. [`SPEC.md`](SPEC.md) — the normative contract. Requirement IDs, API
   shapes, the policy schema, the approval state machine, the error
   taxonomy. Where anything disagrees with `SPEC.md`, `SPEC.md` wins.
2. [`PLAN.md`](PLAN.md) — build sequencing, workstream breakdown, phase
   gates, and §16's resolved decisions.
3. [`docs/adr/`](docs/adr/) — every deviation from, or completion of, the
   literal `SPEC.md`/`PLAN.md` text, with the reasoning and what was
   verified.

Read the relevant sections of the first two before touching code that
implements them. Do not re-derive requirements, re-open a decision already
resolved in `PLAN.md` §16, or change the API, the policy schema, the
verdict names, or the frozen 54-case corpus
(`tests/data/golden_corpus.jsonl`) without an explicit, documented ADR
saying what changed and why.

## Development setup

The full setup and first-run walkthrough already lives in
[`README.md`](README.md)'s "Quick start" section — this document points
there rather than duplicating it, so the two can never silently drift
apart. In short: a Python 3.12 virtualenv, `pip install -e ".[dev]"`, and
`uvicorn app.main:app` gets you a running instance with zero configuration
(mock mode, no API key or model required).

## Running the test suite

```bash
ruff check .            # lint
ruff format --check .   # formatting
mypy app                # strict type check on app/ (relaxed on tests/)
pytest                  # full suite
pytest -m "not docker and not ollama"   # skip the two environment-dependent suites
python scripts/validate_contracts.py    # policy schema + corpus + OpenAPI consistency
python scripts/generate_openapi.py --check   # openapi.json matches the running app
```

`tests/test_docker_smoke.py` (marker `docker`) needs a running Docker
daemon; `tests/test_ollama_live.py` (marker `ollama`) needs a local Ollama
with `qwen3:8b` pulled. Both self-skip — reported by pytest as skipped, not
failed — when their dependency isn't reachable, so a normal `pytest` run
stays green on a machine with neither. See `README.md`'s "Testing" section
for the exact, currently-passing counts and the one known flake
(`tests/test_ollama_live.py::test_benign_request_allowed_by_real_model`,
documented there rather than hidden).

## Coding conventions actually used in this codebase

- **Ruff** (`select = ["E", "F", "I", "UP", "B", "SIM", "C4", "S"]`,
  `pyproject.toml`) and **mypy --strict on `app/`** are both blocking CI
  gates, not advisory. `tests/` is intentionally relaxed
  (`ignore_errors = true` for mypy; a documented per-file Ruff exception
  list for asserts, test fixtures, and the Docker-smoke test's deliberate
  `subprocess` calls) — strict on production code, pragmatic on test code,
  and the exceptions are named in `pyproject.toml`'s comments, not silent.
- **Every detector is a pure function**: no I/O, no state held between
  calls, no verdict decisions, no logging of content
  (`SPEC.md` §2.4). If you're writing a detector that needs any of those,
  it isn't a detector — it belongs somewhere else in the pipeline.
- **A risk score never authorizes anything** (`POL-012`). If new code makes
  a decision based on a raw score rather than a named policy rule, that's a
  bug, not a shortcut.
- **Transformations are orthogonal to verdicts** (`TRN-001`). Whether
  content is modified and whether it is authorized are two separate
  questions; don't conflate them in new rule or transformation code.
- **Structured JSON logging through the field allowlist only**
  (`app/logging_config.py`) — never log request/response content, a key, a
  session cookie, or a CSRF token. `tests/test_audit_privacy.py` grep-tests
  real captured `DEBUG`-level output against every PII/secret-bearing
  corpus case; a change that adds a new logged field needs that allowlist
  updated deliberately, not incidentally.
- **Never touch the frozen 54-case corpus or the policy schema** without an
  ADR. The corpus is the behavioural contract as executable data
  (`PLAN.md` §12's ownership table: "Cases weakened to make a build pass"
  is explicitly what it must never contain).

## The ADR-per-judgment-call discipline

Every phase of this build has produced exactly one ADR (occasionally more,
where more than one genuinely separate judgment call emerged — e.g. Phase 0
produced an addendum) documenting every decision that wasn't fully dictated
by `SPEC.md`/`PLAN.md`'s literal text: a gap found in the frozen policy
YAML, a real Docker Compose behaviour that changed one of `SPEC.md`'s own
example commands, a genuine drift between a hand-authored contract file and
the running application. This is not process for its own sake — it is how
this repository's own stated principle ("no invented content, no number
that isn't traceable, no capability claimed without a test") stays true
across ten sequential phases built by different sessions with no shared
memory between them, other than what's written down.

**If you make a judgment call that SPEC.md/PLAN.md doesn't fully settle,
write an ADR.** Practical convention, followed exactly through ADR 0010:

- Numbered sequentially, zero-padded to four digits
  (`docs/adr/0001-...md` through the current highest number — check
  `docs/adr/` before picking the next one).
- Filename: `NNNN-short-kebab-case-slug.md`.
- Sections used consistently across all ten existing ADRs: `Status` (a
  short "Accepted. Implemented and verified..." summary, not a template
  placeholder), `Context` (what was true before this decision, quoting the
  relevant `PLAN.md`/`SPEC.md` text verbatim rather than paraphrasing where
  the exact wording matters), `Decision`/`Decisions`, `Verified, not merely
  asserted` (real command output, not a claim), and `Consequences`.
- State what was actually found and actually run — real command output,
  real test counts, real diffs — not what should be true. This project's
  standing rule against invented numbers applies exactly as much inside an
  ADR as inside the README.

## Corpus-contribution guidance

The 54-case golden corpus (`tests/data/golden_corpus.jsonl`) is frozen and
schema-validated (`tests/data/corpus.schema.json`,
`scripts/validate_contracts.py`). If you believe a new case is warranted
(a real detector gap, a new attack pattern), the path is: write it up as an
ADR proposing the addition, get it reviewed against `PLAN.md` §9.3's bucket
distribution (adding a case changes the distribution `validate_contracts.py`
checks against, so the check itself needs updating in the same change), and
land the corpus change and the ADR together — never a silent edit to the
corpus file alone.

## Related documents

- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure
- [`CHANGELOG.md`](CHANGELOG.md)
- [`LICENSE`](LICENSE) — MIT
