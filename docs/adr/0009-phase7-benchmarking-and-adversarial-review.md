# ADR 0009: Phase 7 — benchmarking, coverage gate, and adversarial review

## Status

Accepted. Implemented and verified end to end: a real `scripts/benchmark.py`
run against a real `uvicorn` process in mock mode (1,000 requests per shape
after a 100-request warm-up, exactly PLAN.md §10.1's methodology);
`docs/benchmarks.md` populated from that run's actual output, nothing
invented; a real coverage gate wired into CI; thirteen deliberate,
hands-on evasion attempts against the real detectors, seven of which were
real gaps and are now fixed, four of which are documented residual risks,
two of which turned out to already be handled.

## Context

PLAN.md §6's Phase 7 section, quoted verbatim:

> **Preconditions** — Phase 6 gate.
> **Tasks** — WS-14 completion; load and latency benchmarking; adversarial
> review.
> **Deliverables** — the full suite; `scripts/benchmark.py`;
> `docs/benchmarks.md` populated from a real run.
> **Automated checks** — coverage gate; all 54 corpus cases; Hypothesis
> property tests; Docker smoke tests.
> **Manual validation** — a deliberate attempt to evade each detector, with
> results recorded as either a fix or a documented residual risk.
> **Exit gate** — §10's release gates are met and measured, with no
> invented values.

WS-14's own text (PLAN.md §5): "the evidence base for every claim in the
README... a coverage gate; a benchmark script writing `docs/benchmarks.md`...
Acceptance — all 54 cases execute and assert verdict, transformation and
reason codes; the corpus file validates against its schema; coverage meets
the §10 gate."

§10.2's gate table (quoted, not paraphrased, since this ADR's whole point is
not inventing numbers): G1 firewall-added p50 ≤ 25ms (aspirational
budget); G2 p95 ≤ 60ms; G3 p99 ≤ 150ms; G4 throughput, single worker mock,
recorded/no threshold; G5 `DIRECT_INJECTION` recall 10/10 (blocking); G6
all attack buckets 32/32 (blocking); G7 benign pass rate 12/12 (blocking);
G8 redaction accuracy 10/10 (blocking); G9 approval completion + replay
(blocking, already covered by existing Phase 4 tests); G10 restart recovery
(blocking, already covered); G11 audit completeness (blocking, already
covered by Phase 6's `test_audit_privacy.py`); G12 upstream calls avoided,
recorded; G13 estimated cost per 1,000 transactions, derived/labelled; G14
test coverage ≥ 85% line, ≥ 75% branch (blocking); G15 zero high/critical
dependency vulnerabilities (blocking, already covered by Phase 6's
`pip-audit`/Trivy CI job).

Before writing any code, the repo was checked directly for what already
existed versus what Phase 7 still had to build:

- No `scripts/benchmark.py` and no `docs/benchmarks.md` existed.
  `README.md`'s own Status section already said so explicitly ("This
  README still has no measured-latency table — that depends on Phase 7's
  benchmark work").
- `pyproject.toml`'s `[tool.coverage.run]` set `source`/`branch` but no
  `[tool.coverage.report] fail_under`, and `.github/workflows/ci.yml`'s
  pytest step produced `coverage.xml` but nothing read it — there was no
  coverage gate anywhere, automated or otherwise, despite WS-14 naming one
  as a deliverable.
- Hypothesis property tests existed only in `tests/test_normalizer.py`
  (four tests, from Phase 2) — SPEC.md TST-020 ("no detector exceeds its
  deadline on adversarial input") had a deterministic (non-property)
  regression test in `tests/test_orchestrator.py` but no Hypothesis
  coverage of it.
- All 54 golden-corpus cases already passed (`tests/test_golden_corpus.py`,
  unchanged since Phase 3/ADR 0005) and Docker smoke tests already existed
  and passed (`tests/test_docker_smoke.py`, Phase 5). Neither needed
  building, only re-verifying — which this phase did, for real, not by
  assumption.
- Prior ADRs' own residual-risk language ("Novel phrasings", "Multi-layer
  novel encodings", "Unusual or non-Western formats" — SPEC.md §19.4) was
  the starting point for where to probe, per the task's own instruction,
  not the entirety of the probing.

## Decisions

### 1. Benchmark methodology follows PLAN.md §10.1 literally, not an invented one

"Firewall-added latency is wall-clock time inside the firewall excluding
upstream time: total_duration − upstream_duration. Measured in mock mode...
over 1,000 requests after a 100-request warm-up." `scripts/benchmark.py`
does exactly this, against a real `uvicorn app.main:app` subprocess (single
worker, no `UPSTREAM_BASE_URL`), for four request shapes taken verbatim
from the frozen corpus (`BEN-001`, `INJ-001`, `PII-001`, `TOL-001`) rather
than invented payloads, so the measured requests are the same ones the
corpus already asserts a verdict for.

Two genuinely different ways of reading "total_duration − upstream_duration"
per-request, both used, both stated in `docs/benchmarks.md` next to the
numbers they produced:

- For `ALLOW` verdicts (`BEN-001`, `PII-001`), the mock upstream is
  actually called, so client-observed total time includes a real (if tiny)
  upstream component. Rather than approximate a subtraction client-side,
  the script reads the *server-computed* `firewall.timings_ms.firewall_added`
  field `app/main.py` already places in every `200` response body
  (`detection_ms + output_guard_ms` — this field already existed before
  Phase 7; nothing was added to `app/main.py` to produce it). This is a
  more precise per-request number than any client-side subtraction could
  give.
- For `DENY` and `NEED_APPROVAL` verdicts (`INJ-001`, `TOL-001`), SYS-002/
  APR-002 mean the upstream is never called at all — `upstream_duration`
  is exactly zero by construction, so the client-observed total request
  latency already *is* the firewall-added latency, with no subtraction
  needed. This is documented in the output, not silently assumed.

G4 throughput is measured the way PLAN.md names it — "single worker,
mock" — by issuing requests sequentially from one client against one
`uvicorn` worker, explicitly not saturating the server with concurrent
load; the doc states this is a lower bound, not an upper one.

### 2. The rate limiter is loosened for the benchmark run only, not disabled everywhere

`policies/default_policy.yaml`'s `rate_limit_default` rule allows 60
requests per 60 seconds per identity — correct for protecting a real
deployment, but it would turn a 1,000-request single-shape benchmark run
into mostly `429 RATE_LIMITED` responses, measuring the rate limiter's
overhead instead of the firewall's. `scripts/benchmark.py` starts its own
`uvicorn` process with `POLICY_PATH` pointed at a temporary copy of the
default policy with only that one rule's `requests` value raised; nothing
else about the policy changes, and the real, checked-in
`policies/default_policy.yaml` is never modified. This is called out
explicitly in `docs/benchmarks.md`'s Environment section and its "Notes and
caveats", not hidden.

### 3. G13's price is a stated, cited, dated assumption — not fabricated, not silently reused as if measured

PLAN.md §10.3 requires G13 to be "labelled as an estimate wherever it
appears, never as an observed saving," and requires the *count* it
multiplies (avoided calls) to be real. `scripts/benchmark.py` reads the
real `realguard_upstream_calls_avoided_total` counter from a live
`/metrics` scrape before and after the run (a genuinely measured delta),
and multiplies it by a stated public price this session looked up via web
search on 2026-09-05 (OpenAI's published `gpt-4o-mini` pricing, $0.15/1M
input tokens — cited in both the script's own docstring and
`docs/benchmarks.md`, with the caveat that the script cannot re-verify a
live price at run time). Token count is the request's own known character
length divided by 4 — the same formula `app/providers/mock.py`'s
`MockProvider` itself already uses — applied to this script's own literal,
known request text, not invented. Completion-token cost is deliberately
left at zero (a `DENY`d request never reaches a model, so there is no
completion to price), making the estimate an explicit input-tokens-only
lower bound rather than a rounder, less honest number. This is one
illustrative public price point among many possible upstream models, and
is labelled as such everywhere it is printed — never as "the" cost, never
unlabelled.

### 4. The coverage gate reads `coverage.xml`'s line-rate/branch-rate, not `coverage.py`'s own `fail_under`

G14 names two separate thresholds (≥ 85% line, ≥ 75% branch).
`coverage.py`'s own `--fail-under` / `[tool.coverage.report] fail_under`
enforces one *blended* statement+branch percentage when `branch = true` —
it cannot express two independent thresholds. `scripts/check_coverage_gates.py`
instead parses the Cobertura-format `coverage.xml` that
`pytest --cov-report=xml` already produces (CI's own pre-existing step),
which reports `line-rate` and `branch-rate` as separate top-level
attributes, and checks each against its own G14 number. Wired into
`.github/workflows/ci.yml` as a new step immediately after the existing
pytest-with-coverage step. Measured on this run: **93.4% line, 81.8%
branch** — both comfortably above G14's thresholds; see the Phase 7
completion report for the exact command output.

### 5. Hypothesis rigor: checked-in `max_examples` raised permanently; a heavier one-off run is the actual validation evidence

The four existing normalizer property tests (Phase 2) ran at 500/500/200/100
examples and completed in well under a second combined. A new Hypothesis
property test was added for SPEC.md TST-020 ("no detector exceeds its
deadline on adversarial input") in `tests/test_orchestrator.py`, running
every real bundled detector (not a fake) through the real
`DetectorOrchestrator` against Hypothesis-generated arbitrary text,
including text shaped to provoke regex backtracking (long runs of a
repeated near-miss character/word), asserting the orchestrator's
wall-clock return time stays bounded by its configured deadline plus
generous scheduling slack — this is `asyncio.wait_for`'s own guarantee
(`app/orchestrator.py`, unchanged by this phase), not a new mechanism;
the property test is what was missing, not the mechanism it tests.

Decision: every checked-in `max_examples` was raised (normalizer:
500→1000, 500→1000, 200→500, 100→300; new orchestrator test: 300),
measured to still run in about 1.3 seconds combined — a real, permanent
increase, not a one-off. Separately, as the actual high-rigor validation
Phase 7's own name calls for, each property was also run once at 5,000
examples (normalizer) / 2,000 examples (orchestrator) outside the checked-in
suite — all passed, no counterexample found, combined runtime under 10
seconds (independently re-run and re-timed once more: 9.27s combined —
6.77s normalizer, 2.50s orchestrator; see the completion report for the
exact numbers). The checked-in
counts are the ongoing regression bar; the one-off run is the evidence this
phase's rigor actually produced. A dual pytest-Hypothesis-profile system
(env-var-gated `thorough`/`default` profiles) was considered and rejected
as unnecessary complexity for the cost/benefit here — every existing test
already hardcodes its own `max_examples` for good local reasons (e.g.
bounded `max_size` per test), and a profile only overrides settings a test
doesn't itself specify.

### 6. Adversarial review: what was probed, what was found, what was fixed, what stayed a residual risk

Thirteen deliberate evasion attempts were run against the real pipeline
(`app.pipeline.run_input_pipeline`), not detector internals in isolation,
so each verdict reflects what a real client would actually see. Every
attempt and its outcome — not only the ones that became fixes — is listed
in the Phase 7 completion report. Summary:

**Fixed (7 real gaps, each a narrow, additive change; none touches the
frozen corpus, the API, the policy schema, or any verdict name):**

1. Lowercase Cyrillic "т" (U+0442) and lowercase Greek "τ" (U+03C4) in
   "instructions" evaded `prompt_injection` — only their uppercase forms
   were in `app/normalizer.py`'s confusables table. Added, plus Cyrillic
   "ѕ" (U+0455, visually identical to Latin "s").
2. Word joiner (U+2060), the three other invisible math operators
   (U+2061-2064), and soft hyphen (U+00AD) inserted mid-word evaded every
   pattern — none was in the character-stripping set (which only covered
   zero-width space/joiners, BOM, and bidi controls). Added.
3. Sixteen variation selectors (U+FE00-FE0F) inserted after an ordinary
   letter evaded detection the same way. Added as a full range.
4. A space- or dot-separated SSN ("123 45 6789") evaded `pii` entirely —
   only the dash separator was recognised. Added as alternatives within
   the same three-fixed-width-group shape (not a broader "any digit
   sequence" pattern).
5. A lowercase IBAN evaded `pii` entirely (the pattern was case-sensitive).
   Added `re.IGNORECASE`.
6. An AWS STS temporary-credential key (`ASIA...`) evaded `secrets`
   entirely — only the long-term `AKIA` prefix was matched. Added as an
   alternation.
7. A SQL statement prefixed by a `--` line comment made both
   `sql_verb_in` and `sql_unbounded_mutation` evaluate the comment as the
   "first word" instead of the real verb, fully bypassing
   `destructive_sql_command` (an `ALLOW` where the corpus's own sibling
   case, `TOL-002`, expects `DENY`). Fixed by stripping SQL line and block
   comments before either condition inspects the statement.
8. (Related to 7, lower severity) A doubled space in a shell command
   ("rm  -rf") evaded the literal-substring `shell_pattern_in` match —
   the overall verdict still denied (the tool isn't allowlisted at all),
   but the `DESTRUCTIVE_ACTION` reason code was silently missing. Fixed by
   collapsing whitespace runs before matching.

Each fix has a pinned regression test in the new `tests/test_adversarial.py`
(`TestFixedEvasions`), and the full suite (394 tests, mock-mode) still
passes with all 54 golden-corpus verdicts unchanged, confirmed by re-running
`pytest -m "not docker and not ollama"` after every fix, not just once at
the end.

**Documented residual risks (4, not fixed — see SPEC.md §19.5, and
`tests/test_adversarial.py::TestDocumentedResidualRisks` pins each as
current, known-gap behaviour):**

1. A domestic US phone number with no leading "+" (E.164 form) is not
   recognised as PII at all. Not fixed: a general national-phone-number
   regex is a well-documented false-positive magnet (order numbers, zip
   codes, dates, arbitrary digit runs) and risks exactly what PLAN.md's
   own R1 mitigation column warns against — this MVP already has a named,
   accepted convention (E.164 phone) it doesn't quietly relax.
2. "rm --recursive --force" (long-form flags) is not a whitespace variant
   of "rm -rf" — different tokens entirely — so fix 8 above does not, and
   by design cannot, close it. The overall verdict still denies today
   (the tool isn't allowlisted), but if a future policy ever allowlists
   `run_shell`, this specific rewording would slip past the
   `destructive_shell_command` rule's own reason code. A finite
   alternate-spelling arms race (`--recursive`, `-r`, `find ... -delete`,
   `python -c "import shutil; shutil.rmtree(...)"`, …) was judged
   open-ended enough to be a residual risk rather than a "narrow" fix —
   the same reasoning SPEC.md §19.4 THR-008 already gives for "novel tool
   schemas."
3. Splitting a keyword with ordinary, visible punctuation or spaces
   ("I.g.n.o.r.e", "I g n o r e") evades every pattern — these are not
   invisible/zero-width characters normalization can strip, they are
   readable text that shares no literal token with any pattern. Closing
   this generically needs something closer to fuzzy/subword matching,
   which risks a much higher false-positive rate against ordinary
   spaced-out or acronym-style text; SPEC.md §19.4 THR-001 already names
   "novel phrasings" as prompt injection's residual risk, and this is
   squarely that.
4. A base64 payload nested five layers deep is not decoded — confirmed to
   still stop exactly at `MAX_DECODE_DEPTH = 3`. This is not a bug: the
   bound is a deliberate, already-documented design limit (SYS-012;
   THR-003's "Multi-layer novel encodings"), and raising it arbitrarily
   trades one denial-of-service surface (unbounded decode recursion,
   THR-015) for closing another. The adversarial-review test pins the
   bound is still exactly 3, not that it should be higher.

**Already handled (2 probed, found not to be gaps):** capital-letter
homoglyph substitution (Cyrillic/Greek) and NFKC-foldable forms (fullwidth
Latin) were already caught before this phase — the existing confusables
table and the pre-existing `unicodedata.normalize("NFKC", ...)` step
already cover them. Probed and confirmed working, not re-built.

### 7. SPEC.md §19.5 is updated with measured findings, not a full residual-risks rewrite

SPEC.md §19.5 already exists as a placeholder-shaped section: "Stated in
`SECURITY.md` without hedging: heuristic detection has false positives and
negatives... [six general statements]." `SECURITY.md` itself does not yet
exist — it is a named WS-16/Phase 8 deliverable, not this phase's. Rather
than invent `SECURITY.md` early (out of this phase's scope) or leave the
four concrete, measured residual risks above unrecorded anywhere in
SPEC.md, §19.5 is extended in place with the four numbered findings above,
each pointing at the pinned test that keeps it honest. This is a SPEC.md
edit, so it is called out explicitly here per this project's standing rule
— but it is filling in a section SPEC.md itself already designates for
exactly this content ("residual risks"), not changing any requirement,
API shape, verdict name, or corpus case. Phase 8's `SECURITY.md` should
draw on this same §19.5 text rather than re-deriving it.

## Verified, not merely asserted

- `scripts/benchmark.py --iterations 1000 --warmup 100` against a real
  `uvicorn app.main:app` subprocess: `docs/benchmarks.md` holds the actual
  output — p50/p95/p99 firewall-added latency per shape, all four
  comfortably under G1-G3's aspirational budgets (worst observed p99:
  8.368ms on the `need_approval` shape, against a 150ms budget, on the
  final run this document's numbers were regenerated from — every rerun
  performed during this phase, three in total, landed in the same
  single-digit-millisecond range, well clear of budget); G4
  throughput per shape; G12 measured as **1,100** (100 warm-up + 1,000
  measured `deny`-shape requests, the only path currently instrumented for
  this counter); G13 computed from that real count and the cited price.
- `pytest -m "not docker and not ollama"`: **394 passed**, 0 skipped, 0
  failed (up from 377 before this phase — 16 new tests in
  `tests/test_adversarial.py`, 1 new Hypothesis property test in
  `tests/test_orchestrator.py`).
- `pytest --cov=app --cov-report=term-missing --cov-report=xml`: **93.4%
  line, 81.8% branch** (coverage.xml's own `line-rate`/`branch-rate`).
  `python scripts/check_coverage_gates.py coverage.xml`: both gates pass.
- `python scripts/validate_contracts.py`: all checks pass, including the
  frozen 54-case corpus, unchanged by this phase.
- `pytest -m docker`: **5 passed** — a real `docker build` + `docker run`
  of the unmodified `Dockerfile`, driven over real HTTP.
- `pytest -m ollama`: run three separate times against real `qwen3:8b`
  inference on this machine — once embedded in a full combined `pytest -q`
  run (4 passed) and twice more in isolation immediately after (3 passed,
  1 failed, both times, same test, same `UpstreamTimeoutError` at the
  120s configured timeout). 2 failures out of 3 attempts overall: the
  Phase 6 flake is confirmed still present, not fixed, and not reliably
  reproduced either — see the completion report for the exact output of
  all three runs and the honest framing.
- Full suite, every marker, one process: **403 passed**, 0 failed, 0
  skipped, ~83 seconds — on the one (of three) run today where the
  flaky Ollama live test happened to pass; see the point above.
- `ruff check .`, `ruff format --check .`, `mypy app` (strict): all clean,
  no regressions.
- Every one of the thirteen adversarial probes was run twice — once
  against the pre-fix code (to confirm the gap was real, not assumed) and
  once after each fix (to confirm it actually closed) — output for both
  runs is in the completion report, not just the final state.

## Consequences

- `docs/benchmarks.md` now exists with real, reproducible numbers, dated
  and SHA-stamped, matching DOC-010's rigor ahead of Phase 8 writing it
  into the README's own "Measured results" section. `README.md`'s Status
  section sentence "This README still has no measured-latency table" is
  now false and is corrected in this phase's own README touch (a
  benchmarks reference and updated test counts only — the full §18
  restructure remains Phase 8's).
- G14 has a real, CI-enforced gate for the first time; G9-G11 and G15 were
  confirmed already covered by pre-existing tests from Phases 4/6, not
  re-built.
- Seven real detector-evasion gaps are closed; four are named, pinned,
  residual risks rather than either silently present or falsely claimed
  fixed. SPEC.md §19.5 and `tests/test_adversarial.py` are now the
  authoritative record of both.
- `SECURITY.md`, `docs/threat-model.md`, and `docs/architecture.md` remain
  unwritten — named WS-16/Phase 8 deliverables, not duplicated here.
- Dependency-hash pinning (WS-17, named as a gap since ADR 0008) remains
  unresolved; untouched by this phase's scope.
- `scripts/benchmark.py` does not benchmark against a live Ollama model —
  deliberate (see the script's own docstring): real 8B-model latency is
  two to three orders of magnitude larger than firewall-added latency and
  would dominate any combined number without adding information about the
  firewall's own overhead, which is what G1-G3 exist to measure. This is a
  named scope choice, not an oversight.
