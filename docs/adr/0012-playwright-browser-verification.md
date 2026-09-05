# ADR 0012: Real headless-Chromium verification of the reviewer dashboard (Playwright)

## Status

Accepted. Implemented and verified end to end: Playwright installed (pinned
`1.55.0`) with a real, launchable local Chromium (`playwright install
chromium`); a new `browser` pytest marker mirroring the `docker`/`ollama`
skip-clean contract, with both its skip and pass branches actually exercised,
not just written; a real browser session driving the login → queue →
approve flow found one genuine, previously-undetected CSP defect, which is
now fixed (not merely documented as a residual risk); three real screenshots
captured and inspected; all 6 README/`docs/architecture.md` Mermaid diagrams
additionally re-verified by rendering them with the real Mermaid JS library
in a real browser, as a bonus, meaningfully different check than the
existing `mmdc` syntax-only validation.

## Context

`docs/adr/0010`'s Decision 5 and `docs/adr/0011`'s own restated context (its
quote of PLAN.md §6 Phase 9's "Manual validation" line: "a browser review of
the rendered README, including Mermaid diagrams") both named the same real,
honestly-flagged gap: no headless-browser tooling was available in this
environment through Phase 9, so every existing dashboard verification —
`tests/test_dashboard.py`, `tests/test_session.py`, the README's "Dashboard"
section's `curl` walkthrough — drives the HTTP layer directly
(`TestClient` or `curl`), and the Mermaid diagrams were checked only with
`npx @mermaid-js/mermaid-cli` (`mmdc`), a syntax-only CLI parser. Neither
proves:

- that a real browser's own CSP enforcement actually blocks what
  `app/main.py`'s `Content-Security-Policy: default-src 'self'` header is
  supposed to block (a `TestClient` assertion can only check the header's
  *value*, never whether a real user-agent *enforces* it);
- that the vendored `htmx.min.js` actually performs an in-place DOM swap
  with no full page navigation when the Approve/Deny button is clicked (a
  `TestClient` assertion can only check the *response body* of
  `POST /dashboard/approvals/{id}/decide`, never what a browser's DOM does
  with it);
- that the dashboard's rendered pages, or the Mermaid diagrams, look like
  anything at all to an actual human looking at an actual screen.

The user explicitly asked for this gap to be closed for real: install and
use Playwright. This is authorized, additional verification/documentation
work — not the withheld Phase 9 publication step (repository creation,
push, tag, and the GitHub release remain separately gated, exactly as
`docs/adr/0011` already states and as confirmed unchanged at the end of
this work: `git remote -v` and `git tag` are both empty, before and after).

Before writing anything, the environment was checked directly rather than
assumed capable or incapable:

- `playwright` was not previously installed (`pip show playwright` — not
  found) and no Chromium binary existed under
  `~/Library/Caches/ms-playwright/`.
- `pyproject.toml`'s `docker`/`ollama` marker pattern
  (`pytestmark = pytest.mark.<name>` at module level, a fixture that probes
  real availability and calls `pytest.skip(...)` with a specific, actionable
  reason on failure — `tests/test_docker_smoke.py`'s
  `running_mock_container` fixture is the concrete template) was read and
  is exactly what the new `browser` marker follows.
- `app/main.py`'s `SecurityHeadersMiddleware` sends
  `Content-Security-Policy: default-src 'self'` (no `unsafe-inline`)
  system-wide, and every template under `app/templates/dashboard/` was
  re-read: no inline `<script>`/`<style>`, no inline event-handler
  attributes remain (Phase 4/ADR 0006 already fixed that class of issue) —
  the templates *looked* clean by inspection, which is exactly the kind of
  claim this phase's whole point is to verify with a real browser instead
  of trusting the read.

## Decisions

### 1. Playwright is pinned, installed, and its Chromium actually launches in this environment

`playwright==1.55.0` was added to `pyproject.toml`'s `dev` optional
dependencies (pinned to an exact version, unlike every other dependency's
range-pin, because a browser-automation library's behavior is far more
sensitive to point-release drift than an API client's — matching this
project's existing convention of pinning tightly wherever a tool's exact
behavior matters, e.g. `mypy`/`ruff`'s already-pinned exactness), installed
into the project's own `.venv`, followed by `playwright install chromium`
(a real, successful ~130 MiB download of Chromium 140.0.7339.16 / Playwright
build v1187) and `playwright install-deps chromium` (a genuine no-op on this
macOS environment — `install-deps` exists to invoke the host OS's package
manager for Linux-only shared-library dependencies Chromium needs; it exited
0 with no output here because macOS's Chromium build has no such external
step). A direct smoke check (`sync_playwright().chromium.launch()` against
a `data:` URL) confirmed real launch-and-render-and-close before any test
was written. **Nothing about this environment blocked Chromium** — unlike
the Ollama flake or the Docker-daemon-availability check in prior phases,
there was no fallback needed here; the browser genuinely works.

### 2. The `browser` marker mirrors `docker`/`ollama` exactly, and both its skip and pass paths were verified for real

`pyproject.toml`'s marker list gained:

```
"browser: tests requiring a real, launchable headless Chromium via Playwright (Phase 9, ADR 0012); skip, never fail, when unavailable",
```

Both `tests/test_dashboard_browser.py` and `tests/test_mermaid_rendering_browser.py`
set `pytestmark = pytest.mark.browser` at module level and each define a
fixture (`browser_session`, `mermaid_page`) that attempts
`playwright.chromium.launch()` inside a `try`/`except`, calling
`pytest.skip(...)` with a specific, actionable reason
("Chromium is not launchable in this environment (...). Run `playwright
install chromium` ... and re-run `pytest -m browser`.") on any failure —
the identical shape as `test_docker_smoke.py`'s `_docker_available()` +
`pytest.skip("Docker daemon not reachable in this environment")`.

Because Chromium genuinely launches in this environment, the skip path
could not simply be observed by running the suite as-is — it was verified
by *forcing* the failure condition and checking the actual result, not by
reasoning about the code in the abstract:

```
$ PLAYWRIGHT_BROWSERS_PATH=/tmp/nonexistent-browsers-path-71547 \
    .venv/bin/python -m pytest tests/test_dashboard_browser.py -m browser -rs
...
SKIPPED [1] tests/test_dashboard_browser.py:198: Chromium is not launchable
in this environment (Error: BrowserType.launch: Executable doesn't exist at
/tmp/nonexistent-browsers-path-71547/chromium_headless_shell-1187/...)
======================== 1 skipped, 2 warnings in 0.89s ========================
```

— a genuine `SKIPPED`, not an `ERROR` or a `FAILED`, with the reason a
contributor would actually need. Removing the environment override and
re-running produced a genuine `PASSED` (see Decision 3). Both branches of
the marker's contract are therefore evidence-backed, not merely written and
assumed correct.

### 3. The real browser session found one genuine, new CSP defect — fixed, not just documented

The first full run of `tests/test_dashboard_browser.py`'s login → queue →
approve flow, against the pre-fix templates, failed for real:

```
AssertionError: a real CSP violation fired during this session: [{'directive':
'style-src-elem', 'blockedURI': 'inline', 'sourceFile':
'http://127.0.0.1:18020/dashboard/static/vendor/htmx.min.js'}]
```

**Root cause, confirmed by reading the vendored library, not assumed from
the error message alone:** `htmx.min.js` (1.9.12)'s own default
configuration (`config.includeIndicatorStyles: true`) makes it inject an
inline `<style>` element at load time, unconditionally — CSS defining
`.htmx-indicator`/`.htmx-request` opacity transitions — regardless of
whether the page uses the `htmx-indicator` class at all. A grep of every
dashboard template and `app/static/dashboard.css` confirms
`htmx-indicator` is never used anywhere in this codebase; the feature the
injected style exists to support is entirely unused. `app/main.py`'s
`SecurityHeadersMiddleware` sends `default-src 'self'` with no
`style-src 'unsafe-inline'` exception (deliberately — SEC-008's whole point
is a strict default), so a real browser correctly refused htmx's injected
inline style and fired a real `securitypolicyviolation` event — something
no `TestClient`/`curl`-driven test in this codebase could ever have
observed, because none of them runs inside an actual browser's CSP
enforcement engine.

This is exactly the kind of gap this phase exists to close: a defect that
was real, present since Phase 4/ADR 0006 first vendored `htmx.min.js`, and
invisible to every check this project had run against the dashboard until
now (including `docs/adr/0010`'s own explicit statement that the templates
were manually read against the CSP header's semantics — that manual read
did not catch a library-internal behavior, only the templates' own markup).

**Fix**, narrow and additive, no CSP loosening: `app/templates/dashboard/base.html`
gained one line, htmx's own documented pre-load configuration mechanism,
before the vendored script tag:

```html
<meta name="htmx-config" content='{"includeIndicatorStyles": false}'>
```

Confirmed present in the minified source (`config.includeIndicatorStyles`,
the `<meta name="htmx-config">` reader, and the style-injection call site
were all located and read directly in `app/static/vendor/htmx.min.js`
before deciding this was the correct, narrow fix rather than either
loosening SEC-008's CSP header — a materially bigger, security-relevant
change out of this task's scope — or leaving the violation as a documented
residual risk when a real, zero-functional-impact fix was available).
Re-running the identical browser test after the fix passed cleanly with an
empty `window.__cspViolations` array — the fix was verified to actually
close the gap, not just written and assumed to work.

**Outcome, stated plainly: this is a fix, not a clean bill.** The honest
answer to "did the browser check find anything" is *yes* — CSP enforcement
was not already clean; it is clean now, because this phase found and fixed
a real defect no prior phase's tooling could see.

### 4. The primary test drives one real session through login, CSP, HTMX swap, and screenshot capture — not four separate ones

`tests/test_dashboard_browser.py::test_dashboard_real_browser_login_csp_and_htmx_flow`
does, in one real `uvicorn` subprocess + one real Chromium session:

1. Seeds a real `NEED_APPROVAL` case via `POST /v1/chat/completions`
   (service key) — the same API the existing `curl` walkthroughs use.
2. Navigates to `/dashboard/login`, asserts the real response's
   `Content-Security-Policy` header, screenshots it
   (`docs/screenshots/dashboard-login.png`).
3. Logs in through the actual rendered `<form>` (fills the password input,
   clicks the real "Sign in" button — not a direct cookie injection),
   lands on `/dashboard`, re-checks the CSP header on that page too.
4. Waits for the pending row to render, screenshots the queue
   (`docs/screenshots/dashboard-queue.png`).
5. Clicks the real rendered "Approve" button (an `hx-post` +
   `hx-swap="outerHTML"` control, not a form submission), asserts via DOM
   locators — not text re-parsing — that the row's content changed to a
   "Recorded: APPROVE ... COMPLETED" fragment while `page.url` stayed
   byte-for-byte identical (i.e., no navigation occurred), screenshots the
   result (`docs/screenshots/dashboard-decided.png`).
6. Confirms the original request actually resumed via the same
   `GET /v1/firewall/requests/{id}` poll the `curl` walkthrough uses.
7. Asserts, across the whole session, `window.__cspViolations` (a real
   `securitypolicyviolation` listener injected before the first navigation)
   is empty, no console message mentions a CSP refusal, and no uncaught
   page error occurred.

One session, not four, deliberately: splitting login/CSP/HTMX/screenshots
into separate tests would mean either four separate `uvicorn` + Chromium
launches (slower, and each would need its own seeded approval) or sharing
browser state across test functions in a way that obscures which assertion
actually depends on which prior step — the single-flow shape mirrors how
`docs/adr/0011`'s own curl walkthrough is one continuous narrative, not four
disconnected snippets.

### 5. Screenshots are real PNGs, actually opened and inspected — described here from direct observation

Three files, `docs/screenshots/dashboard-{login,queue,decided}.png`
(1280×720 each), were produced by the test above and then actually opened
(not merely confirmed to exist on disk):

- **`dashboard-login.png`**: the "Reviewer sign in" card — header
  "real-guard-v1 · reviewer dashboard" with the orange "MOCK MODE — no
  UPSTREAM_BASE_URL configured" banner (DEP-004's fourth visible marker,
  confirmed rendering for real), the explanatory line about
  `FIREWALL_REVIEWER_KEYS`, a password-type "Reviewer key" input, and a
  blue "Sign in" button. No error shown (no login attempted yet).
- **`dashboard-queue.png`**: the "Pending approvals" card, status filter
  dropdown showing "PENDING", and one real pending row — a red "CRITICAL"
  risk badge, "PENDING" status, "reason: SENSITIVE_TOPIC", "policy:
  review_sensitive_topic", a real expiry timestamp, the real
  `apr_...` approval id, and the sanitized JSON preview showing the
  actual seeded message content ("Based on these symptoms, can you give me
  a specific medical diagnosis?"). Below the preview: a "Note (required to
  deny)" text field, a green "Approve" button, and a red "Deny" button. A
  second card, "Recent decisions", shows "No decisions recorded yet." —
  correct, since nothing had been decided at this point in the flow.
- **`dashboard-decided.png`**: the same layout, but the pending row is now
  replaced in place with "Recorded: **APPROVE** — approval is now
  **COMPLETED** (timestamp)" — the exact HTMX-swapped fragment
  `render_decision_fragment()` (`app/dashboard.py`) produces. The "Recent
  decisions" panel below still reads "No decisions recorded yet." — this is
  correct and expected, not a bug: HTMX only swapped the one row's
  `outerHTML` (`hx-target="#row-{id}"`), exactly as designed; the separate
  "Recent decisions" list is only populated on the next full `GET
  /dashboard` page load, which this flow deliberately does not trigger
  (triggering one would defeat the point of proving the swap happened
  without a full reload).

### 6. Mermaid diagrams: a real, additional, visual browser check — bonus, not a replacement for `mmdc`

`docs/adr/0009` and `docs/adr/0010` already ran all 6 diagrams (4 README, 2
`docs/architecture.md`) through `npx @mermaid-js/mermaid-cli`, confirmed
syntax-valid, non-trivial SVG output. That check remains true and is not
redone or replaced here — it is a real, useful, different check
(command-line grammar validation) than what this phase adds: `mermaid.js`
10.9.1 (an exact pinned version, loaded from `cdnjs.cloudflare.com`, the
same CDN this project's own Artifact tooling allowlists) loaded into a real
Chromium page via `tests/test_mermaid_rendering_browser.py`, rendering all 6
diagrams' actual source text extracted directly from `README.md` and
`docs/architecture.md` (not retyped, not paraphrased), asserting each one's
rendered `<svg>` does not contain Mermaid's own literal "Syntax error" text
(what a failed parse renders as, so a real render failure would fail this
test, not just look different in a screenshot nobody checked), and
screenshotting each diagram individually
(`docs/screenshots/mermaid-diagram-{README-1..4,docs-architecture-1..2}.png`).

All 6 were actually opened and inspected:

- **README diagram 1** (`flowchart LR`, "What it does"): five labelled boxes
  (Client request, a diamond decision node "real-guard-v1", ALLOW/DENY/
  NEED_APPROVAL outcome boxes, an "Output guard" diamond) connected by
  labelled arrows ("malicious / policy violation", "ambiguous", "clean",
  "leak detected", "reviewer approves", "reviewer denies") — a legible
  flowchart, not an error.
- **README diagram 2** / **`docs/architecture.md` diagram 1** (`flowchart TD`,
  system architecture — the same diagram appears in both files): a large,
  fully-labelled component diagram inside a "real-guard-v1" boundary box —
  Authentication, Rate limiter, Request normalizer, Detector orchestrator,
  Detectors, Risk aggregation, Tool-call guard, Policy engine, Approval
  service, Resume worker, Reviewer dashboard, Transformation pipeline,
  Provider adapter, Output guard, Audit service, Metrics service, a SQLite
  WAL cylinder — with external nodes (Human approver, Mock/Ollama/Generic
  providers, Client/App/Agent) and labelled edges (`POST
  /v1/chat/completions`, `ALLOW`, `NEED_APPROVAL`, `DENY`, `approve / deny`,
  "sanitized response") — every box and arrow legible, nothing garbled or
  overlapping.
- **README diagram 3** (`sequenceDiagram`, the `NEED_APPROVAL` creation
  flow): seven numbered lifeline participants (Client, Gateway, Policy
  engine, Transformations, Approval service, Database, Provider) with nine
  numbered, labelled messages and a highlighted note box reading "No
  upstream call is made — APR-002".
- **README diagram 4** (`sequenceDiagram`, the resume flow): seven
  participants (Reviewer, Dashboard, Approval service, Database, Resume
  worker, Provider, Output guard, Client), fourteen numbered messages
  including a self-loop ("re-validate material arguments") on the Resume
  worker lifeline — fully legible.
- **`docs/architecture.md` diagram 2** (`stateDiagram-v2`, the approval
  state machine): a filled start marker into `PENDING`, transitions to
  `APPROVED`/`DENIED`/`EXPIRED`/`RESUMING`/`CANCELLED`, onward to
  `COMPLETED`/`FAILED`, all converging on a ringed end marker — every state
  box and every transition label ("reviewer approves", "TTL elapsed",
  "worker claims, atomic", "upstream failed permanently", "originator
  cancels", etc.) legible and correctly placed.

No diagram rendered as an error message, raw unparsed text, or a garbled/
overlapping mess — all 6 are real, correct, legible Mermaid renders.

## Verified, not merely asserted

- `pip install playwright==1.55.0`: succeeded (`greenlet`, `pyee`,
  `playwright` installed into `.venv`).
- `playwright install chromium`: succeeded — Chromium 140.0.7339.16 (build
  v1187) downloaded and installed.
- `playwright install-deps chromium`: exited 0 (genuine no-op on this
  macOS host).
- A direct `sync_playwright().chromium.launch()` smoke check against a
  `data:` URL: launched, navigated, read content, closed — before any test
  was written.
- `pytest tests/test_dashboard_browser.py -m browser -v`: **1 passed**
  (after the htmx-config fix; failed with the real CSP-violation assertion
  before it, confirming the gap was real, not assumed).
- `PLAYWRIGHT_BROWSERS_PATH=<nonexistent path> pytest
  tests/test_dashboard_browser.py -m browser -rs`: **1 skipped**, with the
  exact reason text quoted in Decision 2 — the skip path verified by
  forcing the failure, not just inspecting the code.
- `pytest tests/test_mermaid_rendering_browser.py -m browser -v`: **1
  passed** — all 6 diagrams rendered, no "Syntax error" text in any.
- `pytest tests/test_dashboard.py tests/test_session.py -v`: **40 passed**
  — no regression from the `base.html` meta-tag addition.
- `ruff check .`: all checks passed (after one line-length fix in the new
  Mermaid test). `ruff format --check .`: all files formatted (two new
  test files were reformatted once by `ruff format` itself, then re-run
  clean). `mypy app` (strict): no issues in 42 source files — untouched by
  this phase's only `app/`-adjacent change (`app/templates/dashboard/base.html`
  is a template, not type-checked code).
- `pytest --cov=app --cov-report=term-missing --cov-report=xml -q`: **455
  passed**, 0 failed (up from 453 — the 2 new browser tests), both Docker
  and a real local Ollama available in this run. `python
  scripts/check_coverage_gates.py coverage.xml`: 93.4% line / 81.8% branch,
  both gates still pass (unchanged — no `app/` logic changed, only a
  template comment/meta-tag and two new test files).
- `python scripts/validate_contracts.py`: all checks pass, including the
  unchanged 54-case golden corpus and the unchanged 11-path OpenAPI shape —
  nothing about the API, policy schema, verdict names, or corpus was
  touched by this phase.
- `git remote -v`: empty, before and after this phase's work. `git tag`:
  empty, before and after. Nothing pushed, tagged, or published.

## Consequences

- `app/templates/dashboard/base.html` carries a new, permanent
  `<meta name="htmx-config">` line disabling `includeIndicatorStyles` — a
  narrow, real, zero-functional-impact fix for a genuine CSP defect this
  phase found. Any future vendored-htmx upgrade should re-check this
  config's continued presence (a future htmx major version could rename or
  remove the option) — not a currently open risk, but worth a human's
  attention the next time `app/static/vendor/htmx.min.js` is upgraded.
- `docs/screenshots/` is a new, permanently tracked directory — 9 real PNGs
  (3 dashboard, 6 Mermaid), not build artifacts, not gitignored.
- `pyproject.toml`'s `dev` extras and marker list both grew by one entry
  each (`playwright==1.55.0`; the `browser` marker) — a contributor without
  `playwright install chromium` having been run still gets a clean `pytest`
  run, the browser tests skipping with an actionable reason, exactly like
  `docker`/`ollama` already behave for their own dependencies.
- The README's "Dashboard" section's "no rendered screenshot" honest-gap
  language and its "Limitations" section's matching bullet are both now
  replaced with real content — see the README diff in this same commit.
  `docs/adr/0010`'s Decision 5 and `docs/adr/0011`'s restated Manual
  Validation gap are both now closed in fact, not just in a future
  intention; those ADRs are left unedited (they are historical records of
  what was true in their own phase) and this ADR is the record of the
  closure.
- The Mermaid `mmdc` syntax check from `docs/adr/0009`/`0010` is not
  removed or superseded — both checks now exist, and are different in kind
  (grammar validity vs. actual visual rendering); a future CI job could
  add `tests/test_mermaid_rendering_browser.py`'s check as a permanent gate
  the same way `mmdc` could be, though wiring either into CI remains
  outside this phase's scope (this phase's task was closing the
  ADR 0011-named gap with real, one-time evidence, not building new
  permanent CI infrastructure).
- Nothing was published: no repository created, no branch protection, no
  push, no tag, no GitHub release. `git remote -v` and `git tag` remain
  empty. This ADR does not touch, supersede, or reduce the scope of
  `docs/adr/0011`'s own withheld go-ahead — that gate is unchanged.
