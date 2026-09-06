# ADR 0014: `/console` — a real React/Next.js reviewer console, additive to the existing dashboard

## Status

Accepted. Post-`v0.1.0` scope expansion, requested explicitly by name
("upgrade this to make more UI based... has to be fully functional", with
`github.com/debster9755/sentinelforge` — a Next.js + Tailwind + shadcn/Radix
SPA by the same author — named as inspiration, and "Full React/Next.js SPA
rewrite" chosen explicitly over two smaller options when asked).

## Context

`real-guard-v1`'s reviewer UI (SPEC.md §2.19, PLAN.md WS-11, ADR 0006) is a
deliberately minimal server-rendered Jinja2+HTMX dashboard: a login screen,
a pending-approvals queue, inline approve/deny, a decision history panel —
WS-11's own words: "the four screens above are the entire deliverable,"
explicitly scoped against admin-console creep. It is real, tested, and has
stood since Phase 4.

`sentinelforge` (github.com/debster9755/sentinelforge, MIT, same copyright
holder) is a completely different stack: Next.js App Router, TypeScript,
Tailwind, shadcn/ui component patterns over Radix primitives, a single
polished "console" page (`app/sentinel-console.tsx`) with stat cards, a
policy-decision visualisation, and a chat-style request/response view. It
is not a multi-page site — one richly composed screen — which set the right
expectation for scope here too: this ADR does not add pages sentinelforge
doesn't have, it adds the pages `real-guard-v1`'s own approval workflow
actually needs (a queue, a decision history, and an overview), built with
the same *kind* of tooling (Next.js, Tailwind, component composition,
real charts) rather than sentinelforge's literal code, which is a fake-data
demo of a different product and has nothing this project's real, persisted
approval workflow can reuse directly.

Three options were put to the user directly (a lighter HTMX+Chart.js
refresh, a Tailwind+Alpine.js middle ground, and a full SPA rewrite); the
full SPA rewrite was chosen.

## Decision

Add a new, additive `/console` single-page application. The existing
`/dashboard` HTMX UI is untouched — same routes, same templates, same
tests, same ADR 0006 guarantees. `/console` is a second, richer UI over the
same backend, not a replacement.

### 1. Frontend: `web/` — Next.js App Router, TypeScript, Tailwind, static export

**Built on Next.js 15.5.25, not 14.** This ADR was drafted saying "Next.js
14"; the first `npm run build` failed immediately with `Configuring Next.js
via 'next.config.ts' is not supported. Please replace the file with
'next.config.js' or 'next.config.mjs'` — TypeScript config support landed in
Next 15. Rather than downgrade the config to `.mjs`, the framework was moved
to 15.5.25 (with React 19.1.9; `recharts` 2.15.4 declares React 19 in its
peer range), which is inside this ADR's own "Next.js 14+" wording. Recorded
here because the version is a real, checkable fact about the build, not a
detail to leave stale.

`next.config.ts` sets `output: 'export'`. There is no Node server at
runtime — `next build` produces static HTML/JS/CSS at *Docker build time*,
and FastAPI serves the result same-origin via `StaticFiles`, exactly the
same way `/dashboard/static` already serves vendored htmx. This keeps the
single-container, single-port deployment model (DEP-002/003) unchanged,
needs no CORS configuration (same origin), and satisfies SPEC.md §2.19's
"no third-party CDN — vendored/same-origin only" rule the same way the
htmx dashboard already does: Next bundles React, Tailwind's compiled CSS,
and the (self-hosted, MIT) `recharts` charting library into the static
output; nothing is fetched from a CDN at request time.

Pages (all client-rendered against the JSON API below, so "static export"
means the *shell* is pre-rendered, not the data):

- `/console/login` — reviewer-key form.
- `/console` — overview: mock-mode banner, stat cards (pending-approval
  count per state, decisions-total, requests-total), a verdict-distribution
  chart and a policy-hits chart, both `recharts` bar charts.
- `/console/approvals` — the queue: status-tab filter, a real data table,
  a review modal per row (full preview JSON, reason codes, policy hits,
  Approve/Deny with a required deny note), calling the decide endpoint with
  a fresh `crypto.randomUUID()` idempotency key per click.
- `/console/decisions` — recent decision history table.

**Path-prefix resolution: `basePath: '/console'`, decided by building both
ways and curling the result.** Two arrangements can produce those URLs, and
the difference is invisible in the HTML — which is exactly why it was
settled empirically rather than by reasoning:

1. `basePath: '/console'`, with pages at `web/app/page.tsx`,
   `web/app/login/page.tsx` and so on. The export is internally consistent:
   `out/index.html`, `out/login/index.html`, and every asset URL emitted as
   `/console/_next/…`. Mounting `out/` at `/console` makes all of them
   resolve with no rewriting.
2. No `basePath`, with pages nested under `web/app/console/…`. The pages
   land at `out/console/index.html` as intended — but the assets are still
   emitted as root-absolute `/_next/…`, which a mount at `/console` does not
   cover. The HTML 200s and looks correct to `curl`; the browser then 404s
   every script and renders a blank page.

Option 1 was taken. The consequence for file layout is that the route files
are `web/app/(console)/page.tsx`, `web/app/(console)/approvals/page.tsx`,
`web/app/(console)/decisions/page.tsx` and `web/app/login/page.tsx` — the
`/console` segment lives in `basePath`, not in the directory tree, and
`(console)` is a parentheses-wrapped route *group* (contributing nothing to
the URL) that carries the signed-in chrome, which `/console/login` sits
outside of.

`trailingSlash: true` is set alongside it: the export is
directory-per-route, and Starlette's `StaticFiles(html=True)` serves a
directory's `index.html` only for a path already ending in `/`, otherwise
issuing a 307. Emitting trailing-slash URLs from Next's own `<Link>`s avoids
that redirect entirely. `/console` (no slash) still 307s to `/console/`,
which is Starlette's mount behaviour and is correct.

**Route registration must precede the mount.** Starlette matches routes in
registration order, so `app.mount("/console", …)` added before the
`/console/api/*` handlers would swallow every API path and answer it with a
static-file 404. `register_console_api_routes()` therefore registers all
seven routes first and mounts last, and says so in its own docstring.

A client-side route guard on every page but `/console/login` calls
`GET /console/api/session` on mount and redirects to `/console/login` on
401 — there is no server-rendered auth gate (there is no server rendering
at request time at all), so this is the enforcement point on the frontend;
the real enforcement, as always, is server-side on every `/console/api/*`
call below.

### 2. Backend: `app/console_api.py` — additive JSON API, zero new business logic

A new module, mounted under `/console/api`, that (like `app/dashboard.py`'s
own docstring already says of itself) "owns no business logic of its own."
Each of the **seven** routes below is a JSON-shaped call to a function
`app/dashboard.py` already calls for the HTMX UI:

| Route | Calls | Notes |
|---|---|---|
| `POST /console/api/login` | `resolve_identity()` | Same REVIEWER-only check as `dashboard_login_submit` (SEC-006). Sets a **separate** cookie, `rg_console_session` (not `rg_session`), `Path=/console/api` — a deliberately distinct name and path from the HTMX dashboard's cookie so the two UIs' sessions never collide or interact. Returns `{identity_id, csrf_token, expires_at}` in the JSON body — safe to hand a CSRF token to the client that just authenticated over the same channel; SEC-007's synchronizer-token property (a forged cross-site request can't compute it) is unaffected by *where* the legitimate client keeps it. |
| `POST /console/api/logout` | — | Clears the cookie. |
| `GET /console/api/session` | `verify_session_cookie` | Session-restore / CSRF-refresh on page load; 401 if absent/expired. |
| `GET /console/api/approvals` | `sweep_expired()`, `list_approvals()` | Same two calls `dashboard_index()` makes; `preview_content` returned as real JSON, not a pre-stringified blob (the HTML template needed a string to embed in a `<pre>`; JSON API callers don't). |
| `GET /console/api/decisions` | `list_recent_decisions()` | Same as the HTML dashboard's history panel. |
| `POST /console/api/approvals/{id}/decide` | `decide_and_resume()` | The exact same call `dashboard_decide()` makes — session+CSRF checked identically (SEC-005/007), `Idempotency-Key` header required identically. Returns JSON, not an HTML fragment (there is no HTMX here to swap into). |
| `GET /console/api/stats` | `count_by_state()` per state, plus `state.metrics.registry.collect()` | **No new measurement.** Queue-depth-by-state uses the same DB query the existing Prometheus gauge already runs at scrape time; every other number (`realguard_decisions_total`, `realguard_risk_level_total`, `realguard_reason_codes_total`, `realguard_policy_hits_total`, `realguard_http_requests_total`) is read directly out of the same `CollectorRegistry` instance `/metrics` serves — reshaped as JSON, never re-derived, so `/console` and `/metrics` can never disagree with each other. |

All error paths return `{"error": <message>, "code": <ErrorCode>}` with
the `FirewallError`'s own status code — a small explicit `try/except`
per route, since (unlike `/v1/firewall/*`) there is no shared exception
handler installed for this new prefix.

Two consequences of that shape, both deliberate:

- The decide route validates its body with an explicit
  `ApprovalDecisionRequest.model_validate()` rather than a FastAPI `body:`
  parameter. A `body:` parameter would route a malformed body to
  `app/main.py`'s `RequestValidationError` handler and return the
  transaction-shaped ERR-001 envelope instead of this module's flat shape —
  an inconsistency inside one API surface.
- `app/metrics.py`'s `ENDPOINT_TEMPLATES` is **not** extended with the
  console routes, so they are labelled `"unmatched"` on
  `realguard_http_requests_total`. This matches the existing treatment of
  `/dashboard/login` and `/dashboard/approvals/{id}/decide`, which are
  already `"unmatched"` today (only `/dashboard` itself is in the list), and
  it adds no metric cardinality — consistent with this ADR's own "no new
  measurement" rule. Named here because `ENDPOINT_TEMPLATES`'s comment
  claims to be "the complete, fixed set of routes this app ever registers,"
  which is now true only of the *instrumented* set.

**Graceful degradation of the static mount.** The mount is conditional on an
`index.html` actually existing (`app/console_static/`, where the Docker
build puts it, then `web/out/`, where a local `npm run build` puts it). A
fresh checkout that has never run npm — and every Python-only `pytest` run,
which never runs npm at all — starts normally, logs one WARNING naming both
searched paths and the command to fix it, and skips the mount.
`/console/api/*`, `/dashboard` and `/v1/firewall/*` are unaffected. This is
what lets the existing Python suite keep passing unmodified and unskipped,
and `tests/test_console_api.py` asserts that state directly rather than
assuming it.

### 3. Docker: one more build stage, one more `COPY`

```
ARG NODE_DIGEST=sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
FROM node:22-slim@${NODE_DIGEST} AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build   # -> /web/out, via output:'export' + the CSP pass below
```
copied into the existing runtime stage as
`COPY --from=web-builder /web/out ./app/console_static`, mounted by
`app/console_api.py` via `StaticFiles(directory=..., html=True)` at
`/console`. No new service in `docker-compose.yml` — one image, one
container, one port, unchanged.

The digest above was obtained on 2026-09-06 by exactly the method ADR 0007
used for `PYTHON_DIGEST`, and the Dockerfile comment records it so the next
person refreshes it deliberately rather than by floating the tag:

```
docker pull node:22-slim
docker inspect --format='{{index .RepoDigests 0}}' node:22-slim
```

`.dockerignore` gained `web/node_modules`, `web/.next` and `web/out`. That
is not tidiness: `npm ci` runs *inside* the stage, and a host
`node_modules` built on macOS carries platform-specific binaries that would
otherwise be copied into a Linux image by `COPY web/ ./` and shadow the
correct ones. `web/package.json` and `web/package-lock.json` are
deliberately **not** excluded — they are precisely what the stage needs.

**Measured, not estimated** (this machine, Docker 29.7.2, builder cache
pruned between runs so both are genuinely cold):

| | Before | After | Delta |
|---|---|---|---|
| `docker build --no-cache` | 17.7s | 27.8s | **+10.1s** |
| Final image size | 341MB | 345MB | **+4MB** |

The image delta is small because only the static export is copied; no Node,
`npm` or `node_modules` reaches the runtime stage. Verified in the running
container: `command -v node` and `command -v npm` both find nothing, and the
process still runs as `uid=10001(realguard)`.

### 4. CSP: the one thing this plan did not anticipate

This ADR asserted, in §1, that a static export "satisfies SPEC.md §2.19's
'no third-party CDN — vendored/same-origin only' rule the same way the htmx
dashboard already does." That was true about *CDNs* and incomplete about
*CSP*, and the gap would have shipped a blank page.

Next.js's App Router static export inlines its React Flight payload as
`<script>self.__next_f.push(…)</script>` blocks directly in each exported
document — **40 of them across 6 documents** in this project's build, plus
2 inline `<style>` blocks. `app/main.py`'s `SecurityHeadersMiddleware` sends
`Content-Security-Policy: default-src 'self'` with no `unsafe-inline`
(SEC-008), and a real browser refuses every one of them. Every `curl` and
`TestClient` check passes regardless, because the HTML itself is served
correctly with a 200 — the failure is entirely in the browser's enforcement.
This is the identical class of defect ADR 0012 found once already (htmx's
own injected inline `<style>`), which is why it was checked with a real
browser here rather than assumed.

Four options were weighed:

1. **Add `unsafe-inline` to the CSP.** Rejected: weakens SEC-008
   system-wide, for every route including `/v1/firewall/*`, to make one
   optional UI convenient.
2. **Per-build script hashes in the header.** Rejected: the header is a
   constant in Python; feeding it build-artefact hashes couples the Python
   service to the frontend build in a way that breaks whenever either moves.
3. **A per-request nonce.** Rejected: requires server-side rendering per
   request, which `output: 'export'` deliberately does not have.
4. **Externalise the inline blocks at build time.** Taken.

`web/scripts/externalize-inline.mjs` runs after `next build` (wired into
`npm run build`, so the Dockerfile and CI get it for free). It rewrites each
inline block into a real file under `out/_next/static/csp/<sha256>.js|css`
and replaces the tag with a plain `<script src>` / `<link rel="stylesheet">`
at the same position — plain, so the parser still executes them in document
order, ahead of the `async` bundle chunks that consume `__next_f`. It then
re-scans the output and **exits non-zero if any inline block survives**, so
a future Next upgrade that emits an unrecognised form fails the build rather
than shipping a page the browser will not run.

The same constraint dictated two smaller choices: `next/font` is not used
(it injects an inline `<style>`; system font stacks instead — which also
keeps SPEC.md §2.19's no-CDN rule trivially satisfied, since no webfont is
fetched at all), and the pre-paint dark-mode bootstrap is a real file,
`web/public/theme-init.js`, rather than the conventional inline snippet.

`tests/test_console_browser.py` is what actually proves the result, with a
real `securitypolicyviolation` listener on a real Chromium. The CSP header
was not modified.

### 5. What this deliberately does not do

- Does not touch `/dashboard`, its templates, its tests, or ADR 0006's
  guarantees. Both UIs work independently; an operator who wants zero
  Node/JS in their build can still use `/dashboard` alone (the Dockerfile
  cannot skip the web-builder stage conditionally in this MVP — a
  documented, named limitation, not a silent one).
- Does not touch `/v1/firewall/*`, verdict names, the policy schema, or
  the 54-case corpus. This is a UI-only addition.
- Does not add authentication, rate-limiting, or approval-state semantics
  the backend didn't already have — `/console/api/*` is a second transport
  for the same, already-specified operations.
- Does not fabricate metrics. `/console/api/stats` cannot report anything
  `/metrics` doesn't already report; if a number looks wrong there, it was
  already wrong in `/metrics`, which is Phase 6's problem, not this one's.

### 6. Two real defects the screenshots caught

Both were found by *opening* the captured screenshots rather than checking
that the files existed, and both are fixed here. Recorded because "the test
passed and wrote a PNG" was true in each case while the UI was wrong.

- **The charts drew no bars.** `recharts` animates bars up from zero width
  over ~1.5s by default, so the overview screenshot — taken as soon as the
  SVG existed — captured two empty pairs of axes. Fixed with
  `isAnimationActive={false}` (right for an operations console regardless:
  it renders immediately and identically every time), and the browser test
  now asserts a bar's rendered width is greater than 1px, not merely that an
  `<svg>` exists.
- **The queue table overflowed its container**, clipping the Review button
  off the right edge, because two full RFC 3339 timestamps per row are very
  wide. Fixed by showing relative times ("4m ago", "in 59m" — which is what
  a reviewer actually needs, given APR-007 expiry) with the exact values kept
  in `title` attributes and shown in full in the review modal.

A third observation turned out **not** to be a defect: the sidebar appeared
to highlight two nav items at once. Measuring `getComputedStyle` in a real
browser showed exactly one `aria-current="page"` at any time — the
screenshot had been taken in the window between `wait_for_url` (which
resolves on the History API change) and React re-rendering the shell against
the new pathname. The fix was in the test, which now waits for the sidebar's
own `aria-current` to move — a strictly stronger assertion, since it proves
the client-side route change reached the rendered tree and not just the
address bar.

## Consequences

- A contributor building this image now needs Node 22 available in their
  build environment (or Docker) in addition to Python 3.12 — a new,
  named prerequisite, documented in README.md's quick-start.
- CI gained the frontend build as a step **inside the existing
  "lint, type-check, test" job**, not as a new job. Branch protection
  requires that exact context name; a new job would produce a check that is
  reported but not required, so a TypeScript or CSP-pass failure could merge
  green. This is the one place where the shape of the CI change was dictated
  by the protection rules rather than by tidiness.
- CI gains a frontend build step (`npm ci && npm run build` under `web/`)
  so a TypeScript or build break in the console fails CI the same way a
  `mypy --strict` break already does for the Python side.
- Two reviewer UIs now exist. This is intentional, not drift: `/dashboard`
  remains the minimal, dependency-light reference implementation SPEC.md
  §2.19 describes; `/console` is the richer, explicitly-requested addition.
  README.md documents both, honestly, with real screenshots of each.
