# ADR 0007: Ollama compose profile, startup preflight, and Docker deployment (Phase 5 / WS-15)

## Status

Accepted. Implemented and verified end to end, including against a real
local Ollama with `qwen3:8b` and a real `docker build`/`docker run`.

## Context

Three prior ADRs each named this phase's scope as something they explicitly
left undone: ADR 0005 ("the Ollama `GET /api/tags` preflight and compose
profile (Phase 5)"), ADR 0006 ("the Ollama compose profile and preflight
check (Phase 5)"), and README.md's own Limitations section ("The Ollama
compose profile and preflight check (Phase 5) ... do not exist yet"). No
`Dockerfile`, `docker-compose.yml`, or `.dockerignore` existed anywhere in
the repository before this phase — confirmed by listing the repo root
before writing any of them, not assumed from the prior ADRs' silence.

PLAN.md §6's Phase 5 section is narrow and specific — narrower than a naive
reading of "Docker deployment" might suggest:

> **Preconditions** — Phase 4 gate; host Ollama running with `qwen3:8b`.
> **Tasks** — the Ollama compose profile; the preflight check;
> Ollama-marked tests.
> **Deliverables** — a working `ollama-host` profile and its README section.
> **Exit gate** — the identical corpus verdicts hold against a real model,
> confirming detection does not depend on the mock.

WS-15 (§5)'s own deliverable list is broader — "multi-stage `Dockerfile`
(non-root, pinned base digest); `docker-compose.yml` with `mock` and
`ollama-host` profiles; `.env.example`; healthcheck; an Ollama preflight
check" — and §7's dependency map notes WS-15 is "parallelisable ... any
time after WS-03," i.e. it was always buildable earlier but nothing forced
it before now. Since no Dockerfile/compose file existed at all, and the
`mock` profile is WS-15's own explicitly named deliverable (and DEP-002's
literal subject), this phase builds all of WS-15 — Dockerfile, both compose
profiles, `.dockerignore` — reading PLAN.md's Phase 5 "tasks" line as the
Ollama-specific *increment* of a WS-15 that, absent any earlier partial
work to build on, has to be delivered whole here. This is the first
reconciliation judgment call; the rest of this ADR documents the others.

Explicitly **not** built this phase, because nothing in Phase 5, WS-15, or
the profile-assignment table (PLAN.md §8) asks for it: rate limiting
enforcement, Prometheus metrics/`GET /metrics` (both Phase 6/WS-12/WS-13),
and separate `docker-compose` services or profiles for "standard-security"
or "production-oriented." Those two rows in SPEC.md §14's deployment-mode
table are configuration of the one image (`POLICY_PATH=...`,
`APP_ENV=production`), not additional container topology — confirmed by
reading every column of that table, not inferred.

## Decisions

### 1. The task's own speculative deployment-mode framing does not match PLAN.md/SPEC.md, and PLAN.md/SPEC.md win

SPEC.md §14's table lists seven supported deployment modes (an eighth,
multi-worker, is explicitly "Not supported"): Mock (default), Local Python,
Docker mock, Ollama/Qwen3-8B, Generic OpenAI-compatible, Standard-security,
Production-oriented. Only two of these are `docker-compose` service/profile
concerns (`Docker mock`'s command is `docker compose --profile mock up`;
Ollama's is `docker compose --profile ollama-host up`) — Standard-security
and Production-oriented are reached by setting `POLICY_PATH` and
`APP_ENV=production` (plus the auth/session/hash-salt variables
`app/config.py`'s cross-field validator already requires) against the
*same* image, and Generic OpenAI-compatible and Local Python aren't Docker
concerns at all. Governing-rules discipline requires resolving this against
the documents, not against a plausible-sounding list — done above in
Context, and repeated here as its own numbered decision because it
determines everything that follows: this ADR does not add a
`standard-security` or `production` compose service, because SPEC.md's own
table doesn't ask for one.

### 2. `OLLAMA_PREFLIGHT_ENABLED` is a new, dedicated opt-in setting — not inferred from `UPSTREAM_BASE_URL`'s shape

SPEC.md §2.10 ties the `GET /api/tags` preflight to "the Ollama provider,"
but §2.10 itself says Ollama is "configuration of the generic
OpenAI-compatible adapter, not separate code" — there is no `OllamaProvider`
class to attach preflight-specific behaviour to, and no way to distinguish
"this `UPSTREAM_BASE_URL` is Ollama" from "this is some other
OpenAI-compatible endpoint" by inspecting the URL alone without guessing
(a self-hosted OpenAI-compatible gateway could also live at a
`host.docker.internal:PORT/v1`-shaped address; conversely, an operator
could point at a *remote* Ollama through a plain hostname). Rejected:
sniffing `UPSTREAM_BASE_URL` for `:11434` or a `host.docker.internal` host
— magic, undocumented, and wrong the moment someone runs Ollama on a
non-default port or a real hostname. Chosen: `OLLAMA_PREFLIGHT_ENABLED: bool
= False` (`app/config.py`), validated to require `UPSTREAM_BASE_URL` when
true (mock mode has no upstream to preflight-check), and set to `true` only
by the `ollama-host` compose service's own `environment:` block. This keeps
the generic-adapter code path (`app/providers/openai_compatible.py`)
completely unaware of Ollama, exactly as §2.10 intends, while giving the
`ollama-host` profile explicit, testable, non-magic control over whether
the preflight runs.

### 3. The preflight target URL is derived from `UPSTREAM_BASE_URL`, not a second URL setting

Given `OLLAMA_PREFLIGHT_ENABLED=true`, `app/providers/ollama_preflight.py`
derives the `/api/tags` target by stripping a trailing `/v1` (with or
without a trailing slash) from `UPSTREAM_BASE_URL` and appending
`/api/tags` — `http://host.docker.internal:11434/v1` becomes
`http://host.docker.internal:11434/api/tags`, matching Ollama's own layout
(the OpenAI-compatible surface lives at `/v1`, the native API one level up).
Rejected a second `OLLAMA_TAGS_URL`/`OLLAMA_HOST` setting: it would let the
two URLs silently point at different hosts, which is a configuration bug
class this design makes structurally impossible — there is exactly one
upstream host to check, because there is exactly one upstream host
configured. A base URL that doesn't end in `/v1` is used as-is rather than
rejected at startup: this only ever runs when an operator has explicitly
opted in, so an unexpected shape is *their* configuration to see fail with
a clear reachability message from the real HTTP call, not this function's
to silently guess around.

### 4. The preflight runs once, at startup, synchronously — not on every `/readyz` poll

SPEC.md §2.10 says "a **startup** preflight," singular. `AppState.__init__`
(`app/main.py`) — already fully synchronous, already doing a blocking
policy-file read — runs `check_ollama_preflight()` once via a plain
`httpx.Client` (not `AsyncClient`; no event loop is serving requests yet at
this point in `create_app()`, so there is nothing to gain from async here
and an `asyncio.run()` just to make one HTTP call would be needless
machinery) and caches the result on `AppState.provider_status`. `/readyz`
reads that cached value on every poll rather than re-checking Ollama's
liveness live each time. Rejected a per-poll re-check: `/readyz` is
documented and tested elsewhere in this codebase as fast and
dependency-light (its existing database check is a single `SELECT 1`); a
live network round-trip to a host service on every readiness probe (which
some orchestrators call every few seconds) would make `/readyz`'s latency
and failure modes depend on Ollama's, for a check SPEC.md explicitly scopes
to startup. The trade-off, stated plainly: if Ollama goes down *after* a
successful startup preflight, `/readyz` keeps reporting `provider: "ok"`
until the process restarts — a real gap, not hidden here, and consistent
with treating this as a startup gate rather than a liveness probe (nothing
in SPEC.md's DEP-003 wording asks for the latter).

### 5. Preflight failure modes both map to `provider: "unreachable"` — the public schema is not extended

`ReadyzDependencies.provider` (`app/schemas.py`) is
`Literal["ok", "unreachable", "not_configured"]`, unchanged. Two genuinely
different preflight failures exist — the host is unreachable at all, or
it's reachable but the configured model isn't pulled — and both are
reported as `"unreachable"` in the JSON body, distinguished only in the
startup log line (`app/providers/ollama_preflight.py`'s `message`, logged
at `WARNING` by `AppState.__init__`). Considered and rejected: adding a
fourth literal value (e.g. `"model_missing"`) to make the distinction
visible in the API response itself. The governing rules treat the API
contract as something that changes only with a documented, deliberate
reason — a fourth readiness state is a real option for a future phase if an
operator needs to distinguish the two cases programmatically, but nothing
in DEP-003's text asks for that ("a failed preflight MUST mark `/readyz`
not-ready with an actionable message" — the message requirement is
satisfied by the log line, not by the JSON body's enum). Verified live
(see "Verified, not merely asserted" below): both failure shapes produce
distinct, correctly-worded log messages and identical `503`/`unreachable`
`/readyz` behaviour.

### 6. `firewall` (mock) is profile-less; `firewall-ollama` is tagged `profiles: ["ollama-host"]` — and the two cannot both be started with one bare `--profile ollama-host up`

This is a real Docker Compose mechanics finding, not a design preference,
verified empirically against this machine's Compose v5.4.0 with a
throwaway three-service test file before touching the real
`docker-compose.yml`: **a service with no `profiles:` key always starts,
regardless of which profile (if any) is requested on the command line** —
confirmed via `docker compose config --services` under a bare invocation,
under `--profile mock`, and under `--profile ollama-host` (the last one
listed *both* `firewall` and `firewall-ollama`). This creates real tension
between two requirements that are both explicit and both binding:

- DEP-002, literal: `docker compose up --build` (no `--profile` flag, no
  `.env` edits) MUST yield mock mode. This is only satisfiable by a
  profile-less mock service — Compose has no YAML-declared "default active
  profile" mechanism, and the standing CFG-004/`.gitignore` rule against a
  tracked `.env` rules out the usual `COMPOSE_PROFILES=mock` in a committed
  `.env` workaround (Compose auto-reads a literal `.env` for that variable,
  but a fresh clone has none).
- SPEC.md's literal Ollama command, `docker compose --profile ollama-host
  up`, must not also silently bring up the mock service and collide with
  it on port 8000.

Resolved by naming the target service explicitly on the Ollama invocation
— verified (again empirically, not assumed) that `docker compose --profile
ollama-host up -d <service-name>` starts *only* the named service, even
though the profile-less sibling would otherwise also start under a bare
`up` with no service name. README.md's Ollama section therefore documents
`docker compose --profile ollama-host up --build firewall-ollama`, not
SPEC.md's bare form — a deliberate, tested departure from the literal
example text, chosen because the literal form does not do what SPEC.md
says it should (start only the Ollama-configured service) under real
Compose semantics on this machine. `docker compose --profile mock up` (no
service name) still works and is documented too: since `mock` is not tied
to any actually-tagged service, this command's behaviour is identical to a
bare `up` — `firewall` starts because it's profile-less, not because of the
flag — functionally correct even though the `mock` profile string is
technically inert.

### 7. `BIND_HOST` never drives the container's real socket bind — a pre-existing gap, left as-is and documented rather than silently patched

`app/config.py`'s `BIND_HOST`/`is_loopback_bind` govern only the SEC-003
cross-field check (whether unauthenticated operation is permitted); nothing
anywhere in this codebase — checked directly, there is no
`uvicorn.run()` call and no `if __name__ == "__main__":` block — wires
`BIND_HOST` into an actual bind address. The operator always passes
`--host`/`--port` on the `uvicorn` command line (every README example
does this explicitly). A container's own loopback interface is not
reachable through Docker's port-publishing at all, so the `Dockerfile`'s
`CMD` binds `0.0.0.0` unconditionally — not a choice, a requirement of
containerized deployment — while `BIND_HOST` itself is left at its default
(unset → `127.0.0.1`) in both compose services' `environment:` blocks.
Setting `BIND_HOST=0.0.0.0` there instead would make the `mock` profile's
own `Settings` cross-field validator correctly conclude it is bound
non-loopback with no keys configured, and refuse to start (SEC-003) —
breaking DEP-002. Since SPEC.md's own deployment-mode table lists Mock's
Auth column as "Optional, loopback," the intent is that this profile
*behave* as loopback-scoped, which `docker-compose.yml` achieves at the
layer that actually matters for real exposure: both services publish to
`127.0.0.1:8000:8000`, not `0.0.0.0:8000:8000` — nothing outside the host
machine can reach either container regardless of what `BIND_HOST`'s own
value claims about itself. The residual gap, stated plainly: `BIND_HOST`'s
value is simply disconnected from reality inside a container, in both
profiles, and always has been outside a container too (nothing enforces
that an operator's `--host` flag matches `BIND_HOST`). Fixing that
properly (e.g. an entrypoint that reads `BIND_HOST`/`BIND_PORT` and drives
`uvicorn.run()` itself) is a real, scoped improvement for a future phase —
not done here because it changes existing bare-metal/`Local Python`
behaviour that Phase 5's task is not chartered to touch.

### 8. Base image pinned by digest, refreshed deliberately

DEP-006: "a pinned base-image digest." `Dockerfile` pins
`python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
(both stages, via a single `ARG PYTHON_DIGEST`), obtained by actually
pulling the tag and reading `docker inspect`'s `RepoDigests` — not copied
from memory or a plausible-looking placeholder. Refreshing it later is a
one-line `ARG` edit plus a re-verified build, not a hunt through the file.

### 9. Non-root user with a fixed numeric UID/GID

DEP-006: "The container MUST run as a non-root user." `useradd --system
--uid 10001 --gid realguard` rather than an unqualified `useradd --system`
(which lets the base image assign whatever UID happens to be free) — a
fixed UID means the named volume's on-disk ownership (`/app/data`) stays
correct across a base-image rebuild that might otherwise reallocate system
UIDs differently. Verified live: `docker compose exec firewall id` →
`uid=10001(realguard) gid=10001(realguard)`.

### 10. `HEALTHCHECK` targets `/healthz`, not `/readyz` — exactly as DEP-006 says, and deliberately not the richer check

DEP-006 names `/healthz` specifically; SPEC.md's own `/healthz` contract
(API-015: "never touches the database, never rate limited") is a pure
liveness signal — "is the process alive and serving" — while `/readyz`
answers a different question ("is this instance ready to accept real
traffic," which can legitimately be `false` — e.g. a failed Ollama
preflight — without the container being unhealthy in Docker's sense).
Using `/readyz` for `HEALTHCHECK` would make Docker restart-loop a
container whose *process* is completely fine but whose *upstream* is
temporarily unreachable — the opposite of DEP-003's "MUST NOT crash the
process" intent, transplanted one layer up into container orchestration.
`python -c "import urllib.request..."` (stdlib) rather than `curl`/`wget`:
no extra package in the runtime stage, one dependency install fewer to
keep current.

### 11. Two named services building one image, not one parameterised service

`firewall` and `firewall-ollama` are separate `docker-compose.yml` service
blocks (both `build: .`, same `Dockerfile`, same resulting `image:
real-guard-v1:latest`) rather than one service whose environment a
`--profile` flag conditionally alters — Compose has no mechanism for the
latter (a service's `environment:` block cannot itself be conditional on
which profile activated it), and decision 6 already established why two
service *identities* are what makes the mutual-exclusivity/naming solution
work at all. Each gets its own named volume (`firewall-mock-data`,
`firewall-ollama-data`) rather than sharing one — a mock-mode SQLite file
and a live-mode one should never be the same file; sharing would make an
approval created in one profile silently visible (or, worse, subtly
inconsistent) in the other.

## Found while verifying, fixed

- **Successful-preflight log visibility.** The first implementation logged
  a successful preflight (`provider: "ok"`) at `INFO`. Running the real
  `ollama-host` container and reading `docker compose logs` showed the
  success message never appeared — this codebase has no
  `logging.basicConfig()` call anywhere (a pre-existing gap: `LOG_LEVEL` is
  a validated `Settings` field that nothing currently applies), so Python's
  handler-of-last-resort default (`WARNING` and above only) silently
  swallows anything logged below that level. The *failure* path was
  already `WARNING` (matching DEP-004's own precedent for the mock-mode
  banner) and was confirmed to appear correctly. Left the success path at
  `INFO` rather than bumping it to `WARNING` — an operator does not need a
  warning-level log line to be told everything is fine, and `/readyz`
  already reports `provider: "ok"` for that case — but this is documented
  here rather than silently left as a surprise: a future phase that wires
  up `LOG_LEVEL` properly (decision 7 names the same root cause for
  `BIND_HOST`) will make the success line visible in `LOG_LEVEL=DEBUG`/
  `INFO` deployments without any change to this module.
- **Ruff `S603`/`S607` on the new Docker smoke test.** `tests/test_docker_smoke.py`
  deliberately shells out to `docker` with fixed, literal argument lists —
  the existing `tests/*` per-file-ignore list (`S101`/`S104`/`S105`/`S106`)
  didn't cover subprocess rules. Added a second, file-scoped
  `per-file-ignores` entry for exactly this file rather than broadening the
  blanket `tests/*` ignore list to cover every test file, since no other
  test shells out to an external process.
- **No prior tension found in `app/providers/openai_compatible.py`'s own
  comment.** Its module docstring already correctly named the preflight as
  "Phase 5 scope (PLAN.md §6) — this module only needs to be reachable and
  correct; wiring it into a live compose profile with a preflight check is
  a later phase's work" — read and confirmed accurate before writing
  anything, not assumed. No code change was needed there; the adapter
  itself required nothing new for this phase.

## Verified, not merely asserted

- `ruff check .`: clean. `ruff format --check .`: clean, 72 files.
  `mypy app` (strict): clean, 37 source files.
- `pytest`: 361 passed, 0 skipped, 0 failed **on this machine**, which has
  both a running Docker daemon and a running local Ollama with `qwen3:8b`
  pulled — 26 new tests (10 in `tests/test_ollama_preflight.py`, 3 in
  `tests/test_config.py`, 4 in `tests/test_gateway.py`, 5 in
  `tests/test_docker_smoke.py`, 4 in `tests/test_ollama_live.py`), up from
  335 at the end of Phase 4. On a machine without Docker and/or Ollama
  reachable, the `docker`- and `ollama`-marked tests self-skip (verified by
  reading `_docker_available()`/`_ollama_ready()`'s exception handling and
  by the unit-level `tests/test_ollama_preflight.py` cases that simulate
  every unreachable/timeout/malformed-response shape via `respx` — not by
  actually disabling Docker or Ollama on this machine to re-run the suite,
  which would have meant tearing down the very Ollama installation Phase
  5's own precondition requires) — this is the literal PLAN.md Phase 5
  acceptance wording: "Ollama tests pass locally; they are skipped, not
  failed, in CI where no Ollama exists."
- Coverage: 93.5% line / 80.3% branch on `app/` (up from Phase 4's 90%/
  79.3% — `app/providers/ollama_preflight.py` itself at 100%).
- `python scripts/validate_contracts.py`: all checks pass, including the
  frozen 54-case corpus (untouched by this phase) and `openapi.json`'s
  8-path contract (unchanged — this phase adds no new HTTP routes).
- `docker build` on the real `Dockerfile`: succeeds
  (`real-guard-v1:latest`, multi-stage, final image built from the pinned
  digest).
- `docker compose up -d firewall` (the `mock` profile, no `.env`, no flags
  beyond `-d`): container reaches Docker's own `healthy` status; `curl
  http://127.0.0.1:8000/healthz` → `{"status":"ok"}`; `curl
  http://127.0.0.1:8000/readyz` → `{"ready":true,"mode":"mock",
  "dependencies":{"database":"ok","policy":"ok","provider":"ok"}}`; the
  README's benign-request curl → `200`, `firewall.decision: "ALLOW"`; the
  README's injection curl → `403`. `docker compose exec firewall id` →
  `uid=10001(realguard)`, confirmed non-root. `docker compose restart
  firewall` → container returns to `healthy` with no error.
- `docker compose --profile ollama-host up -d firewall-ollama` against the
  real host Ollama (already running on this machine, `qwen3:8b` pulled):
  container reaches `healthy`; `curl http://127.0.0.1:8000/readyz` →
  `{"ready":true,"mode":"live","dependencies":{"database":"ok","policy":"ok","provider":"ok"}}`
  — the preflight actually reached the host Ollama through
  `host.docker.internal` + `extra_hosts: host-gateway` and confirmed
  `qwen3:8b` present, from inside the container, over the real Docker
  network path this phase is supposed to prove works.
- The preflight **failure** path, run for real (not only via `respx`): a
  container started with `UPSTREAM_MODEL=does-not-exist:8b` (real host
  reachable, wrong model name) logged `Ollama preflight: reached
  http://host.docker.internal:11434/api/tags, but the configured model
  'does-not-exist:8b' is not pulled on the host (available: ['qwen3:8b']).
  Run \`ollama pull does-not-exist:8b\` on the host, then restart the
  container.` and `curl http://127.0.0.1:8000/readyz` returned `HTTP 503`,
  `"ready":false`, `"provider":"unreachable"` — while `/healthz` kept
  returning `200`, proving DEP-003's "MUST NOT crash the process" holds in
  practice, not just in the unit tests.
- `tests/test_ollama_live.py` (4 tests, real `qwen3:8b` inference, ~110s
  total): the preflight function itself against the real host; `/readyz`
  reporting ready against the real host; a benign request producing a
  real, non-mock, non-empty completion with `firewall.mode: "live"`; a
  prompt-injection request denied `403` before the real model is ever
  called — directly exercising Phase 5's exit-gate wording ("the identical
  corpus verdicts hold against a real model, confirming detection does not
  depend on the mock") for the two corpus-representative shapes this file
  covers (a full 54-case run against live inference is a manual/benchmark
  exercise, not a `pytest` default-run one, given real 8B inference
  latency — noted honestly, not silently expanded into a claim this file
  doesn't make).
- All Docker/Ollama artefacts (containers, the smoke-test image, the
  Ollama-profile named volume, the throwaway Compose-mechanics test
  directory) were removed after verification — nothing left running or
  lingering on disk from this phase's manual testing.

## Consequences

- The `mock` and `ollama-host` `docker-compose.yml` profiles both work as
  real, tested deployment paths — not just written and assumed. DEP-002,
  DEP-003, and DEP-006 are each directly verified against a real build and
  a real run, not only against unit tests.
- `/readyz`'s `provider` field now carries real meaning in the Ollama
  profile (`ok`/`unreachable`, cached from the one startup preflight) where
  it was previously a hardcoded `"not_configured"` placeholder for every
  live upstream; every other live-mode configuration (a generic
  OpenAI-compatible endpoint with `OLLAMA_PREFLIGHT_ENABLED` left `false`)
  keeps exactly its pre-Phase-5 behaviour, unchanged.
- Two real, documented gaps carried forward rather than silently patched
  (decisions 4 and 7): `/readyz`'s Ollama status is startup-cached, not
  live, until process restart; and `BIND_HOST` still never drives an
  actual socket bind anywhere in this codebase, containerized or not.
  Neither was in this phase's chartered scope to fix.
- Still open, unaffected by this phase, and not claimed otherwise: WS-12
  (structured audit logging beyond the existing hash-chained
  `audit_events` rows, Prometheus metrics, `GET /metrics`), WS-13 (rate
  limiting — validated at startup, still unenforced), WS-17 (SSRF hardening
  beyond the existing production-only check, dependency scanning,
  `pip-audit`/Trivy in CI), and `encrypted_payloads`
  (`CONTENT_RETENTION=encrypted` has no storage backend yet) — all
  scheduled for Phase 6 or later per PLAN.md, and untouched by this one.
