# syntax=docker/dockerfile:1
#
# real-guard-v1 container image. PLAN.md §6 Phase 5 / WS-15, SPEC.md §14
# (DEP-002, DEP-003, DEP-006).
#
# Multi-stage: the builder stage resolves and installs dependencies into a
# venv; the runtime stage copies only that venv plus the application source
# — no compiler toolchain, no pip cache, no dev/test dependencies ship in
# the final image. Both stages pin the same base-image digest (DEP-006)
# rather than a floating `python:3.12-slim` tag, so a rebuild months from
# now still starts from the exact bytes this was built and tested against;
# see docs/adr/0007-phase5-ollama-profile-and-docker-deployment.md for how
# that digest was obtained and how to refresh it deliberately.

ARG PYTHON_DIGEST=sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

FROM python:3.12-slim@${PYTHON_DIGEST} AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Only what pyproject.toml's build backend and package-data declaration
# need — tests/, docs/, PLAN.md/SPEC.md are irrelevant to the runtime image
# (and excluded from the build context entirely by .dockerignore).
COPY pyproject.toml README.md LICENSE ./
COPY app ./app
COPY policies ./policies

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.12-slim@${PYTHON_DIGEST} AS runtime

# DEP-006: non-root, fixed UID/GID (no dependency on a base image's own
# uid allocation, which can change between rebuilds of the same tag).
RUN groupadd --system --gid 10001 realguard \
    && useradd --system --uid 10001 --gid realguard --home-dir /app --create-home realguard

WORKDIR /app
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY policies ./policies

# WS-17 (Phase 6, ADR 0008): a real Trivy scan of this image found two HIGH
# findings (GHSA-6v7p-g79w-8964, CVE-2025-47273) that trace to *pip itself*
# — not to real-guard-v1's dependency tree at all (`pip show msgpack` finds
# nothing; neither is a project dependency). pip vendors its own copies of
# msgpack and setuptools (see `pip/_vendor/vendor.txt`) for its own internal
# use while resolving/installing packages; both the base image's
# system-level pip and the venv's own copy (upgraded by `pip install
# --upgrade pip` above) carry them. pip serves no purpose in a running
# container — dependencies are already installed by the time this image
# runs — so removing every copy of it (system and venv) removes both
# findings entirely, verified by re-scanning the built image (docs/adr/0008
# has the before/after counts).
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
    /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
    /usr/local/lib/python3.12/site-packages/setuptools \
    /usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
    /usr/local/lib/python3.12/site-packages/pkg_resources \
    /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
    /opt/venv/lib/python3.12/site-packages/pip \
    /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
    /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.*

# DATABASE_URL defaults to sqlite:///./data/realguard.db (app/config.py) —
# relative to the process's CWD, /app here. Created and owned by the
# unprivileged runtime user up front; docker-compose.yml mounts a named
# volume over it for durability across `docker compose restart`/recreate
# (Phase 4's exit gate: no approval-workflow state lost on restart).
RUN mkdir -p /app/data && chown -R realguard:realguard /app

USER realguard

EXPOSE 8000

# DEP-006: HEALTHCHECK against /healthz, exactly as required ("declare a
# HEALTHCHECK against /healthz" — not /readyz, which is a separate, richer
# check that can legitimately report not-ready — e.g. a failed Ollama
# preflight, DEP-003 — without the process itself being unhealthy). Uses
# the stdlib (urllib) rather than curl/wget so no extra package needs
# installing into the runtime stage.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=2)" || exit 1

# BIND_HOST (app/config.py) governs only the Settings model's own
# loopback/authentication posture check, never the literal uvicorn bind
# address — nothing in this codebase wires BIND_HOST into a bind call
# (there is no `if __name__ == "__main__"` / uvicorn.run() entrypoint; the
# operator always passes --host/--port on the command line, as README.md's
# every example does). A container's own loopback interface is not
# reachable through Docker's port-publishing at all, so 0.0.0.0 is not a
# choice here, it is what containerized deployment requires — the actual
# question DEP-002's "mock is loopback by default" spirit turns on is host
# exposure, which docker-compose.yml controls by publishing to
# 127.0.0.1:8000 rather than 0.0.0.0:8000. See ADR 0007's "BIND_HOST vs.
# the container's real socket bind" decision for the full reasoning and
# the residual gap this leaves (BIND_HOST's own value never reflects the
# literal bind address in the Docker profiles either way).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
