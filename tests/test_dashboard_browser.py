"""Real headless-Chromium verification of the reviewer dashboard, via
Playwright. Phase 9 gap-closure (ADR 0012) — see
docs/adr/0011-phase9-release-preparation.md decision-free "Manual validation"
line and docs/adr/0010's Decision 5, both of which honestly named the same
gap: every prior dashboard walkthrough (`tests/test_dashboard.py`,
`tests/test_session.py`, the README's "Dashboard" section) drives the HTTP
layer directly (`TestClient` or `curl`) and has never actually rendered the
page in a browser, so nothing before this file has ever exercised:

- the browser's own enforcement of the `Content-Security-Policy` header
  `app/main.py`'s `SecurityHeadersMiddleware` sends (a unit test can assert
  the header's *value*; only a real browser can prove the header is
  *enforced* — that an inline script or style the templates might still
  contain would actually be refused);
- HTMX's actual DOM-swap behaviour (a unit test can assert the *response
  body* of `POST /dashboard/approvals/{id}/decide` is the right fragment;
  only a real browser running the vendored `htmx.min.js` can prove that
  fragment is actually spliced into the live page without a full navigation).

This module drives a real `uvicorn` subprocess (mock mode, both key sets
configured — the same shape `scripts/benchmark.py` and
`tests/test_docker_smoke.py` already use to spin up a real process) and a
real Chromium instance launched by Playwright, never `TestClient`, never a
mocked transport. It self-skips (never fails) when Chromium cannot actually
be launched in the current environment, the same "skip, never fail" contract
`docker` and `ollama` already use (pyproject.toml's `browser` marker) — see
this module's own `browser_session` fixture (the `chromium.launch()` call
and its `except`) for exactly what triggers the skip, and the Phase 9
browser-verification completion report for the two real runs
(forced-unavailable → skip; normal → pass) that exercised both branches for
real, not just by inspection.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.browser

REPO_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = REPO_ROOT / "docs" / "screenshots"

# A host/port pair distinct from every other live-server test in this suite
# (test_docker_smoke.py uses 18000) so a developer running the full suite
# locally never collides two "real process" tests against the same socket.
HOST = "127.0.0.1"
PORT = 18020
BASE_URL = f"http://{HOST}:{PORT}"

SERVICE_KEY = "svc_browser_test_key_0123456789abcdef01"
REVIEWER_KEY = "rev_browser_test_key_0123456789abcdef01"

_STARTUP_TIMEOUT_SECONDS = 20.0


def _wait_for_healthz(deadline: float) -> None:
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/healthz", timeout=1.0) as resp:  # noqa: S310
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError) as e:
            last_error = e
        time.sleep(0.2)
    raise TimeoutError(f"server never became healthy at {BASE_URL}/healthz: {last_error}")


@pytest.fixture(scope="module")
def live_server() -> Iterator[str]:
    """A real `uvicorn app.main:app` subprocess, mock mode (no
    `UPSTREAM_BASE_URL`), both a service and a reviewer key configured — not
    a `TestClient`, not a mocked transport. Mirrors
    `tests/test_docker_smoke.py`'s `running_mock_container` fixture and
    `scripts/benchmark.py`'s `run_benchmark()` startup shape.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="realguard-browser-test-"))
    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "development",
            "BIND_HOST": HOST,
            "BIND_PORT": str(PORT),
            "DATABASE_URL": f"sqlite:///{tmp_dir / 'browser.db'}",
            "FIREWALL_API_KEYS": SERVICE_KEY,
            "FIREWALL_REVIEWER_KEYS": REVIEWER_KEY,
        }
    )
    env.pop("UPSTREAM_BASE_URL", None)

    proc = subprocess.Popen(  # noqa: S603 — fixed argv, `sys.executable` is this
        # interpreter's own absolute path, no user/network input reaches this call.
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            HOST,
            "--port",
            str(PORT),
            "--log-level",
            "warning",
        ],
        cwd=REPO_ROOT,
        env=env,
    )
    try:
        _wait_for_healthz(time.monotonic() + _STARTUP_TIMEOUT_SECONDS)
        yield BASE_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture
async def browser_session(
    live_server: str,
) -> AsyncIterator[tuple[Any, list[str], list[str]]]:
    """Yields `(page, console_error_texts, page_error_texts)` against a real
    Chromium instance, plus a `window.__cspViolations` array (read via
    `page.evaluate` in the test itself) populated by a real
    `securitypolicyviolation` listener injected before any navigation.

    Skips the test cleanly — never fails it — if Chromium genuinely cannot
    be launched here (browsers never downloaded, or a sandboxed environment
    that blocks launching a browser process entirely). Playwright's own
    exception hierarchy has changed module paths across versions, so this
    deliberately catches the broad `Exception` from exactly one call
    (`chromium.launch()`) — narrow in scope, not narrow in type — the same
    trade-off `tests/test_docker_smoke.py`'s own availability check makes
    for `docker info`.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as e:  # noqa: BLE001 — see docstring
            pytest.skip(
                "Chromium is not launchable in this environment "
                f"({type(e).__name__}: {e}). Run `playwright install chromium` "
                "(and, on Linux, `playwright install-deps chromium`) and re-run "
                "`pytest -m browser`."
            )

        context = await browser.new_context()
        page = await context.new_page()

        console_errors: list[str] = []
        page_errors: list[str] = []
        page.on(
            "console",
            lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
        )
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))

        # Real CSP enforcement check: a browser fires `securitypolicyviolation`
        # on `document` for every resource/script/style the CSP header actually
        # blocks — this is the browser's own enforcement, not a header-value
        # assertion. Injected via `add_init_script` so it is present on every
        # document this page ever navigates to, from the very first navigation.
        await context.add_init_script(
            """
            window.__cspViolations = [];
            document.addEventListener('securitypolicyviolation', (e) => {
                window.__cspViolations.push({
                    directive: e.violatedDirective,
                    blockedURI: e.blockedURI,
                    sourceFile: e.sourceFile
                });
            });
            """
        )

        try:
            yield page, console_errors, page_errors
        finally:
            await context.close()
            await browser.close()


async def test_dashboard_real_browser_login_csp_and_htmx_flow(
    live_server: str,
    browser_session: tuple[Any, list[str], list[str]],
) -> None:
    """The primary gap-closure test. In one real browser session:

    1. Seeds a real `NEED_APPROVAL` case via the same API the curl
       walkthroughs use (`POST /v1/chat/completions`, service key).
    2. Navigates real Chromium to `/dashboard/login`, screenshots it.
    3. Logs in through the actual rendered `<form>` (not a direct cookie
       injection), lands on `/dashboard`.
    4. Confirms the real `Content-Security-Policy` response header Chromium
       received matches what `app/main.py` sends, on both pages.
    5. Screenshots the queue with the pending item visible.
    6. Clicks the real rendered "Approve" button — an HTMX-driven
       `hx-post` + `hx-swap="outerHTML"`, not a form submission — and
       confirms via DOM assertions (not text re-parsing) that the row
       updates in place with no navigation (`page.url` unchanged).
    7. Screenshots the queue immediately after the decision.
    8. Confirms the original request actually resumed, via the same
       polling endpoint the curl walkthrough uses.
    9. Asserts no `securitypolicyviolation` event fired and no console
       error/page error mentions a CSP refusal, for the whole session.
    """
    page, console_errors, page_errors = browser_session

    create = httpx.post(
        f"{live_server}/v1/chat/completions",
        headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        json={
            "messages": [
                {
                    "role": "user",
                    "content": "Based on these symptoms, can you give me a specific "
                    "medical diagnosis?",
                }
            ]
        },
        timeout=10.0,
    )
    assert create.status_code == 202
    approval_id = create.json()["approval_id"]
    request_id = create.json()["request_id"]

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Login page ------------------------------------------------
    login_response = await page.goto(f"{live_server}/dashboard/login")
    assert login_response is not None
    assert login_response.status == 200
    assert login_response.headers.get("content-security-policy") == "default-src 'self'", (
        "real browser response did not carry the expected CSP header on the login page"
    )
    assert await page.title() == "Sign in — real-guard-v1 dashboard"
    await page.screenshot(path=str(SCREENSHOT_DIR / "dashboard-login.png"))

    # --- 2. Log in through the real rendered form ----------------------
    await page.fill("#reviewer_key", REVIEWER_KEY)
    await page.click("button.rg-button-primary")
    await page.wait_for_url(f"{live_server}/dashboard")
    assert await page.title() == "Approval queue — real-guard-v1 dashboard"

    dashboard_response = await page.goto(f"{live_server}/dashboard")
    assert dashboard_response is not None
    assert dashboard_response.headers.get("content-security-policy") == "default-src 'self'", (
        "real browser response did not carry the expected CSP header on the dashboard page"
    )

    # --- 3. Queue with the pending approval visible --------------------
    row_selector = f"#row-{approval_id}"
    await page.wait_for_selector(row_selector)
    row = page.locator(row_selector)
    assert await row.count() == 1
    assert await row.locator('[data-testid="approve-button"]').count() == 1
    assert await row.locator('[data-testid="deny-button"]').count() == 1
    await page.screenshot(path=str(SCREENSHOT_DIR / "dashboard-queue.png"), full_page=True)

    # --- 4. Click the real Approve button; confirm HTMX swap, no nav ---
    url_before_click = page.url
    await row.locator('[data-testid="approve-button"]').click()
    await page.wait_for_selector(f'{row_selector} [data-testid="decision-status"]')
    assert page.url == url_before_click, (
        "page navigated on decision click — this should be an in-place HTMX swap"
    )
    decision_text = await page.locator(
        f'{row_selector} [data-testid="decision-status"]'
    ).inner_text()
    assert "APPROVE" in decision_text
    assert "COMPLETED" in decision_text
    await page.screenshot(path=str(SCREENSHOT_DIR / "dashboard-decided.png"), full_page=True)

    # --- 5. The original request actually resumed, confirmed over the API --
    poll = httpx.get(
        f"{live_server}/v1/firewall/requests/{request_id}",
        headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        timeout=10.0,
    )
    assert poll.json()["status"] == "COMPLETED"

    # --- 6. Real CSP enforcement: no violation fired, no refusal logged ----
    csp_violations = await page.evaluate("window.__cspViolations")
    assert csp_violations == [], f"a real CSP violation fired during this session: {csp_violations}"
    csp_console_errors = [
        m for m in console_errors if "Content Security Policy" in m or "Refused to" in m
    ]
    assert csp_console_errors == [], f"console logged a CSP refusal: {csp_console_errors}"
    assert page_errors == [], f"an uncaught page error occurred: {page_errors}"
