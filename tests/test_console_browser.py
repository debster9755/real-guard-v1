"""Real headless-Chromium verification of the `/console` SPA, via Playwright.
ADR 0014, using the exact pattern `tests/test_dashboard_browser.py`
established in Phase 9 gap-closure (ADR 0012): a real `uvicorn` subprocess
(mock mode, both key sets configured), a real Chromium instance, no
`TestClient` and no mocked transport anywhere.

`tests/test_console_api.py` covers the `/console/api/*` HTTP surface
directly. This module exists for the two things no HTTP-level test can
prove about a *client-rendered* application:

- **CSP is actually satisfied by the built bundle.** app/main.py sends
  `Content-Security-Policy: default-src 'self'` with no `unsafe-inline`
  (SEC-008), and Next.js's App Router static export inlines its React Flight
  payload as `<script>self.__next_f.push(...)</script>` blocks by default —
  40 of them across 6 documents in this project's own build. Every one would
  be refused by a real browser, rendering a blank page, while every
  `TestClient`/`curl` check kept passing. `web/scripts/externalize-inline.mjs`
  rewrites them into real same-origin files at build time; this test is what
  proves a browser agrees, via a real `securitypolicyviolation` listener —
  the identical technique, and the identical class of defect, ADR 0012 found
  once already in the vendored htmx build.

- **The SPA actually works.** A static-export shell that 200s over `curl` can
  still fail to hydrate, fail to attach its session cookie, or fail to reach
  its own API. Only driving the real rendered controls proves the whole
  chain: login form -> `rg_console_session` cookie -> client-side route
  change -> queue fetch -> review modal -> a real decision that resumes a
  real held request.

Self-skips (never fails) when Chromium cannot be launched, or when no
`npm run build` output exists yet — the same "skip, never fail" contract
`docker`/`ollama`/`browser` markers already use across this suite.
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
# (test_docker_smoke.py uses 18000, test_dashboard_browser.py uses 18020), so
# running the full suite locally never collides two real processes on one
# socket.
HOST = "127.0.0.1"
PORT = 18030
BASE_URL = f"http://{HOST}:{PORT}"

SERVICE_KEY = "svc_console_browser_key_0123456789abcd"
REVIEWER_KEY = "rev_console_browser_key_0123456789abcd"

_STARTUP_TIMEOUT_SECONDS = 20.0

SENSITIVE_PROMPT = "Based on these symptoms, can you give me a specific medical diagnosis?"


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
def built_console() -> Path:
    """The built SPA, or a clean skip. Uses `app/console_api.py`'s own
    resolver rather than a second hardcoded path, so this test and the
    application can never disagree about where the build lives."""
    from app.console_api import find_console_static_dir

    static_dir = find_console_static_dir()
    if static_dir is None:
        pytest.skip(
            "No built /console frontend found. Run `npm ci && npm run build` in web/ "
            "(Node 22+) and re-run `pytest -m browser`."
        )
    return static_dir


@pytest.fixture(scope="module")
def live_server(built_console: Path) -> Iterator[str]:
    """A real `uvicorn app.main:app` subprocess in mock mode — the same shape
    `tests/test_dashboard_browser.py`, `tests/test_docker_smoke.py` and
    `scripts/benchmark.py` all use."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="realguard-console-browser-"))
    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "development",
            "BIND_HOST": HOST,
            "BIND_PORT": str(PORT),
            "DATABASE_URL": f"sqlite:///{tmp_dir / 'console.db'}",
            "FIREWALL_API_KEYS": SERVICE_KEY,
            "FIREWALL_REVIEWER_KEYS": REVIEWER_KEY,
        }
    )
    env.pop("UPSTREAM_BASE_URL", None)

    proc = subprocess.Popen(  # noqa: S603 — fixed argv, `sys.executable` is this
        # interpreter's own absolute path; no user/network input reaches this call.
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
    """`(page, console_error_texts, page_error_texts)` against a real
    Chromium, plus a `window.__cspViolations` array populated by a real
    `securitypolicyviolation` listener injected before any navigation.

    Skips cleanly — never fails — when Chromium genuinely cannot be launched.
    Playwright's exception hierarchy has moved across versions, so this
    catches the broad `Exception` from exactly one call (`chromium.launch()`)
    — narrow in scope, not in type — exactly as
    `tests/test_dashboard_browser.py` does.
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

        context = await browser.new_context(viewport={"width": 1280, "height": 900})
        page = await context.new_page()

        console_errors: list[str] = []
        page_errors: list[str] = []
        page.on(
            "console",
            lambda msg: console_errors.append(msg.text) if msg.type == "error" else None,
        )
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))

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


async def test_console_real_browser_login_csp_and_decide_flow(
    live_server: str,
    browser_session: tuple[Any, list[str], list[str]],
) -> None:
    """One real browser session, end to end:

    1. Seed a real `NEED_APPROVAL` case over the API (service key).
    2. Navigate real Chromium to `/console/login/`; screenshot.
    3. Sign in through the actual rendered form; land on `/console/`.
    4. Confirm the real CSP header on both documents, and that the overview
       rendered real data (stat cards, the recharts SVG, the mock banner).
    5. Navigate to the queue via the real sidebar link (client-side routing,
       no full page load); screenshot with the pending row visible.
    6. Open the review modal, read the transformed preview, click the real
       Approve button; screenshot the decided state.
    7. Confirm the held request actually resumed, over the same polling
       endpoint the curl walkthrough uses.
    8. Assert no `securitypolicyviolation` fired, no CSP refusal was logged,
       and no uncaught page error occurred, for the whole session.
    """
    page, console_errors, page_errors = browser_session

    create = httpx.post(
        f"{live_server}/v1/chat/completions",
        headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        json={"messages": [{"role": "user", "content": SENSITIVE_PROMPT}]},
        timeout=10.0,
    )
    assert create.status_code == 202, create.text
    approval_id = create.json()["approval_id"]
    request_id = create.json()["request_id"]

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Sign-in page -------------------------------------------------
    login_response = await page.goto(f"{live_server}/console/login/")
    assert login_response is not None
    assert login_response.status == 200
    assert login_response.headers.get("content-security-policy") == "default-src 'self'", (
        "real browser response did not carry the expected CSP header on /console/login/"
    )
    await page.wait_for_selector('[data-testid="login-submit"]')
    assert await page.title() == "Sign in — real-guard-v1 console"
    await page.screenshot(path=str(SCREENSHOT_DIR / "console-login.png"), full_page=True)

    # --- 2. Sign in through the real rendered form -----------------------
    await page.fill('[data-testid="reviewer-key-input"]', REVIEWER_KEY)
    await page.click('[data-testid="login-submit"]')
    await page.wait_for_url(f"{live_server}/console/")
    await page.wait_for_selector('[data-testid="overview"]')

    overview_response = await page.goto(f"{live_server}/console/")
    assert overview_response is not None
    assert overview_response.headers.get("content-security-policy") == "default-src 'self'", (
        "real browser response did not carry the expected CSP header on /console/"
    )
    await page.wait_for_selector('[data-testid="overview"]')

    # DEP-004: mock mode is visible in this UI too.
    await page.wait_for_selector('[data-testid="mock-mode-banner"]')
    # The SPA hydrated and actually fetched: the identity id came from
    # `GET /console/api/session`, not from the pre-rendered shell.
    identity_text = await page.locator('[data-testid="identity-id"]').inner_text()
    assert identity_text.startswith("key_")
    # recharts really rendered an SVG from real registry data — and really
    # drew a bar in it. Asserting only on the <svg> is not enough: recharts
    # animates bars up from zero width by default, so an empty pair of axes
    # satisfies "an SVG exists" while showing the reviewer nothing (which is
    # exactly what the first run of this test captured).
    await page.wait_for_selector('[data-testid="chart-verdicts"] svg')
    bar_width = await page.evaluate(
        """() => {
            const rects = document.querySelectorAll(
                '[data-testid="chart-verdicts"] .recharts-bar-rectangle path'
            );
            return Math.max(0, ...Array.from(rects, (r) => r.getBoundingClientRect().width));
        }"""
    )
    assert bar_width > 1, (
        f"the verdict chart drew no visible bar (widest was {bar_width}px) — "
        "the axes rendered but the data did not"
    )
    # Park the pointer off the chrome before every screenshot, so a stray
    # :hover state on whatever was last clicked is not baked into the image
    # published in README.md.
    await page.mouse.move(900, 780)
    await page.screenshot(path=str(SCREENSHOT_DIR / "console-overview.png"), full_page=True)

    # --- 3. Queue, reached by the real sidebar link ----------------------
    url_before_nav = page.url
    await page.click('[data-testid="nav-approvals"]')
    await page.wait_for_url(f"{live_server}/console/approvals/")
    assert page.url != url_before_nav
    # `wait_for_url` resolves on the History API change, which happens
    # *before* React re-renders the shell against the new pathname — waiting
    # for the sidebar's own `aria-current` to move is what actually proves
    # the client-side route change propagated into the rendered tree, and
    # not merely into the address bar. (Screenshotting in that gap is how
    # this was noticed: the captured frame still showed "Overview" active.)
    await page.wait_for_selector('[data-testid="nav-approvals"][aria-current="page"]')
    assert (
        await page.locator('[data-testid="nav-overview"][aria-current="page"]').count() == 0
    ), "two sidebar items claimed to be the current page at once"
    row_selector = f'[data-testid="row-{approval_id}"]'
    await page.wait_for_selector(row_selector)
    assert await page.locator(row_selector).count() == 1
    await page.mouse.move(900, 780)
    await page.screenshot(path=str(SCREENSHOT_DIR / "console-approvals.png"), full_page=True)

    # --- 4. Review modal, then a real Approve ----------------------------
    await page.click(f'[data-testid="review-{approval_id}"]')
    await page.wait_for_selector('[data-testid="review-modal"]')
    preview_text = await page.locator('[data-testid="preview-json"]').inner_text()
    assert '"messages"' in preview_text, "the review modal did not render the preview JSON"

    # Deny is disabled until a note is typed — the client-side half of the
    # required-note rule (the server enforces it regardless; see
    # tests/test_console_api.py::test_deny_requires_a_note_server_side).
    assert await page.locator('[data-testid="deny-button"]').is_disabled()

    await page.mouse.move(900, 780)
    await page.screenshot(path=str(SCREENSHOT_DIR / "console-review.png"), full_page=True)

    await page.click('[data-testid="approve-button"]')
    await page.wait_for_selector('[data-testid="decision-flash"]')
    flash = await page.locator('[data-testid="decision-flash"]').inner_text()
    assert "APPROVE" in flash
    # APR-011: the approval resumed inline, so its real final state is
    # COMPLETED — the SPA refetches rather than guessing this.
    assert "COMPLETED" in flash
    await page.mouse.move(900, 780)
    await page.screenshot(path=str(SCREENSHOT_DIR / "console-decided.png"), full_page=True)

    # The row really left the PENDING tab.
    assert await page.locator(row_selector).count() == 0

    # --- 5. The held request actually resumed, confirmed over the API ----
    poll = httpx.get(
        f"{live_server}/v1/firewall/requests/{request_id}",
        headers={"Authorization": f"Bearer {SERVICE_KEY}"},
        timeout=10.0,
    )
    assert poll.json()["status"] == "COMPLETED"

    # --- 6. Real CSP enforcement ----------------------------------------
    csp_violations = await page.evaluate("window.__cspViolations")
    assert csp_violations == [], f"a real CSP violation fired during this session: {csp_violations}"
    csp_console_errors = [
        m for m in console_errors if "Content Security Policy" in m or "Refused to" in m
    ]
    assert csp_console_errors == [], f"console logged a CSP refusal: {csp_console_errors}"
    assert page_errors == [], f"an uncaught page error occurred: {page_errors}"

    # --- 7. The screenshots are real pages, not blank or error frames ----
    for name in (
        "console-login",
        "console-overview",
        "console-approvals",
        "console-review",
        "console-decided",
    ):
        path = SCREENSHOT_DIR / f"{name}.png"
        assert path.is_file(), f"{path} was not written"
        assert path.stat().st_size > 8_000, (
            f"{path} is {path.stat().st_size} bytes — too small to be a rendered page; "
            "a blank or error screen is the usual cause"
        )


async def test_console_dark_mode_toggle_persists(
    live_server: str,
    browser_session: tuple[Any, list[str], list[str]],
) -> None:
    """The dark-mode toggle really changes the rendered theme and really
    survives a reload — the `localStorage` write plus the pre-paint
    `theme-init.js` (an external file precisely because SEC-008's CSP refuses
    the usual inline bootstrap snippet)."""
    page, _console_errors, page_errors = browser_session

    await page.goto(f"{live_server}/console/login/")
    await page.wait_for_selector('[data-testid="login-submit"]')
    await page.fill('[data-testid="reviewer-key-input"]', REVIEWER_KEY)
    await page.click('[data-testid="login-submit"]')
    await page.wait_for_selector('[data-testid="theme-toggle"]')

    before = await page.evaluate("document.documentElement.classList.contains('dark')")
    await page.click('[data-testid="theme-toggle"]')
    after = await page.evaluate("document.documentElement.classList.contains('dark')")
    assert after is not before, "the theme toggle did not change the <html> class"

    await page.reload()
    await page.wait_for_selector('[data-testid="theme-toggle"]')
    persisted = await page.evaluate("document.documentElement.classList.contains('dark')")
    assert persisted is after, "the theme choice did not survive a reload"

    assert page_errors == [], f"an uncaught page error occurred: {page_errors}"
