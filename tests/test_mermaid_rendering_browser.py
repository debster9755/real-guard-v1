"""Real, visual, browser-rendered verification of every Mermaid diagram in
`README.md` and `docs/architecture.md`. Phase 9 gap-closure bonus (ADR 0012).

`docs/adr/0009` and `docs/adr/0010` both verified these six diagrams with
`npx @mermaid-js/mermaid-cli` (`mmdc`) — real, but syntax-only: `mmdc` proves
Mermaid's grammar parses each block and produces *some* non-empty SVG, not
that a browser actually paints recognisable boxes, arrows, and labels (an
`mmdc` run would just as happily "succeed" against a diagram that renders as
a single misplaced box with truncated text). This module is a meaningfully
different, real check: it loads the actual Mermaid JS library into a real
headless Chromium page (the same rendering engine GitHub's own Markdown
preview uses under the hood) and screenshots the result, so this file's own
completion report can describe what the rendered diagram actually looks like
— not just that a CLI process exited 0.

Not a replacement for GitHub's own renderer (this harness is a local HTML
file, not github.com), but a real, visual, browser-based check GitHub-side
rendering has never been exercised here at all (no repository is public yet
— docs/adr/0011 decision-adjacent context).

Self-skips (never fails) under the same `browser` marker/contract as
tests/test_dashboard_browser.py when Chromium cannot actually launch here.
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.browser

REPO_ROOT = Path(__file__).resolve().parent.parent
SCREENSHOT_DIR = REPO_ROOT / "docs" / "screenshots"

# Pinned exact version, same allowlisted CDN host this project's own Artifact
# tooling uses elsewhere — a real, reachable, versioned URL, not "latest".
_MERMAID_CDN_URL = "https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js"

_SOURCES = [
    ("README.md", REPO_ROOT / "README.md"),
    ("docs/architecture.md", REPO_ROOT / "docs" / "architecture.md"),
]


def _extract_mermaid_blocks(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return re.findall(r"```mermaid\n(.*?)```", text, re.DOTALL)


def _build_harness_html(blocks: list[tuple[str, str]]) -> str:
    """`blocks` is `[(diagram_id, mermaid_source), ...]`."""
    divs = "\n".join(
        f'<pre class="mermaid" id="{diagram_id}">{html.escape(source)}</pre>'
        for diagram_id, source in blocks
    )
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<script src="{_MERMAID_CDN_URL}"></script>
</head>
<body>
{divs}
<script>
  mermaid.initialize({{ startOnLoad: true }});
</script>
</body>
</html>
"""


@pytest.fixture
async def mermaid_page(tmp_path: Path) -> Any:
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as e:  # noqa: BLE001 — see test_dashboard_browser.py's identical fixture
            pytest.skip(
                "Chromium is not launchable in this environment "
                f"({type(e).__name__}: {e}). Run `playwright install chromium` "
                "and re-run `pytest -m browser`."
            )
        page = await browser.new_page()
        try:
            yield page, tmp_path
        finally:
            await browser.close()


async def test_every_readme_and_architecture_mermaid_diagram_renders_visually(
    mermaid_page: tuple[Any, Path],
) -> None:
    """Loads all 6 diagrams (4 README, 2 architecture.md) into one real
    Chromium page via the real Mermaid JS library (not `mmdc`), waits for
    each to actually paint an `<svg>` (Mermaid replaces a failed parse with
    an *error* SVG containing literal "Syntax error" text — checked for and
    ruled out explicitly, not just "an svg exists"), and screenshots each
    diagram individually so this test's own completion report can describe
    what is actually visible in each one.
    """
    page, tmp_path = mermaid_page

    all_blocks: list[tuple[str, str, str]] = []  # (source_label, diagram_id, mermaid_source)
    for label, path in _SOURCES:
        blocks = _extract_mermaid_blocks(path)
        assert blocks, f"no mermaid blocks found in {path} — extraction regex or file drifted"
        slug = label.replace("/", "-").replace(".md", "").replace(".", "-")
        for i, source in enumerate(blocks, start=1):
            all_blocks.append((label, f"diagram-{slug}-{i}", source))

    assert len(all_blocks) == 6, (
        f"expected the 6 diagrams docs/adr/0009 and docs/adr/0010 both verified "
        f"(4 README + 2 architecture.md), found {len(all_blocks)} — a diagram "
        f"was added or removed since those ADRs; update this test's expectation "
        f"deliberately if so, not silently"
    )

    harness_html = _build_harness_html(
        [(diagram_id, source) for _, diagram_id, source in all_blocks]
    )
    harness_path = tmp_path / "mermaid-harness.html"
    harness_path.write_text(harness_html, encoding="utf-8")

    await page.goto(f"file://{harness_path}")

    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    for label, diagram_id, _source in all_blocks:
        await page.wait_for_selector(f"#{diagram_id} svg", timeout=15_000)
        rendered_text = await page.locator(f"#{diagram_id} svg").text_content()
        assert "Syntax error" not in rendered_text, (
            f"{label}'s {diagram_id} rendered Mermaid's own error diagram, not the real one"
        )
        screenshot_name = f"mermaid-{diagram_id}.png"
        await page.locator(f"#{diagram_id}").screenshot(path=str(SCREENSHOT_DIR / screenshot_name))
