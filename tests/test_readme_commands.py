"""DOC-004: every fenced `bash` block in README.md marked `<!-- test -->`
MUST be executed by CI against a running mock-mode instance. This is the
CI-enforced mechanism DOC-004 requires — PLAN.md §12's anti-drift
automation item 1: "extracts every fenced bash block marked <!-- test -->
and executes it against a running mock-mode container. A stale command
fails CI."

This test starts a real `uvicorn app.main:app` subprocess in mock mode (the
same pattern `scripts/benchmark.py` already uses to drive real HTTP against
this application), rewrites each extracted command's
`http://127.0.0.1:8000` to the test server's own ephemeral host:port, runs
it through `bash -c` exactly as a reader would paste it, and asserts the
documented *shape* of the output (status codes, key JSON fields) rather
than a byte-identical match — timestamps, ids, and mock-response nonces
differ on every run by design.

pytest marker: `docs` (README command extraction tests, Phase 8).
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.docs

ROOT = Path(__file__).resolve().parent.parent
README_PATH = ROOT / "README.md"
README_BASE_URL = "http://127.0.0.1:8000"

_TEST_BLOCK_RE = re.compile(
    r"<!--\s*test\s*-->\s*\n```bash\n(?P<code>.*?)\n```",
    re.DOTALL,
)


def _extract_test_blocks(readme_text: str) -> list[str]:
    """Every fenced bash block immediately preceded by a `<!-- test -->`
    marker, in document order, exactly as DOC-004 specifies."""
    return [m.group("code") for m in _TEST_BLOCK_RE.finditer(readme_text)]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_healthz(base_url: str, timeout_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url}/healthz", timeout=1.0) as resp:  # noqa: S310
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError) as e:
            last_err = e
        time.sleep(0.2)
    raise RuntimeError(f"server never became healthy at {base_url}/healthz: {last_err}")


@pytest.fixture(scope="module")
def mock_server() -> Iterator[str]:
    """A real `uvicorn app.main:app` subprocess, mock mode, no auth
    configured — exactly the Quick start section's own preconditions."""
    port = _free_port()
    host = "127.0.0.1"
    base_url = f"http://{host}:{port}"

    with tempfile.TemporaryDirectory(prefix="realguard-readme-test-") as tmp_dir:
        db_path = Path(tmp_dir) / "readme_test.db"
        env = os.environ.copy()
        env.update(
            {
                "APP_ENV": "development",
                "BIND_HOST": host,
                "BIND_PORT": str(port),
                "DATABASE_URL": f"sqlite:///{db_path}",
                "FIREWALL_API_KEYS": "",
                "FIREWALL_REVIEWER_KEYS": "",
            }
        )
        env.pop("UPSTREAM_BASE_URL", None)

        proc = subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                host,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            _wait_for_healthz(base_url)
            yield base_url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def _run_block(code: str, base_url: str) -> subprocess.CompletedProcess[str]:
    rewritten = code.replace(README_BASE_URL, base_url)
    return subprocess.run(  # noqa: S602
        rewritten,
        shell=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestReadmeCommandBlocksExist:
    def test_at_least_two_test_marked_blocks_present(self) -> None:
        """A regression guard: if every `<!-- test -->` marker were
        accidentally removed from a future README edit, the extraction
        below would silently test nothing and this whole file would pass
        for the wrong reason. Fail loudly instead."""
        blocks = _extract_test_blocks(README_PATH.read_text())
        assert len(blocks) >= 2, (
            "Expected at least the BEN-001 and INJ-001 <!-- test --> blocks "
            "in README.md's Quick start section"
        )


class TestReadmeCommandBlocksExecute:
    """Runs every `<!-- test -->`-marked block from README.md, in document
    order, against one shared live mock-mode server."""

    def test_benign_request_block_returns_allow(self, mock_server: str) -> None:
        blocks = _extract_test_blocks(README_PATH.read_text())
        benign_block = next(b for b in blocks if "banana bread" in b)
        result = _run_block(benign_block, mock_server)
        assert result.returncode == 0, result.stderr
        body = json.loads(result.stdout)
        assert body["firewall"]["decision"] == "ALLOW"
        assert body["firewall"]["transformation"] == "NONE"
        assert body["object"] == "chat.completion"
        assert "choices" in body and body["choices"][0]["message"]["role"] == "assistant"

    def test_injection_request_block_returns_403(self, mock_server: str) -> None:
        blocks = _extract_test_blocks(README_PATH.read_text())
        injection_block = next(b for b in blocks if "Ignore all previous instructions" in b)
        result = _run_block(injection_block, mock_server)
        assert result.returncode == 0, result.stderr
        # The block's own trailing `# 403` is a bash comment, not output —
        # curl's `-w '%{http_code}\n'` is the only thing that prints.
        assert result.stdout.strip() == "403"

    def test_every_marked_block_runs_without_a_shell_error(self, mock_server: str) -> None:
        """Every <!-- test -->-marked block, not only the two named tests
        above, must at least execute cleanly against the live server — this
        is what actually makes a stale command (a typo, a renamed field, a
        removed endpoint) fail CI, per DOC-004."""
        blocks = _extract_test_blocks(README_PATH.read_text())
        assert blocks, "no <!-- test --> blocks found in README.md"
        for block in blocks:
            result = _run_block(block, mock_server)
            assert result.returncode == 0, (
                f"README <!-- test --> block failed:\n{block}\n\nstderr:\n{result.stderr}"
            )
