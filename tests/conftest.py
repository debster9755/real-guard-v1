"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_factory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Callable[..., TestClient]]:
    """Builds a TestClient bound to a freshly-constructed app in mock mode,
    with optional extra environment variables applied *before* the app is
    constructed (needed for e.g. FIREWALL_API_KEYS/FIREWALL_REVIEWER_KEYS,
    which `Settings` reads once at startup — setting them after `client()`
    has already built the app would have no effect).

    Each call gets its own per-test temp DATABASE_URL unless the caller
    overrides it, so approval-workflow tests never share state with each
    other or with a developer's local DB. All apps built through one call to
    this fixture are closed together at teardown.
    """
    monkeypatch.delenv("UPSTREAM_BASE_URL", raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")

    from app.main import create_app

    stack = ExitStack()

    def _make(**extra_env: str) -> TestClient:
        for key, value in extra_env.items():
            monkeypatch.setenv(key, value)
        app = create_app()
        return stack.enter_context(TestClient(app))

    yield _make
    stack.close()


@pytest.fixture
def client(client_factory: Callable[..., TestClient]) -> TestClient:
    """A TestClient bound to a freshly-constructed app in mock mode, with no
    keys configured (unauthenticated dev mode) — the fixture most existing
    tests use."""
    return client_factory()


@pytest.fixture
def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
