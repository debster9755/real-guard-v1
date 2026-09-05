"""A link checker for every internal Markdown link across the published
documentation set (PLAN.md §12's anti-drift automation and this project's
own DOC-004-adjacent "link check" automated check for Phase 8).

Every relative file link (`[text](path/to/file.md)`, with or without an
in-file `#anchor`) and every same-document anchor link (`[text](#anchor)`)
is resolved against the real filesystem / the real headings in the target
file — nothing here is assumed to resolve. External `http(s)://` links are
checked only for well-formed syntax (scheme + host); this project does not
require live reachability of an external URL, only that nothing invented
or malformed is linked.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent

PUBLISHED_MARKDOWN = [
    ROOT / "README.md",
    ROOT / "SECURITY.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "CODE_OF_CONDUCT.md",
    ROOT / "CHANGELOG.md",
    *sorted((ROOT / "docs").glob("*.md")),
    *sorted((ROOT / "docs" / "adr").glob("*.md")),
]

_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)


def _slugify(heading: str) -> str:
    """GitHub's own Markdown heading-anchor algorithm, close enough for
    this repository's headings: strip inline code/formatting punctuation,
    lowercase, spaces to hyphens."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)  # drop anything that isn't word/space/hyphen
    s = re.sub(r"\s+", "-", s).strip("-")
    return s


def _heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    counts: dict[str, int] = {}
    for _hashes, title in _HEADING_RE.findall(text):
        base = _slugify(title)
        n = counts.get(base, 0)
        counts[base] = n + 1
        slugs.add(base if n == 0 else f"{base}-{n}")
    return slugs


def _all_links(text: str) -> list[str]:
    return _LINK_RE.findall(text)


def _iter_file_links() -> list[tuple[Path, str]]:
    pairs: list[tuple[Path, str]] = []
    for path in PUBLISHED_MARKDOWN:
        text = path.read_text()
        for link in _all_links(text):
            pairs.append((path, link))
    return pairs


@pytest.mark.docs
class TestInternalLinksResolve:
    def test_published_markdown_files_exist(self) -> None:
        assert len(PUBLISHED_MARKDOWN) >= 7, "the published Markdown set looks incomplete"
        for path in PUBLISHED_MARKDOWN:
            assert path.exists(), f"expected published doc missing: {path}"

    @pytest.mark.parametrize(
        "source_path",
        PUBLISHED_MARKDOWN,
        ids=lambda p: str(p.relative_to(ROOT)),
    )
    def test_every_link_in_file_resolves(self, source_path: Path) -> None:
        text = source_path.read_text()
        own_slugs = _heading_slugs(text)
        failures: list[str] = []

        for link in _all_links(text):
            target = link.strip()
            if target.startswith(("mailto:",)):
                continue

            if target.startswith(("http://", "https://")):
                parsed = urlparse(target)
                if not parsed.scheme or not parsed.netloc:
                    failures.append(f"malformed external URL: {target!r}")
                continue

            if target.startswith("#"):
                anchor = target[1:]
                if anchor and anchor not in own_slugs:
                    failures.append(
                        f"same-file anchor {target!r} not found among this file's own "
                        f"heading slugs {sorted(own_slugs)}"
                    )
                continue

            # A relative file path, optionally with its own #anchor.
            file_part, _, anchor_part = target.partition("#")
            if not file_part:
                # ('#anchor' already handled above; an empty file_part here
                # means something like "path#" which is just a path.)
                continue
            resolved = (source_path.parent / file_part).resolve()
            if not resolved.exists():
                failures.append(f"linked path does not exist: {target!r} -> {resolved}")
                continue
            if anchor_part and resolved.suffix == ".md":
                target_slugs = _heading_slugs(resolved.read_text())
                if anchor_part not in target_slugs:
                    failures.append(
                        f"anchor {anchor_part!r} not found in {resolved.relative_to(ROOT)} "
                        f"(known: {sorted(target_slugs)})"
                    )

        assert not failures, (
            f"{source_path.relative_to(ROOT)} has {len(failures)} broken link(s):\n"
            + "\n".join(failures)
        )
