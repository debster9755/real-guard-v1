"""DOC-012: no published Markdown may contain `TODO`, `TBD`, `XXX`, `FIXME`
or `<placeholder>`, enforced by a CI grep.

Extended in Phase 8 to cover every published Markdown file, not only
README.md — SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md,
CHANGELOG.md, and docs/*.md (docs/adr/ included, since an ADR is published
documentation too, though it is expected to freely *discuss* other
projects' placeholder conventions in prose without ever containing one
itself as a literal marker).
"""

from __future__ import annotations

import re
from pathlib import Path

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

# Word-boundary matches only, so this never flags a substring inside an
# unrelated real word (there are none in this codebase's prose, but the
# boundary is cheap insurance). `<placeholder>` is matched literally,
# angle brackets included, since it's specifically the templating-style
# marker DOC-012 names, not the English word alone.
_FORBIDDEN_PATTERNS = [
    re.compile(r"\bTODO\b"),
    re.compile(r"\bTBD\b"),
    re.compile(r"\bXXX\b"),
    re.compile(r"\bFIXME\b"),
    re.compile(r"<placeholder>", re.IGNORECASE),
]

# A backtick-quoted mention of the literal marker (e.g. this file's own ADR
# discussing DOC-012's rule and writing "no `TODO`, `TBD` or placeholder
# survives") is citing the rule, not leaving an actual unfinished-work
# marker in the document — DOC-012's real intent is unmarked, bare prose
# placeholders. Backtick spans are blanked out before scanning so a
# genuine `TODO:` left in real (non-code-quoted) prose still fails loudly.
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _blank_inline_code(text: str) -> str:
    return _INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)


@pytest.mark.docs
class TestNoPlaceholderText:
    def test_published_markdown_set_is_non_empty(self) -> None:
        assert len(PUBLISHED_MARKDOWN) >= 7

    @pytest.mark.parametrize(
        "path",
        PUBLISHED_MARKDOWN,
        ids=lambda p: str(p.relative_to(ROOT)),
    )
    def test_file_has_no_forbidden_placeholder_marker(self, path: Path) -> None:
        text = path.read_text()
        scannable = _blank_inline_code(text)
        hits: list[str] = []
        for pattern in _FORBIDDEN_PATTERNS:
            for m in pattern.finditer(scannable):
                line_no = text.count("\n", 0, m.start()) + 1
                line = text.splitlines()[line_no - 1].strip()
                hits.append(f"line {line_no}: {pattern.pattern} -> {line!r}")
        assert not hits, (
            f"{path.relative_to(ROOT)} contains forbidden placeholder marker(s):\n"
            + "\n".join(hits)
        )
