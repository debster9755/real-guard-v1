"""PLAN.md §6 Phase 3 exit gate: "no response path bypasses the output
guard, asserted by a test that enumerates every return statement in the
completion handler."

This is a static (AST-based) test rather than a runtime one on purpose: the
property being asserted is about the *shape of the code* — every `return`
that can be reached after the upstream provider is called must be
textually preceded, within that same function, by a call to
`run_output_guard()`. A runtime test could only ever prove this for the
specific inputs it happens to construct; this test proves it for every
possible input, by inspecting every `return` statement in the handler
directly, exactly as the exit gate specifies.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Depth-first search for a (possibly nested) function definition."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")


def _call_linenos(func: ast.AST, *, attr_or_name: str) -> list[int]:
    """Line numbers of every Call node whose callee is a Name or Attribute
    matching `attr_or_name` (e.g. "complete" for `state.provider.complete(...)`,
    "run_output_guard" for a bare-name call)."""
    linenos: list[int] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        name = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", None)
        if name == attr_or_name:
            linenos.append(node.lineno)
    return linenos


def _return_linenos(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[int]:
    linenos = []
    for node in ast.walk(func):
        if isinstance(node, ast.Return):
            linenos.append(node.lineno)
    return linenos


def test_no_return_after_upstream_call_bypasses_the_output_guard() -> None:
    import app.main as main_module

    source = inspect.getsource(main_module)
    tree = ast.parse(source)
    handler = _find_function(tree, "create_chat_completion")

    upstream_call_linenos = _call_linenos(handler, attr_or_name="complete")
    assert upstream_call_linenos, (
        "expected to find at least one call to provider.complete() in "
        "create_chat_completion — if this assertion fails, the function was "
        "refactored and this test's detection needs updating, not removing"
    )
    upstream_lineno = min(upstream_call_linenos)

    guard_call_linenos = _call_linenos(handler, attr_or_name="run_output_guard")
    assert guard_call_linenos, "expected at least one call to run_output_guard()"

    return_linenos = _return_linenos(handler)
    post_upstream_returns = [ln for ln in return_linenos if ln > upstream_lineno]
    assert post_upstream_returns, (
        "expected at least one return statement after the upstream call — "
        "if this assertion fails, the ALLOW branch was restructured and "
        "this test's detection needs updating, not removing"
    )

    for return_lineno in post_upstream_returns:
        guard_before_this_return = [
            gl for gl in guard_call_linenos if upstream_lineno < gl < return_lineno
        ]
        assert guard_before_this_return, (
            f"return statement at app/main.py:{return_lineno} follows the "
            f"upstream call (line {upstream_lineno}) but is not preceded by "
            "a run_output_guard() call — SYS-006/SYS-014 violation: this "
            "return path would deliver an un-inspected upstream response"
        )


def test_resume_approved_also_calls_run_output_guard_before_completing() -> None:
    """SYS-014: the approval-resume path is not exempt either. Same static
    property, applied to app/approvals.py's resume_approved()."""
    import app.approvals as approvals_module

    source = inspect.getsource(approvals_module)
    tree = ast.parse(source)
    handler = _find_function(tree, "resume_approved")

    upstream_call_linenos = _call_linenos(handler, attr_or_name="complete")
    assert upstream_call_linenos
    upstream_lineno = min(upstream_call_linenos)

    guard_call_linenos = _call_linenos(handler, attr_or_name="run_output_guard")
    assert guard_call_linenos, "resume_approved() must call run_output_guard()"
    assert min(guard_call_linenos) > upstream_lineno, (
        "run_output_guard() must be called after the upstream provider call, "
        "against the actual response — not before it exists"
    )


def test_this_test_file_is_exercised_by_pytest_collection() -> None:
    """Trivial sanity check that this file is where it should be, so a
    future rename doesn't silently drop the exit-gate assertion from CI."""
    assert Path(__file__).name == "test_no_response_bypasses_output_guard.py"
