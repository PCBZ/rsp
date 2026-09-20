"""Line budgets, counted the way the rule means them.

Success criterion 1 says a plugin adapter wrapping an upstream tool is under 80
lines; criterion 2 says the same of the host adapter. Both are evidence that
each end of the protocol is cheap to implement, so both are worth checking
continuously rather than asserting in a pull request.

The measure is code: docstrings, comments and blank lines do not count. Saying
so in prose left it ambiguous enough that a reviewer read the budget against
the file length, so it is defined here instead.
"""

from __future__ import annotations

import ast
import io
import pathlib
import tokenize

import pytest

ROOT = pathlib.Path(__file__).parent.parent
BUDGET = 80
ADAPTERS = [ROOT / "rsp" / "guards.py", ROOT / "plugins" / "rsp-echo" / "main.py"]


def code_lines(source: str) -> int:
    tree = ast.parse(source)
    docstrings = sum(
        node.body[0].end_lineno - node.body[0].lineno + 1
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef) and ast.get_docstring(node)
    )
    comments = sum(
        1
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT
    )
    lines = source.splitlines()
    blank = sum(1 for line in lines if not line.strip())
    return len(lines) - docstrings - comments - blank


@pytest.mark.parametrize("path", ADAPTERS, ids=lambda p: p.name)
def test_adapter_stays_within_budget(path: pathlib.Path) -> None:
    """An adapter that outgrows this means something belongs in the runtime,
    not that the budget was wrong."""
    count = code_lines(path.read_text())
    assert count <= BUDGET, f"{path.name} is {count} lines of code, budget {BUDGET}"


def test_the_measure_ignores_prose() -> None:
    """Otherwise the budget would punish explaining a decision."""
    assert code_lines('"""Four\nline\ndocstring.\n"""\n\n# comment\nx = 1\n') == 1
