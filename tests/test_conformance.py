"""Every case in conformance/cases, against every plugin that can answer it.

What passing means lives in `conformance/harness.py`, which the shippable
runner uses too — two definitions of a passing case would drift, and the one
an outside implementer runs is the one that has to be right.

A case names a role, so it runs against each implementation of that role and
the answers have to match; one that named a language could only test one. A
stand-in for the standalone kit, so nothing here imports rsp.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Callable

import pytest
from harness import check

from plugins import REQUIRED, Implementation, for_role

ROOT = pathlib.Path(__file__).parent.parent
CASE_ROOT = ROOT / "conformance" / "cases"
CASES = sorted(CASE_ROOT.rglob("*.json"))

# Resolved at collection, so a missing plugin is a visible skip per case
# rather than a silently shorter run.
RUNS = [
    (path, implementation)
    for path in CASES
    for implementation in for_role(json.loads(path.read_text(encoding="utf-8"))["plugin"])
]


def _id(run: tuple[pathlib.Path, Implementation]) -> str:
    path, implementation = run
    return f"{path.relative_to(CASE_ROOT).as_posix().removesuffix('.json')}-{implementation.name}"


@pytest.mark.parametrize("escaped", [False, True], ids=["utf8", "escaped"])
@pytest.mark.parametrize("run", RUNS, ids=_id)
def test_case(
    run: tuple[pathlib.Path, Implementation],
    escaped: bool,
    record_property: Callable[[str, object], None],
) -> None:
    """Both encodings, because JSON permits either: a plugin decoding
    surrogate pairs wrong is off by two, invisibly, until content leaves the
    BMP."""
    path, implementation = run
    case = json.loads(path.read_text(encoding="utf-8"))
    # What makes the report a matrix rather than a list (conftest.py).
    record_property("clause", case["clause"])
    record_property("plugin", implementation.name)
    command = list(implementation.command)
    if not implementation.installed:
        message = f"not installed: {implementation.missing}"
        pytest.fail(message) if REQUIRED else pytest.skip(message)

    outcome = check(case, command, escaped=escaped)

    assert outcome.passed, outcome.why
