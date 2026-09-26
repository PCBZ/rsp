"""Every case in conformance/cases, against every plugin of the role it names.

Passing is defined once, in `conformance/harness.py`, which the shippable kit
runs too. A stand-in for that kit, so nothing here imports rsp.
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

# Installed or not, so a missing plugin is a visible skip per case, not a shorter run.
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
    """Both, as JSON permits either: bad surrogate-pair decoding shows only past the BMP."""
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
