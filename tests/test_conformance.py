"""Every case in conformance/cases, against every plugin of the role it names.

Passing is defined once, in `conformance/harness.py`, which the shippable kit
runs too. A stand-in for that kit, so nothing here imports rsp.
"""

from __future__ import annotations

import ast
import json
import pathlib
from collections.abc import Callable

import pytest
from harness import check, spellings

from plugins import ROOT, Implementation, for_role, needs

CASE_ROOT = ROOT / "conformance" / "cases"
CASES = sorted(CASE_ROOT.rglob("*.json"))

# Installed or not, so a missing plugin is a visible skip per case, not a shorter run.
# The spelling is part of the run rather than a dimension crossed over all of
# them: a case whose bytes are fixed has one, and running it twice runs it once.
RUNS = [
    (path, implementation, escaped)
    for path, case in ((path, json.loads(path.read_text(encoding="utf-8"))) for path in CASES)
    for implementation in for_role(case["plugin"])
    for escaped in spellings(case)
]


def _id(run: tuple[pathlib.Path, Implementation, bool]) -> str:
    path, implementation, escaped = run
    name = path.relative_to(CASE_ROOT).as_posix().removesuffix(".json")
    return f"{name}-{implementation.name}-{'escaped' if escaped else 'utf8'}"


@pytest.mark.parametrize("run", RUNS, ids=_id)
def test_case(
    run: tuple[pathlib.Path, Implementation, bool],
    record_property: Callable[[str, object], None],
) -> None:
    """Both encodings where JSON permits them: bad surrogate pairs show only past the BMP."""
    path, implementation, escaped = run
    case = json.loads(path.read_text(encoding="utf-8"))
    # What makes the report a matrix rather than a list (conftest.py).
    record_property("clause", case["clause"])
    record_property("plugin", implementation.name)
    command = list(implementation.command)
    needs(implementation)

    outcome = check(case, command, escaped=escaped)

    assert outcome.passed, outcome.why


def test_every_case_runs_in_each_spelling_it_has() -> None:
    """A repeat that was dropped and a case that stopped being collected are one fewer run.

    Nothing here is read from `CASES` or from `spellings`, which are what is
    under suspicion: the directory is walked again and the rule is written out.
    A test that asks the code what it expects agrees with it by construction.
    """
    collected: dict[tuple[str, str], set[bool]] = {}
    for path, implementation, escaped in RUNS:
        collected.setdefault((path.name, implementation.name), set()).add(escaped)

    on_disk = sorted(CASE_ROOT.rglob("*.json"))
    assert on_disk, "no case files"
    for path in on_disk:
        case = json.loads(path.read_text(encoding="utf-8"))
        wanted = {False} if "raw_request" in case else {False, True}
        for implementation in for_role(case["plugin"]):
            ran = collected.get((path.name, implementation.name))
            assert ran == wanted, f"{path.name} on {implementation.name}: {ran}, wanted {wanted}"


def test_nothing_asks_a_plugin_declared_for_another_platform() -> None:
    """Every site that picks implementations asks `unavailable`, not `installed`.

    One that did not was found by CI rather than here: it built a Runtime from
    everything `installed` said yes to, and a manifest declaring another
    platform still says yes — the handshake is where it went wrong, a hundred
    and forty-five times.

    Read as syntax rather than as text, or this file's own prose about
    `installed` is a finding against itself.
    """
    offenders: dict[str, list[int]] = {}
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        lines = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and node.attr == "installed"
        ]
        if lines:
            offenders[path.name] = lines
    assert not offenders, (
        f"filtering on `installed` at {offenders}, which is true for a plugin "
        "this platform cannot run"
    )
