"""Every case in conformance/cases, against every plugin that can answer it.

A case names a role, so it runs against each implementation of that role and
the answers have to match; one that named a language could only test one. A
stand-in for the standalone kit, so nothing here imports rsp.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from collections.abc import Callable

import pytest

from plugins import REQUIRED, Implementation, for_role

ROOT = pathlib.Path(__file__).parent.parent
CASE_ROOT = ROOT / "conformance" / "cases"
CASES = sorted(CASE_ROOT.rglob("*.json"))

# Resolved at collection, so a missing plugin is a visible skip per case
# rather than a silently shorter run.
RUNS = [
    (path, implementation)
    for path in CASES
    for implementation in for_role(json.loads(path.read_text())["plugin"])
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
    case = json.loads(path.read_text())
    # What makes the report a matrix rather than a list (conftest.py).
    record_property("clause", case["clause"])
    record_property("plugin", implementation.name)
    command = list(implementation.command)
    if not implementation.installed:
        message = f"not installed: {implementation.missing}"
        pytest.fail(message) if REQUIRED else pytest.skip(message)

    try:
        proc = subprocess.run(
            command,
            input=json.dumps(case["request"], ensure_ascii=escaped),
            capture_output=True,
            text=True,
            check=False,
            # A plugin that hangs must fail its case, not the whole run. The
            # kit is the thing that tests misbehaving plugins; it cannot be
            # stopped by one.
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"{case['plugin']} did not answer within 10s")

    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]

    # T2 holds for every case, not only the one written about it: exactly one
    # object on stdout and nothing else. Checking it per-case let the other
    # nine accept a plugin that printed extra.
    assert len(lines) == 1, f"expected exactly one object on stdout, got {len(lines)}"
    got = json.loads(lines[0])

    if declaration := case["expect"].get("declaration"):
        # A wrapper's version carries the wrapped tool's, which no case can
        # know in advance, so the fields a host acts on are asserted exactly
        # and the version by prefix.
        for field, value in declaration.items():
            assert got[field] == value, field
        assert got["version"].startswith(case["expect"]["version_prefix"])
    else:
        assert got == case["expect"]["response"]

    if case["expect"].get("diagnostics_on_stderr"):
        assert proc.stderr, "this plugin emits diagnostics; they belong on stderr (T2)"
