"""Every case in conformance/cases, run against the plugin it names.

A stand-in for the standalone kit in #19, which has to run without the runtime
source present — so nothing here imports rsp.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

CASES = sorted((pathlib.Path(__file__).parent.parent / "conformance" / "cases").glob("*.json"))
PLUGINS = {"rsp-echo": [sys.executable, "plugins/rsp-echo/main.py"]}


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_case(path: pathlib.Path) -> None:
    case = json.loads(path.read_text())
    proc = subprocess.run(
        PLUGINS[case["plugin"]],
        input=json.dumps(case["request"]),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]

    if expected_objects := case["expect"].get("stdout_objects"):
        assert len(lines) == expected_objects
        assert proc.stderr, "diagnostics belong on stderr, and this plugin emits some (T2)"

    assert json.loads(lines[0]) == case["expect"]["response"]
