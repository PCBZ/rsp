"""Every case in conformance/cases, run against the plugin it names.

A stand-in for the standalone kit, which has to run without the runtime
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
    try:
        proc = subprocess.run(
            PLUGINS[case["plugin"]],
            input=json.dumps(case["request"]),
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
    assert json.loads(lines[0]) == case["expect"]["response"]

    if case["expect"].get("diagnostics_on_stderr"):
        assert proc.stderr, "this plugin emits diagnostics; they belong on stderr (T2)"
