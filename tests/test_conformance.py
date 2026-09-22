"""Every case in conformance/cases, run against the plugin it names.

A stand-in for the standalone kit, which has to run without the runtime
source present — so nothing here imports rsp.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
from collections.abc import Callable

import pytest

ROOT = pathlib.Path(__file__).parent.parent
CASE_ROOT = ROOT / "conformance" / "cases"
CASES = sorted(CASE_ROOT.rglob("*.json"))

# A plugin is a command. What it is written in is its author's business, which
# is the claim these entries exist to make rather than assert.
PLUGINS = {
    "rsp-echo": ([sys.executable, "plugins/rsp-echo/main.py"], (sys.executable,)),
    # A wrapper needs its tool as well as its runtime. Both must be present
    # or the cases cannot run, and in CI that is a failure rather than a skip.
    "rsp-gitleaks-ts": (
        ["node", "examples/gitleaks-ts/src/main.ts"],
        ("node", "gitleaks"),
    ),
}

# A wrapper may be pointed at its tool by an environment variable instead of
# PATH. This check has to look where the plugin will look, or it reports a tool
# as missing while the plugin goes on to find it.
TOOL_OVERRIDES = {"gitleaks": "RSP_GITLEAKS"}


def _installed(tool: str) -> bool:
    override = os.environ.get(TOOL_OVERRIDES.get(tool, ""))
    return shutil.which(override or tool) is not None


# Toolchains belong to CI, not to a contributor's machine. Locally a missing
# one skips its cases; here it fails, because a silently skipped plugin proves
# nothing.
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"


@pytest.mark.parametrize("escaped", [False, True], ids=["utf8", "escaped"])
@pytest.mark.parametrize(
    "path", CASES, ids=lambda p: p.relative_to(CASE_ROOT).as_posix().removesuffix(".json")
)
def test_case(
    path: pathlib.Path, escaped: bool, record_property: Callable[[str, object], None]
) -> None:
    """Both encodings, because JSON permits either. This host sends raw UTF-8,
    but another may escape, and a plugin decoding surrogate pairs wrong reports
    offsets that are wrong by two — invisibly, until content leaves the BMP."""
    case = json.loads(path.read_text())
    # The clause and the implementation are what make the report a matrix
    # rather than a list of names (see conftest.py).
    record_property("clause", case["clause"])
    record_property("plugin", case["plugin"])
    command, tools = PLUGINS[case["plugin"]]
    if missing := [tool for tool in tools if not _installed(tool)]:
        message = f"not installed: {', '.join(missing)}"
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
