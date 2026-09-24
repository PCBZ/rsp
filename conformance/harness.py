"""Run one case against one plugin command. Standard library only.

This is the part a kit ships: the cases are data, and what it means to pass
one is here rather than in whatever test framework happens to be running. The
repository's own suite calls it, and so does `run.py`, so there is one
definition of a passing case instead of two that drift.

Nothing imports `rsp`. A plugin author checks their plugin against the
protocol, not against our implementation of it.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Any, NamedTuple

# A plugin that hangs must fail its case, not the whole run: the kit is the
# thing that tests misbehaving plugins, and cannot be stopped by one.
TIMEOUT = 10


class Outcome(NamedTuple):
    passed: bool
    why: str = ""


def load(root: pathlib.Path) -> list[tuple[str, dict[str, Any]]]:
    """Every case under `root`, named by its path relative to it."""
    return [
        (
            path.relative_to(root).as_posix().removesuffix(".json"),
            json.loads(path.read_text("utf-8")),
        )
        for path in sorted(root.rglob("*.json"))
    ]


def check(case: dict[str, Any], command: list[str], *, escaped: bool = False) -> Outcome:
    """What the plugin said, against what the case requires.

    `escaped` sends the request with `\\uXXXX` escapes instead of raw UTF-8.
    JSON permits either, and a plugin decoding surrogate pairs wrong reports
    offsets that are wrong by two — invisibly, until content leaves the BMP.
    """
    try:
        proc = subprocess.run(
            command,
            input=json.dumps(case["request"], ensure_ascii=escaped),
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return Outcome(False, f"no answer within {TIMEOUT}s")
    except OSError as unstartable:
        return Outcome(False, f"could not start: {unstartable}")

    if proc.returncode != 0:
        return Outcome(False, f"exited {proc.returncode}: {proc.stderr.strip()[:200]}")

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    # T2 holds for every case, not only the one written about it: exactly one
    # object on stdout and nothing else.
    if len(lines) != 1:
        return Outcome(False, f"expected one object on stdout, got {len(lines)}")
    try:
        got = json.loads(lines[0])
    except json.JSONDecodeError as unreadable:
        return Outcome(False, f"stdout is not JSON: {unreadable}")

    expect = case["expect"]
    if declaration := expect.get("declaration"):
        # A wrapper's version carries the wrapped tool's, which no case can
        # know in advance, so the fields a host acts on are asserted exactly
        # and the version by prefix.
        for field, value in declaration.items():
            if got.get(field) != value:
                return Outcome(False, f"{field}: expected {value!r}, got {got.get(field)!r}")
        if not str(got.get("version", "")).startswith(expect["version_prefix"]):
            return Outcome(
                False, f"version {got.get('version')!r} lacks {expect['version_prefix']!r}"
            )
    elif got != expect["response"]:
        return Outcome(False, f"expected {expect['response']}, got {got}")

    if expect.get("diagnostics_on_stderr") and not proc.stderr:
        return Outcome(False, "this plugin emits diagnostics; they belong on stderr (T2)")
    return Outcome(True)
