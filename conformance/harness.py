"""Run one case against one plugin command. Standard library only.

The one definition of a passing case, shared by `run.py` and the repository's
suite. Nothing imports `rsp`: a plugin is checked against the protocol, not
against this implementation of it.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from typing import Any, NamedTuple

TIMEOUT = 10  # a plugin that hangs fails its case, not the run


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


def spellings(case: dict[str, Any]) -> tuple[bool, ...]:
    """Which encodings to send this case in, as `escaped` values.

    Both where JSON permits both. One where `raw_request` fixes the bytes:
    `escaped` has nothing to act on there, so a second run sends the first
    message again.
    """
    return (False,) if "raw_request" in case else (False, True)


def check(case: dict[str, Any], command: list[str], *, escaped: bool = False) -> Outcome:
    r"""What the plugin said, against what the case requires.

    `escaped` sends `\uXXXX` escapes instead of raw UTF-8. JSON permits either,
    and a plugin that decodes surrogate pairs wrong is off by two outside the BMP.
    """
    # `raw_request` is the message byte for byte. T4 is about what a parser
    # accepts beyond the grammar, and a case built from `request` cannot carry
    # a repeated key or a bare NaN — this file is JSON too.
    raw = case.get("raw_request")
    payload = raw if raw is not None else json.dumps(case["request"], ensure_ascii=escaped)
    try:
        proc = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            encoding="utf-8",  # whatever the locale (M1)
            check=False,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return Outcome(False, f"no answer within {TIMEOUT}s")
    except OSError as exc:
        return Outcome(False, f"could not start: {exc}")
    except UnicodeDecodeError:
        return Outcome(False, "output is not UTF-8")

    if case["expect"].get("refused"):
        # A message no plugin may act on. Refusing is saying nothing a host
        # could read as a verdict; the host turns that into BLOCK (E1).
        if proc.returncode != 0 or not proc.stdout.strip():
            return Outcome(True)
        return Outcome(False, f"answered {proc.stdout.strip()[:120]} instead of refusing")

    if proc.returncode != 0:
        return Outcome(False, f"exited {proc.returncode}: {proc.stderr.strip()[:200]}")

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    # T2 holds for every case: exactly one object on stdout and nothing else.
    if len(lines) != 1:
        return Outcome(False, f"expected one object on stdout, got {len(lines)}")
    try:
        got = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        return Outcome(False, f"stdout is not JSON: {exc}")
    if not isinstance(got, dict):  # `null` is JSON, and not the object T1 asks for
        return Outcome(False, f"expected a JSON object, got {type(got).__name__}")

    expect = case["expect"]
    if declaration := expect.get("declaration"):
        # Exact fields, but the version by prefix: a wrapper's carries its tool's.
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
