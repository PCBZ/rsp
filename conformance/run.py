#!/usr/bin/env python3
"""Run the conformance cases against a plugin, and say which clauses it settled.

    python conformance/run.py -- my-plugin --flag        # which role am I?
    python conformance/run.py --role gitleaks -- my-plugin

Standard library only, and no import of the reference runtime: a plugin author
should be able to copy `conformance/` and `plugins/` next to their plugin and
find out whether it conforms, without installing the implementation whose
behaviour is not the thing being tested.

Host cases are not run here. A host is a library rather than a process, so the
runner for those belongs to whoever wrote the host; `conformance/host/` holds
the cases and `conformance/cases/README.md` describes the shape.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys
from typing import Any

from harness import check, load

ROOT = pathlib.Path(__file__).parent


def roles(cases: list[tuple[str, dict[str, Any]]]) -> dict[str, int]:
    counted: dict[str, int] = collections.Counter()
    for _, case in cases:
        counted[case["plugin"]] += 1
    return dict(sorted(counted.items()))


def run_role(cases: list[tuple[str, dict[str, Any]]], command: list[str]) -> tuple[int, list[str]]:
    """Every case for one role. Returns how many failed, and the clauses the
    plugin settled by passing."""
    failures = 0
    settled: dict[str, bool] = collections.defaultdict(bool)
    for name, case in cases:
        # Both encodings, because JSON permits either and a plugin can pass
        # one and fail the other.
        outcomes = {escaped: check(case, command, escaped=escaped) for escaped in (False, True)}
        passed = all(outcome.passed for outcome in outcomes.values())
        failures += not passed
        for clause in (part.strip() for part in case["clause"].split(",")):
            settled[clause] = settled[clause] or passed
        if passed:
            print(f"pass  {name}")
        else:
            for escaped, outcome in outcomes.items():
                if not outcome.passed:
                    print(f"FAIL  {name} ({'escaped' if escaped else 'utf-8'}): {outcome.why}")
    return failures, sorted(clause for clause, ok in settled.items() if ok)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="conformance/run.py")
    parser.add_argument("--role", help="which cases to run; omit to try every role")
    parser.add_argument("--list-roles", action="store_true", help="what roles exist, then stop")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- the plugin command")
    arguments = parser.parse_args(argv)

    cases = load(ROOT / "cases")
    available = roles(cases)

    if arguments.list_roles:
        for role, count in available.items():
            print(f"{role}\t{count} cases")
        return 0

    command = [word for word in arguments.command if word != "--"]
    if not command:
        parser.error("give the plugin command after --")
    if arguments.role and arguments.role not in available:
        parser.error(f"no cases for role {arguments.role!r}; try {', '.join(available)}")

    # A plugin conforms to a role rather than in general, so without one the
    # kit reports every role and the author reads off which they are. Failures
    # against a role a plugin never claimed are information, not a verdict.
    wanted = [arguments.role] if arguments.role else list(available)
    passed_a_role = False
    for role in wanted:
        if len(wanted) > 1:
            print(f"\n== {role}")
        mine = [entry for entry in cases if entry[1]["plugin"] == role]
        failures, settled = run_role(mine, command)
        passed_a_role = passed_a_role or not failures
        print(f"{len(mine) - failures}/{len(mine)} cases for {role}", file=sys.stderr)
        if settled:
            print(f"clauses settled: {', '.join(settled)}", file=sys.stderr)
    return 0 if passed_a_role else 1


if __name__ == "__main__":
    raise SystemExit(main())
