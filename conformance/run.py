#!/usr/bin/env python3
"""Run the conformance cases against a plugin, and say which clauses it settled.

    python conformance/run.py --role gitleaks -- gitleaks-wrapper --flag

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

from harness import check, load

ROOT = pathlib.Path(__file__).parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="conformance/run.py")
    parser.add_argument("--role", required=True, help="which cases to run, e.g. echo or gitleaks")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- the plugin command")
    arguments = parser.parse_args(argv)

    command = [word for word in arguments.command if word != "--"]
    if not command:
        parser.error("give the plugin command after --")

    cases = [
        (name, case) for name, case in load(ROOT / "cases") if case["plugin"] == arguments.role
    ]
    if not cases:
        parser.error(f"no cases for role {arguments.role!r}")

    failures = 0
    clauses: dict[str, bool] = collections.defaultdict(bool)
    for name, case in cases:
        # Both encodings, because JSON permits either and a plugin can pass
        # one and fail the other.
        outcomes = {escaped: check(case, command, escaped=escaped) for escaped in (False, True)}
        passed = all(outcome.passed for outcome in outcomes.values())
        failures += not passed
        for clause in (part.strip() for part in case["clause"].split(",")):
            clauses[clause] = clauses[clause] or passed
        if passed:
            print(f"pass  {name}")
        else:
            for escaped, outcome in outcomes.items():
                if not outcome.passed:
                    encoding = "escaped" if escaped else "utf-8"
                    print(f"FAIL  {name} ({encoding}): {outcome.why}")

    settled = sorted(clause for clause, ok in clauses.items() if ok)
    print(f"\n{len(cases) - failures}/{len(cases)} cases", file=sys.stderr)
    print(f"clauses settled: {', '.join(settled) or 'none'}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
