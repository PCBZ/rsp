"""`rsp validate` checks a config; `rsp ingest` runs a directory through it.

`validate` is separate from loading on purpose: `load` raises on the first
problem, because a host that starts with half its guards is worse than one
that does not start, while someone editing a file wants to be told and to see
an exit code.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections.abc import Sequence

from rsp.config import load
from rsp.runtime import ConfigError, Plugin


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rsp")
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("validate", help="check a config file")
    check.add_argument("config", help="path to a TOML config")

    run = commands.add_parser("ingest", help="run a directory through the plugins")
    run.add_argument("directory", help="directory of documents")
    run.add_argument("--config", default="rsp.toml", help="path to a TOML config")

    arguments = parser.parse_args(argv)
    try:
        plugins = load(arguments.config)
    except ConfigError as wrong:
        print(wrong, file=sys.stderr)
        return 1

    if arguments.command == "validate":
        return _validate(plugins)
    return _ingest(pathlib.Path(arguments.directory), plugins)


def _validate(plugins: list[Plugin]) -> int:
    for plugin in plugins:
        print(
            f"{plugin.name}: {' '.join(plugin.command)} "
            f"[on_error={plugin.on_error.value} timeout={plugin.timeout:g}s]"
        )
    # The handshake is not attempted: a config can be right about what it says
    # while the tool it names is installed somewhere else, and "invalid" is the
    # wrong word for a missing binary.
    print(f"{len(plugins)} plugin(s), not started", file=sys.stderr)
    return 0


def _ingest(directory: pathlib.Path, plugins: list[Plugin]) -> int:
    try:
        from rsp.ingest import ingest
    except ImportError:
        print(
            "rsp ingest needs the llamaindex extra: pip install 'rsp[llamaindex]'", file=sys.stderr
        )
        return 1

    try:
        report = ingest(directory, plugins)
    except (ConfigError, FileNotFoundError) as wrong:
        print(wrong, file=sys.stderr)
        return 1

    print(f"scanned {report.scanned} chunks")
    for item in report.findings:
        # The chunk, not the finding: the host never sees a span (S4), so this
        # points at text to read rather than at a position.
        print(f"  {item.verdict:7}{item.types:18} {item.source}:{item.lines}")
    print(
        f"{report.indexed} chunks indexed, "
        f"{len(report.blocked)} blocked, {len(report.redacted)} redacted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
