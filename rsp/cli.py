"""`rsp validate` checks a config; `rsp ingest` runs a directory through it.

`load` stops at the first problem, because a host with half its guards is worse
than one that does not start; `validate` turns that into a message and an exit
code for someone editing the file.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections.abc import Sequence

from rsp.config import load
from rsp.runtime import ConfigError, Plugin


def _validate(plugins: list[Plugin]) -> int:
    for plugin in plugins:
        print(
            f"{plugin.name}: {' '.join(plugin.command)} "
            f"[on_error={plugin.on_error.value} timeout={plugin.timeout:g}s]"
        )
    # No handshake: a binary installed elsewhere does not make the config invalid.
    print(f"{len(plugins)} plugin(s), not started", file=sys.stderr)
    return 0


def _ingest(directory: pathlib.Path, plugins: list[Plugin]) -> int:
    try:
        # rsp.ingest imports llama_index lazily, so a missing extra surfaces at the call.
        from rsp.ingest import ingest

        report = ingest(directory, plugins)
    except ImportError:
        print(
            "rsp ingest needs the llamaindex extra: pip install 'rsp[llamaindex]'", file=sys.stderr
        )
        return 1
    except (ConfigError, FileNotFoundError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(f"scanned {report.scanned} chunks")
    for item in report.findings:
        # A chunk's lines, not a position: the host never sees a span (S4).
        print(f"  {item.verdict:7}{item.types:18} {item.source}:{item.lines}")
    print(
        f"{report.indexed} chunks indexed, "
        f"{len(report.blocked)} blocked, {len(report.redacted)} redacted"
    )
    return 0


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
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 1

    if arguments.command == "validate":
        return _validate(plugins)
    return _ingest(pathlib.Path(arguments.directory), plugins)


if __name__ == "__main__":
    raise SystemExit(main())
