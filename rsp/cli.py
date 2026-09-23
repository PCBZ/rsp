"""`rsp-validate`: read a config and say what is wrong with it.

Separate from loading on purpose. `load` raises on the first problem because a
host that starts with half its guards is worse than one that does not start;
this prints and exits non-zero, because someone editing a file wants the list.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from rsp.config import load
from rsp.runtime import ConfigError


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rsp-validate", description=__doc__)
    parser.add_argument("config", help="path to a TOML config")
    arguments = parser.parse_args(argv)

    try:
        plugins = load(arguments.config)
    except ConfigError as wrong:
        print(wrong, file=sys.stderr)
        return 1

    for plugin in plugins:
        print(
            f"{plugin.name}: {' '.join(plugin.command)} "
            f"[on_error={plugin.on_error.value} timeout={plugin.timeout:g}s]"
        )
    # The handshake is not attempted: a config can be right about what it says
    # while the tool it names is installed somewhere else, and saying "invalid"
    # about a machine's missing binary is a different claim.
    print(f"{len(plugins)} plugin(s), not started", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
