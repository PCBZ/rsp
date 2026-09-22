"""Which plugins exist, found rather than listed.

Each one ships a `conformance.json` saying what runs it, so adding an adapter
in a new language is a new directory and no change here. That file is a
convention of this kit, not part of the protocol: a plugin cannot declare how
to start it, because you have to start it to hear the declaration.

A case names a role, not an implementation: `gitleaks` is any adapter over that
binary, so one case holds for all of them. Nothing here imports `rsp` — the
conformance harness has to run with the runtime source absent.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).parent.parent


@dataclass(frozen=True)
class Implementation:
    """A plugin: how to run it from source, and what that needs installed.

    Any entry can be pointed at something already built, with
    `RSP_PLUGIN_<NAME>`. Only Go needs it today — `go run` recompiles on every
    invocation and the corpus suite makes four hundred — but the hatch belongs
    to all of them rather than to the language that asked first.
    """

    name: str
    role: str
    source: tuple[str, ...]
    toolchain: tuple[str, ...]
    wraps: tuple[str, ...] = ()

    @property
    def built(self) -> str | None:
        short = self.name.removeprefix("rsp-").upper().replace("-", "_")
        return os.environ.get(f"RSP_PLUGIN_{short}")

    @property
    def command(self) -> tuple[str, ...]:
        return (self.built,) if self.built else self.source

    @property
    def tools(self) -> tuple[str, ...]:
        """A built binary needs the wrapped tool; running from source also
        needs the toolchain that runs it."""
        return self.wraps if self.built else self.toolchain + self.wraps

    @property
    def installed(self) -> bool:
        return all(_resolve(tool) for tool in self.tools)

    @property
    def missing(self) -> str:
        return ", ".join(tool for tool in self.tools if not _resolve(tool))


def _resolve(tool: str) -> str | None:
    """Where the plugin looks: a wrapper can be pointed at its tool by
    `RSP_<TOOL>`, and checking only PATH calls it missing while the plugin
    finds it."""
    override = os.environ.get(f"RSP_{tool.upper().replace('-', '_')}")
    return shutil.which(override or tool)


MANIFEST = "conformance.json"


def _load(path: pathlib.Path) -> Implementation:
    """One manifest. `{dir}` is where it lives and `{python}` is this
    interpreter, so a command works from any working directory."""
    declared = json.loads(path.read_text())
    fill = {"dir": str(path.parent), "python": sys.executable}
    return Implementation(
        name=declared["name"],
        role=declared["role"],
        source=tuple(token.format(**fill) for token in declared["source"]),
        toolchain=tuple(token.format(**fill) for token in declared["toolchain"]),
        wraps=tuple(declared.get("wraps", ())),
    )


REGISTRY = tuple(
    _load(path)
    for path in sorted(ROOT.glob(f"plugins/*/{MANIFEST}"))
    + sorted(ROOT.glob(f"examples/*/{MANIFEST}"))
)


def for_role(role: str) -> list[Implementation]:
    return [implementation for implementation in REGISTRY if implementation.role == role]


# Toolchains belong to CI, not to a contributor's machine. Locally a missing one
# skips its cases; here it fails, because a silently skipped plugin proves
# nothing.
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"
