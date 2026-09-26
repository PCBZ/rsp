"""Which plugins exist, found from each one's `conformance.json` rather than listed.

That file is this kit's convention, not the protocol's: a plugin cannot declare
how to start itself. A case names a role (`gitleaks` is any adapter over that
binary), so one case holds for all of them. No `rsp` import: the harness runs
with the runtime source absent.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).parent.parent
MANIFEST = "conformance.json"
# Absolute: a relative one makes a test pass or fail by where pytest was run.
ECHO = [sys.executable, str(ROOT / "plugins/rsp-echo/main.py")]


def script(body: str) -> list[str]:
    """A plugin that is one expression, for a misbehaviour no fixture should keep."""
    return [sys.executable, "-c", body]


# Set in CI, where a skipped plugin proves nothing; locally a missing toolchain skips.
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"


@dataclass(frozen=True)
class Implementation:
    """A plugin: how to run it from source, and what that needs installed.

    `RSP_PLUGIN_<NAME>` points any entry at a prebuilt binary, for toolchains
    that recompile on every call, as `go run` does.
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
        return self.wraps if self.built else self.toolchain + self.wraps

    @property
    def installed(self) -> bool:
        return all(_resolve(tool) for tool in self.tools)

    @property
    def missing(self) -> str:
        return ", ".join(tool for tool in self.tools if not _resolve(tool))


def _resolve(tool: str) -> str | None:
    """Honour `RSP_<TOOL>` as the plugin does, or a tool it finds reads as missing."""
    override = os.environ.get(f"RSP_{tool.upper().replace('-', '_')}")
    return shutil.which(override or tool)


def _load(path: pathlib.Path) -> Implementation:
    """Fill in `{dir}` and `{python}`, so a command runs from any directory."""
    declared = json.loads(path.read_text(encoding="utf-8"))
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
