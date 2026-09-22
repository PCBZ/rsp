"""Which plugins exist, what runs them, and what a case is allowed to name.

A case names a **role**, not an implementation. `gitleaks` means any adapter
wrapping that binary, so a case written against one of them holds for all of
them — which is the protocol's whole claim, and was untestable while the case
files named a language. Two implementations of one role must answer every case
identically; that is now a thing the suite can check rather than assert.

Nothing here imports `rsp`: the conformance harness has to run with the
runtime source absent.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).parent.parent


@dataclass(frozen=True)
class Implementation:
    """A plugin: a command, and what has to be installed to run it."""

    name: str
    role: str
    command: tuple[str, ...]
    tools: tuple[str, ...]

    @property
    def installed(self) -> bool:
        return all(_resolve(tool) for tool in self.tools)

    @property
    def missing(self) -> str:
        return ", ".join(tool for tool in self.tools if not _resolve(tool))


def _resolve(tool: str) -> str | None:
    """Where the plugin will look for a tool, which is where this must look.

    A wrapper can be pointed at its tool by `RSP_<TOOL>`; checking only PATH
    reports a tool missing while the plugin goes on to find it.
    """
    override = os.environ.get(f"RSP_{tool.upper().replace('-', '_')}")
    return shutil.which(override or tool)


def _go_command() -> tuple[str, ...]:
    """A built binary when one is offered, `go run` otherwise.

    `go run` recompiles on every invocation, which the corpus suite would pay
    for four hundred times.
    """
    if built := os.environ.get("RSP_GITLEAKS_GO"):
        return (built,)
    return ("go", "run", str(ROOT / "examples/gitleaks-go"))


REGISTRY = (
    Implementation(
        name="rsp-echo",
        role="echo",
        command=(sys.executable, str(ROOT / "plugins/rsp-echo/main.py")),
        tools=(sys.executable,),
    ),
    Implementation(
        name="rsp-gitleaks-ts",
        role="gitleaks",
        command=("node", str(ROOT / "examples/gitleaks-ts/src/main.ts")),
        tools=("node", "gitleaks"),
    ),
    Implementation(
        name="rsp-gitleaks-go",
        role="gitleaks",
        command=_go_command(),
        tools=("go", "gitleaks") if "RSP_GITLEAKS_GO" not in os.environ else ("gitleaks",),
    ),
)


def for_role(role: str) -> list[Implementation]:
    return [implementation for implementation in REGISTRY if implementation.role == role]


# Toolchains belong to CI, not to a contributor's machine. Locally a missing one
# skips its cases; here it fails, because a silently skipped plugin proves
# nothing.
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"
