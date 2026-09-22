"""Which plugins exist, what runs them, and what a case is allowed to name.

A case names a role, not an implementation: `gitleaks` is any adapter over that
binary, so one case holds for all of them. Nothing here imports `rsp` — the
conformance harness has to run with the runtime source absent.
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


REGISTRY = (
    Implementation(
        name="rsp-echo",
        role="echo",
        source=(sys.executable, str(ROOT / "plugins/rsp-echo/main.py")),
        toolchain=(sys.executable,),
    ),
    Implementation(
        name="rsp-gitleaks-ts",
        role="gitleaks",
        source=("node", str(ROOT / "examples/gitleaks-ts/src/main.ts")),
        toolchain=("node",),
        wraps=("gitleaks",),
    ),
    Implementation(
        name="rsp-gitleaks-go",
        role="gitleaks",
        # -C, because `go run <dir>` resolves the package against the working
        # directory's module and the repository root is not one.
        source=("go", "run", "-C", str(ROOT / "examples/gitleaks-go"), "."),
        toolchain=("go",),
        wraps=("gitleaks",),
    ),
)


def for_role(role: str) -> list[Implementation]:
    return [implementation for implementation in REGISTRY if implementation.role == role]


# Toolchains belong to CI, not to a contributor's machine. Locally a missing one
# skips its cases; here it fails, because a silently skipped plugin proves
# nothing.
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"
