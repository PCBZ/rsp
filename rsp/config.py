"""Plugins from a file, so that adding a scanner is not a code change.

Not part of the protocol. SPEC.md says a plugin is a command and says nothing
about where a host reads that command from, which is why nothing here appears
in the spec and why a host is free to ignore this module entirely.

`tomllib` because it is the standard library from 3.11 and the core promises to
add no dependencies (D7). A host that prefers YAML parses it itself and passes
the mapping to `plugins_from` — one call, and this file stays dependency-free:

    Runtime(plugins_from(yaml.safe_load(text)))

Unknown keys are errors rather than warnings. A misspelled `on_eror` that is
quietly ignored leaves a plugin failing open while the file still reads as if
it blocks, which is how a security control gets switched off by a typo.
"""

from __future__ import annotations

import math
import pathlib
import tomllib
from typing import Any

from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT
from rsp.runtime import ConfigError, OnError, Plugin

TOP_LEVEL = frozenset({"plugins"})
FIELDS = frozenset({"name", "command", "on_error", "timeout", "max_output"})
REQUIRED = ("name", "command")


def load(path: str | pathlib.Path) -> list[Plugin]:
    """Read a config file. Raises ConfigError for anything it cannot honour."""
    file = pathlib.Path(path)
    try:
        document = tomllib.loads(file.read_text(encoding="utf-8"))
    except OSError as unreadable:
        raise ConfigError(f"{file}: {unreadable.strerror}") from unreadable
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as invalid:
        raise ConfigError(f"{file}: {invalid}") from invalid
    return plugins_from(document, where=str(file))


def plugins_from(document: Any, where: str = "config") -> list[Plugin]:
    """The plugins a mapping describes, in the order it lists them."""
    if not isinstance(document, dict):
        raise ConfigError(f"{where}: expected a table, got {type(document).__name__}")
    if unknown := sorted(set(document) - TOP_LEVEL):
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")

    declared = document.get("plugins", [])
    if not isinstance(declared, list):
        raise ConfigError(f"{where}: plugins must be a list of tables")
    if not declared:
        # An empty list is a host with no guards, which is a thing to say out
        # loud rather than a file to accept in silence.
        raise ConfigError(f"{where}: no plugins configured")
    plugins = [_plugin(entry, f"{where}: plugins[{at}]") for at, entry in enumerate(declared)]
    # The runtime refuses these too, since a Plugin list can also be built in
    # Python. Refusing them here is what lets a check that starts nothing say
    # so: names key the declarations, and a duplicate hands one plugin
    # another's capabilities.
    seen: set[str] = set()
    for plugin in plugins:
        if plugin.name in seen:
            raise ConfigError(f"{where}: {plugin.name} configured twice")
        seen.add(plugin.name)
    return plugins


def _plugin(entry: Any, where: str) -> Plugin:
    if not isinstance(entry, dict):
        raise ConfigError(f"{where}: expected a table")
    if unknown := sorted(set(entry) - FIELDS):
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
    if missing := [field for field in REQUIRED if field not in entry]:
        raise ConfigError(f"{where}: missing {', '.join(missing)}")

    return Plugin(
        name=_text(entry["name"], f"{where}.name"),
        command=_command(entry["command"], f"{where}.command"),
        on_error=_on_error(entry.get("on_error"), f"{where}.on_error"),
        timeout=_positive(entry.get("timeout", DEFAULT_TIMEOUT), f"{where}.timeout"),
        max_output=_bytes(entry.get("max_output", DEFAULT_MAX_OUTPUT), f"{where}.max_output"),
    )


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}: expected a non-empty string")
    return value


def _command(value: Any, where: str) -> list[str]:
    """An argv list, never a string.

    `command = "gitleaks stdin"` is the shape that invites a shell, and a
    shell turns a plugin name into an injection point. Rejected rather than
    split on spaces, which would make the quoting rules ours to get wrong.
    """
    if isinstance(value, str):
        raise ConfigError(f"{where}: expected a list of arguments, not a string")
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where}: expected a non-empty list of arguments")
    return [_text(argument, f"{where}[{at}]") for at, argument in enumerate(value)]


def _on_error(value: Any, where: str) -> OnError:
    if value is None:
        return OnError.BLOCK
    try:
        return OnError(value)
    except ValueError:
        allowed = ", ".join(member.value for member in OnError)
        raise ConfigError(f"{where}: expected one of {allowed}, got {value!r}") from None


def _positive(value: Any, where: str) -> float:
    """A bound, so nothing that fails to bound anything.

    `timeout = nan` passed a `value <= 0` test, because every comparison with
    NaN is false — and then so is every comparison a wait makes with it, which
    is E4's bound switched off by a config value. `inf` says it out loud. TOML
    spells both.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{where}: expected a positive number")
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{where}: expected a positive finite number, got {value}")
    return float(value)


def _bytes(value: Any, where: str) -> int:
    """A count of bytes, which a fraction is not: int() would round it away."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{where}: expected a whole number of bytes")
    if value <= 0:
        raise ConfigError(f"{where}: expected a positive number")
    return value
