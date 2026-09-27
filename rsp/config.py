"""Plugins from a TOML file, so that adding a scanner is not a code change.

Not part of the protocol; a host is free to ignore this module. One that prefers
another format parses it and passes the mapping on:

    Runtime(plugins_from(yaml.safe_load(text)))

Unknown keys are errors, not warnings: a quietly ignored `on_eror` leaves a
plugin failing open while the file reads as if it blocks.
"""

from __future__ import annotations

import math
import pathlib
import tomllib
from typing import Any

from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT
from rsp.runtime import ConfigError, OnError, Plugin

_TOP_LEVEL = frozenset({"plugins"})
_FIELDS = frozenset({"name", "command", "on_error", "timeout", "max_output"})
_REQUIRED = ("name", "command")


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{where}: expected a non-empty string")
    return value


def _command(value: Any, where: str) -> list[str]:
    """An argv list, never a string.

    A string invites a shell, and splitting it on spaces would make the quoting
    rules ours to get wrong.
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
    """A finite positive number: `nan` passes `value <= 0` and would switch off E4."""
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


def _plugin(entry: Any, where: str) -> Plugin:
    if not isinstance(entry, dict):
        raise ConfigError(f"{where}: expected a table")
    if unknown := sorted(set(entry) - _FIELDS):
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")
    if missing := [field for field in _REQUIRED if field not in entry]:
        raise ConfigError(f"{where}: missing {', '.join(missing)}")

    return Plugin(
        name=_text(entry["name"], f"{where}.name"),
        command=_command(entry["command"], f"{where}.command"),
        on_error=_on_error(entry.get("on_error"), f"{where}.on_error"),
        timeout=_positive(entry.get("timeout", DEFAULT_TIMEOUT), f"{where}.timeout"),
        max_output=_bytes(entry.get("max_output", DEFAULT_MAX_OUTPUT), f"{where}.max_output"),
    )


def plugins_from(document: Any, where: str = "config") -> list[Plugin]:
    """The plugins a mapping describes, in the order it lists them."""
    if not isinstance(document, dict):
        raise ConfigError(f"{where}: expected a table, got {type(document).__name__}")
    if unknown := sorted(set(document) - _TOP_LEVEL):
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}")

    declared = document.get("plugins", [])
    if not isinstance(declared, list):
        raise ConfigError(f"{where}: plugins must be a list of tables")
    if not declared:
        # A host with no guards is said out loud, not accepted in silence.
        raise ConfigError(f"{where}: no plugins configured")
    plugins = [_plugin(entry, f"{where}: plugins[{at}]") for at, entry in enumerate(declared)]
    # Runtime refuses these too; checking here lets `rsp validate`, which starts nothing, say so.
    seen: set[str] = set()
    for plugin in plugins:
        if plugin.name in seen:
            raise ConfigError(f"{where}: {plugin.name} configured twice")
        seen.add(plugin.name)
    return plugins


def load(path: str | pathlib.Path) -> list[Plugin]:
    """Read a config file. Raises ConfigError for anything it cannot honour."""
    file = pathlib.Path(path)
    try:
        document = tomllib.loads(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"{file}: {exc.strerror}") from exc
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{file}: {exc}") from exc
    return plugins_from(document, where=str(file))
