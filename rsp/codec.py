"""Wire codec: a request mapping in, a parsed response out, or why not.

Sits between rsp.process and plugin identity, so both directions can be tested on
raw bytes without spawning anything.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Invocation, Outcome, invoke

RSP_VERSION = "0.1"
# Past this, parsers lose precision and two hosts disagree about a span (RFC 8259 §6).
_SAFE_INTEGER = 2**53 - 1
# RFC 8259 §2 whitespace. str.strip() also removes characters a strict parser refuses.
_WHITESPACE = " \t\n\r"


def _sendable(value: Any, seen: frozenset[int] = frozenset()) -> None:
    """Raise ValueError if any part of a request would break T4 on the wire.

    `seen` holds the containers above this one, so a request nested inside itself
    fails as a ValueError rather than a RecursionError, which `call` cannot catch (E2).
    """
    if isinstance(value, (Mapping, list, tuple)):
        if id(value) in seen:
            raise ValueError("a request cannot contain itself")
        seen = seen | {id(value)}
    if isinstance(value, Mapping):
        # json.dumps writes the key 1 as "1", so {1: "a", "1": "b"} repeats a key.
        written = [str(key) if isinstance(key, (int, float, bool)) else key for key in value]
        if len(set(written)) != len(written):
            raise ValueError("a key would be repeated once written")
        for nested in value.values():
            _sendable(nested, seen)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _sendable(nested, seen)
    elif isinstance(value, int) and not isinstance(value, bool) and abs(value) > _SAFE_INTEGER:
        raise ValueError(f"{value} is outside the interoperable range")


def encode(request: Mapping[str, Any]) -> bytes:
    """One request as compact UTF-8 JSON. Raises ValueError if it cannot be.

    `ensure_ascii=False` keeps the bytes a plugin counts the bytes we sent (S1);
    `allow_nan=False` stops Python writing NaN, which no other parser accepts.
    """
    _sendable(request)  # a host does not send what it would refuse (T4)
    return json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _reject_constant(token: str) -> Any:
    """NaN and Infinity are not JSON (RFC 8259); Python's parser takes them."""
    raise ValueError(f"{token} is not JSON")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated key: parsers disagree about which one wins (RFC 8259 §4)."""
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _checked_number(token: str) -> int:
    """Integers a JavaScript host could not read back unchanged."""
    value = int(token)
    if abs(value) > _SAFE_INTEGER:
        raise ValueError(f"{token} is outside the interoperable range")
    return value


_DECODER = json.JSONDecoder(
    parse_constant=_reject_constant,
    object_pairs_hook=_reject_duplicate_keys,
    parse_int=_checked_number,
)


def decode(raw: bytes) -> tuple[Outcome, dict[str, Any] | None]:
    """Exactly one JSON object and nothing else, or why not (T2).

    Not the first object that parses: anything else on stdout makes the protocol
    channel a log, where a stray line looks like a response.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Outcome.MALFORMED, None

    # Stripped with JSON's four, not Python's: a plugin whose whole output is
    # some other space character said something, and EMPTY means it did not.
    body = text.lstrip(_WHITESPACE)
    if not body:
        return Outcome.EMPTY, None

    try:
        payload, end = _DECODER.raw_decode(body)
    except ValueError:  # JSONDecodeError, or a value the hooks above refuse
        return Outcome.MALFORMED, None

    if body[end:].strip(_WHITESPACE):
        return Outcome.MALFORMED, None  # a second object, or trailing noise
    if not isinstance(payload, dict):
        return Outcome.MALFORMED, None  # a list or a bare string is not a response
    try:
        encode(payload)  # `\ud800` parses, and cannot be written back as UTF-8 (M1)
    except ValueError:
        return Outcome.MALFORMED, None

    return Outcome.OK, payload


@dataclass(frozen=True)
class Reply:
    outcome: Outcome
    payload: dict[str, Any] | None
    invocation: Invocation | None  # None when no process was ever started

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.OK


def call(
    command: Sequence[str],
    request: Mapping[str, Any],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> Reply:
    """One plugin call, from a request mapping to a parsed response. Never raises (E2).

    Only a clean exit has its output parsed: from a killed or truncated call it is
    a fragment, whether or not it happens to parse.
    """
    try:
        payload_bytes = encode(request)
    except (ValueError, TypeError):
        # No plugin is at fault and none ran, but there is no verdict either (E3).
        return Reply(Outcome.UNENCODABLE, None, None)

    invocation = invoke(command, payload_bytes, timeout=timeout, max_output=max_output)
    if not invocation.ok:
        return Reply(invocation.outcome, None, invocation)

    outcome, payload = decode(invocation.stdout)
    return Reply(outcome, payload, invocation)
