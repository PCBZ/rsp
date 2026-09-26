"""Wire codec.

A request mapping in, a parsed response out, or an outcome explaining why there
is none. Sits above the process layer and below plugin identity: chaos testing
can drive rsp.process with garbage, and these functions can be exercised on raw
bytes without spawning anything.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Invocation, Outcome, invoke

RSP_VERSION = "0.1"


def encode(request: Mapping[str, Any]) -> bytes:
    """One request as compact UTF-8 JSON. Raises ValueError if it cannot be.

    Both flags are load-bearing. `ensure_ascii` off keeps content as UTF-8, so
    the bytes a plugin counts are the bytes we sent (S1). `allow_nan` off stops
    Python emitting NaN and Infinity, which it does by default and which no
    other language's parser accepts.

    Only call() promises never to raise, so it is call() that turns the
    ValueError into an outcome.
    """
    # Outbound too: T4 is about a message, and a request is one. A host that
    # sends what it would refuse has written a rule for everyone else.
    _sendable(request)
    return json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _sendable(value: Any, seen: frozenset[int] = frozenset()) -> None:
    """Raise if any part of a request would violate T4 on the wire.

    `seen` carries the containers above this one. Without it a host that
    nested metadata inside itself recursed until Python gave up, and a
    RecursionError is not the ValueError the caller turns into a verdict — so
    `evaluate` raised, which E2 forbids. json.dumps refuses a cycle on its
    own; this has to refuse one before it gets there.
    """
    if isinstance(value, (Mapping, list, tuple)):
        if id(value) in seen:
            raise ValueError("a request cannot contain itself")
        seen = seen | {id(value)}
    if isinstance(value, Mapping):
        # `{1: "a", "1": "b"}` is two keys here and one key twice on the wire:
        # json.dumps writes an integer key as a string without saying so.
        written = [str(key) if isinstance(key, (int, float, bool)) else key for key in value]
        if len(set(written)) != len(written):
            raise ValueError("a key would be repeated once written")
        for nested in value.values():
            _sendable(nested, seen)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _sendable(nested, seen)
    elif isinstance(value, int) and not isinstance(value, bool) and abs(value) > SAFE_INTEGER:
        raise ValueError(f"{value} is outside the interoperable range")


def _reject_constant(token: str) -> Any:
    """NaN and Infinity are not JSON (RFC 8259); Python's parser takes them."""
    raise ValueError(f"{token} is not JSON")


# RFC 8259 §6: outside this range an implementation may lose precision, and
# two hosts that round differently disagree about a span.
SAFE_INTEGER = 2**53 - 1

# RFC 8259 §2 allows exactly these around a value. `str.strip()` also removes
# a non-breaking space and a line separator, which a strict parser refuses —
# leniency in the framing is the same divergence as leniency in the grammar.
WHITESPACE = " \t\n\r"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """RFC 8259 leaves duplicates undefined, and parsers differ: last wins in
    Python, Go and JavaScript, first wins elsewhere, some refuse. A plugin
    sending `{"verdict":"ALLOW","verdict":"BLOCK"}` is asking two hosts to
    disagree about whether content is safe, so this one refuses to guess.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen.add(key)
    return dict(pairs)


def _checked_number(token: str) -> int:
    """Integers a JavaScript host could not read back unchanged."""
    value = int(token)
    if abs(value) > SAFE_INTEGER:
        raise ValueError(f"{token} is outside the interoperable range")
    return value


_DECODER = json.JSONDecoder(
    parse_constant=_reject_constant,
    object_pairs_hook=_reject_duplicate_keys,
    parse_int=_checked_number,
)


def decode(raw: bytes) -> tuple[Outcome, dict[str, Any] | None]:
    """Exactly one JSON object and nothing else, or why not (T2).

    Not "the first object that parses": anything else on stdout means the
    plugin treats the protocol channel as a log, and the host cannot tell a
    stray line from a response.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Outcome.MALFORMED, None

    # Stripped with JSON's four, not Python's: a plugin whose whole output is
    # some other space character said something, and EMPTY means it did not.
    body = text.lstrip(WHITESPACE)
    if not body:
        return Outcome.EMPTY, None

    try:
        payload, end = _DECODER.raw_decode(body)
    except (json.JSONDecodeError, ValueError):
        return Outcome.MALFORMED, None  # ValueError: the NaN tokens _DECODER rejects

    if body[end:].strip(WHITESPACE):
        return Outcome.MALFORMED, None  # a second object, or trailing noise
    if not isinstance(payload, dict):
        return Outcome.MALFORMED, None  # a list or a bare string is not a response
    try:
        # `\ud800` is legal JSON and not text: it survives parsing and cannot
        # be written back as UTF-8. Checked on the parsed payload, because the
        # escape is only a surrogate after the parser has read it — a host
        # that accepts one fails later, somewhere else, holding content it can
        # no longer put anywhere (M1).
        encode(payload)
    except (UnicodeEncodeError, ValueError):
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
    """One plugin call, from a request mapping to a parsed response.

    Never raises (E2). A process that failed is reported as it failed; only a
    process that ended cleanly has its output parsed, because output from a
    killed or truncated call is a fragment whether or not it happens to parse.
    """
    try:
        payload_bytes = encode(request)
    except (ValueError, TypeError):
        # The host built a request that is not JSON. No plugin is at fault and
        # none was run, but there is no verdict either, so this is an error
        # like any other (E3).
        return Reply(Outcome.UNENCODABLE, None, None)

    invocation = invoke(command, payload_bytes, timeout=timeout, max_output=max_output)
    if not invocation.ok:
        return Reply(invocation.outcome, None, invocation)

    outcome, payload = decode(invocation.stdout)
    return Reply(outcome, payload, invocation)
