"""Wire codec — issue #6.

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
    """A request on the wire: compact UTF-8 JSON, one object.

    ensure_ascii is off so that content stays UTF-8 rather than u-escapes.
    Escaped, the bytes a plugin receives would no longer line up with the byte
    offsets it is expected to report (S1).

    allow_nan is off because NaN and Infinity are not JSON (RFC 8259) — Python
    writes them anyway. A host is the one who would produce them: a retriever
    score of NaN reaches metadata, and the request goes out as something a Go
    or Rust plugin rejects, making a working plugin look broken.

    Raises ValueError for a request that cannot be represented; call() turns
    that into an outcome, since only call() promises never to raise.
    """
    return json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _reject_constant(token: str) -> Any:
    raise ValueError(f"{token} is not JSON")


_DECODER = json.JSONDecoder(parse_constant=_reject_constant)


def decode(raw: bytes) -> tuple[Outcome, dict[str, Any] | None]:
    """Exactly one JSON object, and nothing else (T2, Q7).

    Not "the first object we can find": a plugin that prints a debug line
    before its response has put diagnostics on the protocol channel, and the
    host cannot tell that apart from a response it should act on. Rejecting is
    the only reading that keeps stdout meaningful.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Outcome.MALFORMED, None

    if not text.strip():
        return Outcome.EMPTY, None

    try:
        payload, end = _DECODER.raw_decode(text.lstrip())
    except (json.JSONDecodeError, ValueError):
        # ValueError covers the NaN/Infinity tokens rejected below: Python
        # accepts them by default, so a lenient host would take a response no
        # other implementation would, and the divergence would surface as
        # "works here, fails there".
        return Outcome.MALFORMED, None

    if text.lstrip()[end:].strip():
        return Outcome.MALFORMED, None  # a second object, or trailing noise
    if not isinstance(payload, dict):
        return Outcome.MALFORMED, None  # a list or a bare string is not a response

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
