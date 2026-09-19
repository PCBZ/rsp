"""Plugin invocation and codec — issues #4 and #6.

Two layers, deliberately separable:

    invoke()  bytes in, bytes out, plus a classification of how the process
              ended. Knows nothing about JSON.
    call()    a request mapping in, a parsed response out, or an outcome
              explaining why there is none.
    handshake()  who a plugin says it is, validated (#5).
    redact()  what a chunk looks like after every plugin has spoken (#21).

Neither turns a failure into BLOCK. That is E1, and it belongs to the layer
that knows about verdicts (#7).

Spawn-per-call is the v0.1 process model (Q6).
"""

from __future__ import annotations

import enum
import json
import os
import signal
import subprocess
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

RSP_VERSION = "0.1"
DEFAULT_TIMEOUT = 5.0  # seconds, per call (Q4)
DEFAULT_MAX_OUTPUT = 1 << 20  # 1 MiB of stdout (Q7)
_CHUNK = 65536


class Outcome(enum.Enum):
    """How a call ended. Everything but OK is an error under E1 and E3.

    The first six describe the process; the last two describe what it said.
    Kept in one enum because a caller asking "may I trust this response?" does
    not care which half went wrong, while a caller writing a log line does.
    """

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    OVERSIZE = "OVERSIZE"
    UNDELIVERED = "UNDELIVERED"
    TRUNCATED = "TRUNCATED"
    CRASHED = "CRASHED"
    UNSPAWNABLE = "UNSPAWNABLE"
    EMPTY = "EMPTY"
    MALFORMED = "MALFORMED"
    UNENCODABLE = "UNENCODABLE"


@dataclass(frozen=True)
class Invocation:
    outcome: Outcome
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    duration: float

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.OK


def _kill_group(pgid: int) -> None:
    """Kill the plugin and anything it spawned.

    A plugin is usually a wrapper — rsp-gitleaks runs the gitleaks binary — so
    killing only the direct child leaves the grandchild holding the CPU and the
    pipe. The process gets its own session at spawn time precisely so the whole
    group can go at once.

    Takes the group id rather than the process, because the group outlives the
    process: once the direct child has been reaped, os.getpgid() raises and
    there is nothing left to ask. Under start_new_session the child leads its
    own group, so the id is its pid, recorded before anything can exit.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def invoke(
    command: Sequence[str],
    payload: bytes,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> Invocation:
    """Run one plugin call. Never raises: every failure is an Outcome (E2)."""
    started = time.monotonic()
    try:
        # A list, never a string: no shell, so nothing in the config can be
        # interpolated into one.
        proc = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError, TypeError, IndexError) as exc:
        # OSError covers a missing binary or a bad permission, but `command`
        # comes from user config: an empty list raises IndexError and a null
        # entry raises TypeError. This function never raises (E2), so a
        # misconfigured plugin has to leave here as a verdict, not a traceback.
        return Invocation(Outcome.UNSPAWNABLE, b"", str(exc).encode(), None, 0.0)

    pgid = proc.pid  # it leads its own group; record it before anything exits

    out, err = bytearray(), bytearray()
    oversize = threading.Event()
    undelivered = threading.Event()
    truncated = threading.Event()

    def feed() -> None:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            # The plugin stopped reading before it had the whole request, so it
            # cannot have parsed one. Whatever it printed is a verdict about
            # content it never saw, and under E1 that must not read as OK.
            undelivered.set()

    def drain(stream, sink: bytearray, cap: int, *, protocol_channel: bool) -> None:
        try:
            while chunk := stream.read1(_CHUNK):
                room = cap - len(sink)
                if len(chunk) > room:
                    sink += chunk[:room]
                    oversize.set()
                    _kill_group(pgid)
                    return
                sink += chunk
        except OSError:
            # Bytes lost on stdout mean the response is incomplete, and an
            # incomplete response must not read as success. On stderr it only
            # costs diagnostics, and refusing content over a lost log line
            # would block chunks for no security reason.
            if protocol_channel:
                truncated.set()

    workers = [
        threading.Thread(target=feed, daemon=True),
        threading.Thread(
            target=drain,
            args=(proc.stdout, out, max_output),
            kwargs={"protocol_channel": True},
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(proc.stderr, err, max_output),
            kwargs={"protocol_channel": False},
            daemon=True,
        ),
    ]
    for worker in workers:
        worker.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(pgid)
        proc.wait()  # reap, so a timeout leaves no zombie

    # Also after a clean exit. A wrapper can exit zero having left the tool it
    # spawned running, and that grandchild holds the pipe open — the drain
    # threads would block until it decided to finish. One call, one process
    # group, and the group ends when the call does (Q6).
    _kill_group(pgid)

    for worker in workers:
        worker.join(timeout=1.0)

    if not any(worker.is_alive() for worker in workers):
        # Close our ends rather than waiting for the Popen to be collected. A
        # stalled worker still holds a stream, so leave those to the collector
        # instead of closing a file another thread is reading.
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    if oversize.is_set():
        outcome = Outcome.OVERSIZE
    elif timed_out:
        outcome = Outcome.TIMEOUT
    elif proc.returncode != 0:
        outcome = Outcome.CRASHED
    elif undelivered.is_set():
        outcome = Outcome.UNDELIVERED
    elif truncated.is_set():
        outcome = Outcome.TRUNCATED
    else:
        outcome = Outcome.OK

    return Invocation(
        outcome=outcome,
        stdout=bytes(out),
        stderr=bytes(err),
        exit_code=proc.returncode,
        duration=time.monotonic() - started,
    )


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


REQUIRED_DECLARATION_FIELDS = ("rsp_version", "name", "version", "hooks")


@dataclass(frozen=True)
class Handshake:
    """What a plugin says it is (H2).

    Only what the host acts on. `hooks` decides what it is called with (H3),
    `version` is part of a cache key (D4), `deterministic` decides whether
    caching is legal at all, and `max_inline_bytes` is the plugin's own limit
    on how much content it will take inline (D5).
    """

    rsp_version: str
    name: str
    version: str
    hooks: frozenset[str]
    deterministic: bool = False
    max_inline_bytes: int | None = None

    def supports(self, hook: str) -> bool:
        return hook in self.hooks

    def inline_limit(self, host_limit: int) -> int:
        """The smaller of what the plugin accepts and what the host offers.

        Declarations lower the limit; they never raise it. A plugin asking for
        more than the host allows would otherwise choose how much memory the
        host spends on it, which is the attack the output cap exists to stop
        (Q7) arriving through the front door instead.
        """
        return (
            host_limit if self.max_inline_bytes is None else min(self.max_inline_bytes, host_limit)
        )


def _declaration(payload: Mapping[str, Any]) -> Handshake | None:
    """Validate a declaration. Unknown fields are ignored, never an error (D8)."""
    if any(field not in payload for field in REQUIRED_DECLARATION_FIELDS):
        return None

    hooks = payload["hooks"]
    if not isinstance(hooks, list) or not all(isinstance(hook, str) for hook in hooks):
        return None
    if not all(isinstance(payload[f], str) for f in ("rsp_version", "name", "version")):
        return None

    # Defaulting rather than guessing: a plugin that did not say it is
    # deterministic is not treated as one, because the cost of guessing wrong is
    # a cached verdict from a plugin whose answer depends on when you asked.
    deterministic = payload.get("deterministic", False)
    if not isinstance(deterministic, bool):
        return None

    max_inline = payload.get("max_inline_bytes")
    if max_inline is not None and (
        not isinstance(max_inline, int) or isinstance(max_inline, bool) or max_inline <= 0
    ):
        return None

    return Handshake(
        rsp_version=payload["rsp_version"],
        name=payload["name"],
        version=payload["version"],
        hooks=frozenset(hooks),
        deterministic=deterministic,
        max_inline_bytes=max_inline,
    )


def handshake(
    command: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> tuple[Outcome, Handshake | None]:
    """Ask a plugin who it is, before sending it any content (H1).

    Its own invocation rather than the first message of a stream, because one
    call is one process in v0.1 (Q6). The cost is an extra spawn per plugin per
    run, which caching cannot remove: the cache key contains the plugin version,
    and the version is what the handshake is for (#13).
    """
    reply = call(
        command,
        {"rsp_version": RSP_VERSION, "hook": "handshake"},
        timeout=timeout,
        max_output=max_output,
    )
    if not reply.ok:
        return reply.outcome, None

    declaration = _declaration(reply.payload)
    if declaration is None:
        return Outcome.MALFORMED, None
    return Outcome.OK, declaration


class Severity(enum.IntEnum):
    """The scale S6 compares. IntEnum because the comparison is the point.

    Only a rank. The wire value stays a string on the Span: a plugin that
    declares "catastrophic" ranks lowest (S7) but the operator should still see
    the word it used, and normalising it away would hide a plugin that thinks
    it is being more severe than the scale allows.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def of(cls, wire: str | None) -> Severity:
        """Rank a declared severity. Unknown is lowest, never an error (S7, D8).

        Exact match: "CRITICAL" is not "critical". Accepting case variants would
        be this host taking something a stricter one rejects, which is the
        leniency tracked in #29.
        """
        try:
            return cls[wire.upper()] if wire and wire.islower() else cls.LOW
        except KeyError:
            return cls.LOW


@dataclass(frozen=True)
class Span:
    """A range one plugin wants masked, carried with what it takes to merge.

    `replacement` and `severity` come from the response the span arrived in
    (V3, V4); `order` is the plugin's position in the configured list, which is
    what settles a tie without asking the clock.
    """

    start: int
    end: int
    type: str | None = None
    severity: str = "low"
    replacement: str = "[REDACTED]"
    order: int = 0

    @property
    def rank(self) -> Severity:
        return Severity.of(self.severity)


def valid_span(span: Span, content: bytes) -> bool:
    """S3. Plugins are untrusted, so a span is a claim until it is checked.

    An unchecked span is a host crash waiting to happen: a range past the end
    slices short in Python and raises elsewhere, and one that cuts a multi-byte
    character raises on decode. Either way a plugin chose when the host fell
    over.
    """
    if span.start < 0 or span.end > len(content) or span.start > span.end:
        return False
    # A continuation byte is 0b10xxxxxx; a boundary is anything else.
    return all(
        i in (0, len(content)) or (content[i] & 0xC0) != 0x80 for i in (span.start, span.end)
    )


def merge_spans(spans: Iterable[Span]) -> list[Span]:
    """Coalesce overlapping and adjacent ranges into one (S6).

    Adjacent ranges merge too: two plugins finding neighbouring secrets should
    produce one mask, not `[REDACTED][REDACTED]`, which tells a reader exactly
    how the boundary fell.

    The surviving replacement is the highest-severity contributor's, ties going
    to the earlier plugin. Any rule other than a total order would make the
    output depend on which plugin happened to answer first.
    """
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[Span] = []
    for span in ordered:
        if merged and span.start <= merged[-1].end:
            current = merged[-1]
            winner = max((current, span), key=lambda s: (s.rank, -s.order))
            types = {t for t in (current.type, span.type) if t}
            merged[-1] = Span(
                start=current.start,
                end=max(current.end, span.end),
                type="+".join(sorted(types)) or None,
                severity=winner.severity,
                replacement=winner.replacement,
                # The winner's order, not the earliest contributor's: this
                # field exists to break the next tie, and the next tie is
                # against whoever currently holds the replacement. Carrying the
                # earliest order instead lets a later plugin keep a replacement
                # that an earlier one should have taken.
                order=winner.order,
            )
        else:
            merged.append(span)
    return merged


def redact(content: str, spans: Iterable[Span]) -> tuple[str, list[Span]]:
    """Apply every plugin's spans to the original content, once (S5).

    Every plugin on a hook sees the same bytes, and masking happens after the
    last one has answered. The alternative — handing plugin N+1 what plugin N
    redacted — means each plugin reports offsets into a different string, and
    the host has to map them back. One coordinate system costs duplicate
    findings on the same bytes, which is what merging is for.

    Invalid spans are dropped and returned, so the caller can treat the
    response as a plugin error (S3, E1) rather than silently masking the wrong
    bytes.
    """
    data = content.encode("utf-8")
    usable, rejected = [], []
    for span in spans:
        (usable if valid_span(span, data) else rejected).append(span)

    out, cursor = bytearray(), 0
    for span in merge_spans(usable):
        out += data[cursor : span.start]
        out += span.replacement.encode("utf-8")
        cursor = span.end
    out += data[cursor:]
    return out.decode("utf-8"), rejected
