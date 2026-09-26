"""Subprocess lifecycle: start a plugin, feed it, drain it, reap it.

Bytes in, bytes out, and how the process ended. Knows no JSON, and not what a
failure means — that is rsp.runtime's job (E1). One process per call (Q6).
"""

from __future__ import annotations

import contextlib
import enum
import io
import os
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5.0  # seconds per call, startup included (E4)
DEFAULT_MAX_OUTPUT = 1 << 20  # bytes of stdout; more is an error (E1)
_CHUNK = 65536


class Outcome(enum.StrEnum):
    """How a call ended. Everything but OK is an error (E1, E3).

    One enum for process and content failures alike: the caller only asks
    whether the response can be trusted.
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
    """Kill the plugin and everything it spawned.

    A wrapper's tool can outlive it holding the pipe, hence a session of its own
    at spawn. Takes the group id because os.getpgid() fails once the child is
    reaped, while the group may still have members.
    """
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGKILL)


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
        proc = subprocess.Popen(
            list(command),  # argv, never a shell
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError, TypeError, IndexError) as exc:
        # An empty argv raises IndexError and a null entry TypeError (E2).
        return Invocation(Outcome.UNSPAWNABLE, b"", str(exc).encode(), None, 0.0)

    pgid = proc.pid  # its own group leader; recorded before anything exits

    out, err = bytearray(), bytearray()
    oversize = threading.Event()
    undelivered = threading.Event()
    truncated = threading.Event()

    def feed() -> None:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            undelivered.set()  # anything it prints is about content it never saw

    def drain(
        stream: io.BufferedReader, sink: bytearray, cap: int, *, protocol_channel: bool
    ) -> None:
        try:
            while chunk := stream.read1(_CHUNK):
                room = cap - len(sink)
                if len(chunk) <= room:
                    sink += chunk
                    continue
                sink += chunk[:room]
                if not protocol_channel:
                    # Noisy is not failing (E3): discard the excess, keep draining.
                    while stream.read1(_CHUNK):
                        pass
                    return
                oversize.set()
                _kill_group(pgid)
                return
        except OSError:
            if protocol_channel:  # lost stderr costs only diagnostics (E3)
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
        # E4 bounds the call from spawn, so the plugin's startup spends the budget.
        proc.wait(timeout=max(0.0, timeout - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(pgid)
        proc.wait()  # reap: no zombie

    # Also after a clean exit: a wrapper can exit zero with its tool still holding the pipe.
    _kill_group(pgid)

    for worker in workers:
        worker.join(timeout=1.0)

    if not any(worker.is_alive() for worker in workers):
        # Closing a stream a stalled worker still reads is the worse bug.
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            with contextlib.suppress(OSError):
                stream.close()

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
