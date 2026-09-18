"""Subprocess invocation — issue #4.

Lifecycle only: start a plugin, feed it, drain it, reap it. No JSON (#6), no
handshake (#5), no verdicts (#7). This layer returns bytes and a classification;
turning a failure into BLOCK (E1) belongs to the layer above.

Spawn-per-call is the v0.1 process model (Q6).
"""

from __future__ import annotations

import enum
import os
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5.0  # seconds, per call (Q4)
DEFAULT_MAX_OUTPUT = 1 << 20  # 1 MiB of stdout (Q7)
_CHUNK = 65536


class Outcome(enum.Enum):
    """What happened to the process. Everything but OK is an error under E1."""

    OK = "OK"
    TIMEOUT = "TIMEOUT"
    OVERSIZE = "OVERSIZE"
    UNDELIVERED = "UNDELIVERED"
    CRASHED = "CRASHED"
    UNSPAWNABLE = "UNSPAWNABLE"


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
    except OSError as exc:
        return Invocation(Outcome.UNSPAWNABLE, b"", str(exc).encode(), None, 0.0)

    pgid = proc.pid  # it leads its own group; record it before anything exits

    out, err = bytearray(), bytearray()
    oversize = threading.Event()
    undelivered = threading.Event()

    def feed() -> None:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except OSError:
            # The plugin stopped reading before it had the whole request, so it
            # cannot have parsed one. Whatever it printed is a verdict about
            # content it never saw, and under E1 that must not read as OK.
            undelivered.set()

    def drain(stream, sink: bytearray, cap: int) -> None:
        try:
            while chunk := stream.read1(_CHUNK):
                room = cap - len(sink)
                if len(chunk) >= room:
                    sink += chunk[:room]
                    oversize.set()
                    _kill_group(pgid)
                    return
                sink += chunk
        except OSError:
            pass

    workers = [
        threading.Thread(target=feed, daemon=True),
        threading.Thread(target=drain, args=(proc.stdout, out, max_output), daemon=True),
        threading.Thread(target=drain, args=(proc.stderr, err, max_output), daemon=True),
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

    if oversize.is_set():
        outcome = Outcome.OVERSIZE
    elif timed_out:
        outcome = Outcome.TIMEOUT
    elif proc.returncode != 0:
        outcome = Outcome.CRASHED
    elif undelivered.is_set():
        outcome = Outcome.UNDELIVERED
    else:
        outcome = Outcome.OK

    return Invocation(
        outcome=outcome,
        stdout=bytes(out),
        stderr=bytes(err),
        exit_code=proc.returncode,
        duration=time.monotonic() - started,
    )
