"""Process lifecycle tests. Plugins here are inline scripts; a real
misbehaving plugin replaces them once one exists."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from rsp import process as runtime
from rsp.process import Invocation, Outcome, invoke

ECHO = [sys.executable, "plugins/rsp-echo/main.py"]
CAP = 4096


def script(body: str) -> list[str]:
    return [sys.executable, "-c", body]


def test_reference_plugin_round_trips() -> None:
    request = {"rsp_version": "0.1", "hook": "on_chunk", "content": "a secret here"}
    result = invoke(ECHO, json.dumps(request).encode())
    assert result.ok
    assert json.loads(result.stdout)["verdict"] == "REDACT"
    assert b"rsp-echo" in result.stderr  # diagnostics arrived, on the right channel (T2)


def test_nonzero_exit_is_crashed() -> None:
    result = invoke(script("import sys; sys.exit(3)"), b"{}")
    assert result.outcome is Outcome.CRASHED
    assert result.exit_code == 3


def test_missing_binary_is_unspawnable() -> None:
    result = invoke(["./definitely-not-a-plugin"], b"{}")
    assert result.outcome is Outcome.UNSPAWNABLE
    assert result.stdout == b""


@pytest.mark.parametrize("command", [[], [None], [""], ["", "x"]])
def test_malformed_command_is_unspawnable(command) -> None:
    """`command` comes from rsp.yaml. An empty list raises IndexError and a
    null entry raises TypeError, neither of which is an OSError."""
    result = invoke(command, b"{}")
    assert result.outcome is Outcome.UNSPAWNABLE
    assert result.stderr  # the reason survives for the operator


def test_output_exactly_at_the_cap_is_not_oversize() -> None:
    # Reads stdin first, like a real plugin. A script that exits without
    # reading races feed(): the write usually lands in the pipe buffer, but
    # when it loses, the outcome is UNDELIVERED and the test flakes.
    exact = script(f"import sys; sys.stdin.read(); sys.stdout.buffer.write(b'x' * {CAP})")
    result = invoke(exact, b"{}", timeout=5.0, max_output=CAP)
    assert result.outcome is Outcome.OK
    assert len(result.stdout) == CAP


def test_one_byte_over_the_cap_is_oversize() -> None:
    over = script(f"import sys; sys.stdin.read(); sys.stdout.buffer.write(b'x' * {CAP + 1})")
    result = invoke(over, b"{}", timeout=5.0, max_output=CAP)
    assert result.outcome is Outcome.OVERSIZE
    assert len(result.stdout) == CAP  # truncated to the cap, not one past it


def test_hang_times_out_promptly() -> None:
    result = invoke(script("import time; time.sleep(30)"), b"{}", timeout=0.5)
    assert result.outcome is Outcome.TIMEOUT
    assert result.duration < 5.0  # killed, not waited out


def test_flood_is_capped() -> None:
    flood = script("import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)")
    result = invoke(flood, b"{}", timeout=10.0, max_output=1 << 16)
    assert result.outcome is Outcome.OVERSIZE
    assert len(result.stdout) <= 1 << 16  # the cap is the cap, not the cap plus a chunk


def test_partial_delivery_is_not_ok() -> None:
    """A plugin that stopped reading never saw the whole request, so its
    verdict is about content it does not have. Not a deadlock, and not OK."""
    result = invoke(script("print('{}')"), b"x" * (1 << 20), timeout=5.0)
    assert result.outcome is Outcome.UNDELIVERED
    assert result.duration < 5.0


def test_timeout_kills_the_whole_process_group() -> None:
    """A plugin is usually a wrapper. Killing only the child orphans the tool."""
    spawner = script(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(30)\n"
    )
    result = invoke(spawner, b"{}", timeout=1.0)
    assert result.outcome is Outcome.TIMEOUT

    grandchild = int(result.stdout.split()[0])
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.05)
    pytest.fail(f"grandchild {grandchild} survived the timeout")


def test_no_zombies_left_behind() -> None:
    before = _child_count()
    for _ in range(5):
        invoke(script("import time; time.sleep(10)"), b"{}", timeout=0.3)
    assert _child_count() <= before


def _child_count() -> int:
    out = subprocess.run(
        ["ps", "-o", "stat=", "-g", str(os.getpid())], capture_output=True, text=True, check=False
    ).stdout
    return sum(1 for line in out.splitlines() if "Z" in line)


def test_descendants_die_even_when_the_wrapper_exits_cleanly() -> None:
    """The dangerous case is not the hang — it is the wrapper that returns 0
    having left the tool it spawned running and holding the pipe."""
    spawner = script(
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print(child.pid, flush=True)\n"
    )
    started = time.monotonic()
    result = invoke(spawner, b"{}", timeout=10.0)
    assert result.duration < 5.0  # did not wait on the grandchild's pipe

    grandchild = int(result.stdout.split()[0])
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except (ProcessLookupError, PermissionError):
            return
        time.sleep(0.05)
    pytest.fail(f"grandchild {grandchild} outlived the call ({time.monotonic() - started:.1f}s)")


class _FailingStream:
    """A pipe that dies mid-read. Hard to provoke with a real plugin, easy to
    hand to the drain loop."""

    def __init__(self, chunks: list[bytes], then: Exception | None) -> None:
        self._chunks, self._then = list(chunks), then

    def read1(self, _n: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        if self._then:
            raise self._then
        return b""

    def close(self) -> None:
        pass


class _FakeProc:
    def __init__(self, stdout, stderr, returncode: int = 0) -> None:
        self.pid, self.returncode = 999999, returncode
        self.stdout, self.stderr = stdout, stderr
        self.stdin = _FailingStream([], None)
        self.stdin.write = lambda data: len(data)  # type: ignore[method-assign]

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


def test_stdout_read_failure_is_truncated(monkeypatch) -> None:
    """Losing bytes on the protocol channel must not read as success."""
    proc = _FakeProc(
        stdout=_FailingStream([b'{"verdict": "ALL'], OSError("input/output error")),
        stderr=_FailingStream([], None),
    )
    monkeypatch.setattr(runtime, "_kill_group", lambda pgid: None)
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **k: proc)

    result = invoke(["anything"], b"{}", timeout=5.0)
    assert result.outcome is Outcome.TRUNCATED
    assert result.exit_code == 0  # a clean exit did not make a partial read OK
    assert result.stdout == b'{"verdict": "ALL'


def test_stderr_read_failure_does_not_block(monkeypatch) -> None:
    """Diagnostics are not the protocol channel. A lost log line is not a
    reason to reject content."""
    proc = _FakeProc(
        stdout=_FailingStream([b'{"verdict": "ALLOW"}'], None),
        stderr=_FailingStream([b"warming up"], OSError("input/output error")),
    )
    monkeypatch.setattr(runtime, "_kill_group", lambda pgid: None)
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *a, **k: proc)

    result = invoke(["anything"], b"{}", timeout=5.0)
    assert result.outcome is Outcome.OK
    assert result.stdout == b'{"verdict": "ALLOW"}'


def test_invoke_never_raises() -> None:
    """E2 in miniature: this layer classifies failures, it does not propagate them."""
    for command in (["./nope"], script("import sys; sys.exit(9)"), script("raise SystemExit(1)")):
        assert isinstance(invoke(command, b"{}", timeout=2.0), Invocation)


def test_a_flood_of_diagnostics_does_not_fail_the_call() -> None:
    """stderr is not the protocol channel (E3). Capping it protects memory;
    rejecting the response would turn a logging hiccup into dropped data."""
    chatty = script('import sys; sys.stdin.read(); sys.stderr.write("x" * 200_000); print("{}")')
    result = invoke(chatty, b"{}", max_output=1 << 16)
    assert result.outcome is Outcome.OK
    assert result.stdout == b"{}\n"
    assert len(result.stderr) == 1 << 16  # capped, not collected whole


def test_a_flood_on_stdout_still_fails() -> None:
    flood = script(
        'import sys\nsys.stdin.read()\nwhile True: sys.stdout.buffer.write(b"x" * 65536)'
    )
    result = invoke(flood, b"{}", timeout=10.0, max_output=1 << 16)
    assert result.outcome is Outcome.OVERSIZE
