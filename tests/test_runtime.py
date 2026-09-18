"""Lifecycle tests for #4. Plugins here are inline scripts — rsp-chaos (#9)
replaces them with a real misbehaving plugin later."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from rsp.runtime import DEFAULT_MAX_OUTPUT, Invocation, Outcome, invoke

ECHO = [sys.executable, "plugins/rsp-echo/main.py"]


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


def test_hang_times_out_promptly() -> None:
    result = invoke(script("import time; time.sleep(30)"), b"{}", timeout=0.5)
    assert result.outcome is Outcome.TIMEOUT
    assert result.duration < 5.0  # killed, not waited out


def test_flood_is_capped() -> None:
    flood = script("import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)")
    result = invoke(flood, b"{}", timeout=10.0, max_output=1 << 16)
    assert result.outcome is Outcome.OVERSIZE
    assert len(result.stdout) < DEFAULT_MAX_OUTPUT  # bounded, not swallowed whole


def test_plugin_that_never_reads_stdin_does_not_deadlock() -> None:
    result = invoke(script("print('{}')"), b"x" * (1 << 20), timeout=5.0)
    assert result.outcome is Outcome.OK  # writer thread absorbed the broken pipe


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


def test_invoke_never_raises() -> None:
    """E2 in miniature: this layer classifies failures, it does not propagate them."""
    for command in (["./nope"], script("import sys; sys.exit(9)"), script("raise SystemExit(1)")):
        assert isinstance(invoke(command, b"{}", timeout=2.0), Invocation)
