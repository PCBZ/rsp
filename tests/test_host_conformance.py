"""Host cases: a plugin's answer goes in, the host's behaviour is asserted.

The other direction from `test_conformance.py`, and the one that needs a
runner per host rather than per plugin — a host is a library, not a process,
so a kit cannot spawn it. What a kit ships is the cases and the plugin that
follows them; this file is what points them at `rsp`.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

import pytest

from rsp.runtime import OnError, Plugin, Runtime, Verdict

ROOT = pathlib.Path(__file__).parent.parent
CASES = sorted((ROOT / "conformance" / "host").glob("*.json"))
REPLAY = [sys.executable, str(ROOT / "plugins/rsp-replay/main.py")]


def _plugins(case: dict[str, Any], tmp_path: pathlib.Path) -> list[Plugin]:
    """One plugin per script. Composition clauses need more than one, and the
    order here is the configured order S6 breaks ties by."""
    declared = case.get("plugins") or [case["plugin"]]
    plugins = []
    for at, script in enumerate(declared):
        path = tmp_path / f"script-{at}.json"
        path.write_text(json.dumps(script), encoding="utf-8")
        plugins.append(
            Plugin(
                name=f"replay-{at}",
                command=[*REPLAY, str(path)],
                on_error=OnError(script.get("on_error", case.get("on_error", "block"))),
                timeout=case.get("timeout", 5.0),
            )
        )
    return plugins


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_host_case(
    path: pathlib.Path,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    record_property: Any,
) -> None:
    case = json.loads(path.read_text(encoding="utf-8"))
    record_property("clause", case["clause"])
    record_property("plugin", "rsp (host)")

    calls = tmp_path / "calls"
    monkeypatch.setenv("RSP_REPLAY_CALLS", str(calls))
    plugins = _plugins(case, tmp_path)

    request = case["request"]
    started = time.monotonic()
    result = Runtime(plugins).evaluate(request["hook"], request["content"])
    elapsed = time.monotonic() - started

    expected = case["expect"]
    assert result.verdict is Verdict(expected["verdict"]), result.reasons
    if expected["content"] == "unchanged":
        assert result.content == request["content"], "a refused response leaves content alone"
    else:
        assert result.content == expected["content"]

    if "timeout" in case:
        # Otherwise a host with its own longer bound passes a case about the
        # configured one: the verdict would be the same, five seconds later.
        assert elapsed < case["timeout"] * 4, f"took {elapsed:.1f}s for a {case['timeout']}s bound"
    if expected.get("hooks_called") is not None:
        seen = calls.read_text(encoding="utf-8").split() if calls.exists() else []
        assert [hook for hook in seen if hook != "handshake"] == expected["hooks_called"]
