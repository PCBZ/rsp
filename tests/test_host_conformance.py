"""Host cases: a plugin's answer goes in, the host's behaviour is asserted.

A host is a library, not a process, so the kit ships cases and a replay plugin
and each host brings a runner; this is `rsp`'s.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time
from typing import Any

import pytest

from rsp.process import DEFAULT_MAX_OUTPUT
from rsp.runtime import OnError, Plugin, Runtime, Verdict

ROOT = pathlib.Path(__file__).parent.parent
CASES = sorted((ROOT / "conformance" / "host").glob("*.json"))
REPLAY = [sys.executable, str(ROOT / "plugins/rsp-replay/main.py")]
# What rsp-replay understands. It crashes on anything else, so a typo would pass
# every crash case; checked here because the side that starts nothing can report.
BEHAVIOURS = frozenset({"crash", "hang", "garbage", "chatty", "silent", "noisy", "raw", "flood"})
NEEDS_REPLY = frozenset({"noisy"})


def _checked(script: dict[str, Any], where: str) -> dict[str, Any]:
    behaviour = script.get("behaviour")
    if behaviour is not None and behaviour not in BEHAVIOURS:
        pytest.fail(f"{where}: no such behaviour {behaviour!r}")
    if (behaviour is None or behaviour in NEEDS_REPLY) and "reply" not in script:
        pytest.fail(f"{where}: needs a reply")
    if unknown := sorted(set(script) - {"behaviour", "reply", "raw", "declaration", "on_error"}):
        pytest.fail(f"{where}: unknown key(s) {', '.join(unknown)}")
    return script


def _plugins(case: dict[str, Any], tmp_path: pathlib.Path) -> list[Plugin]:
    """One plugin per script, in the configured order S6 breaks ties by."""
    declared = case.get("plugins") or [case["plugin"]]
    declared = [_checked(script, f"plugins[{at}]") for at, script in enumerate(declared)]
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
                max_output=case.get("max_output", DEFAULT_MAX_OUTPUT),
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
    result = Runtime(plugins).evaluate(
        request["hook"], request["content"], metadata=request.get("metadata")
    )
    elapsed = time.monotonic() - started

    expected = case["expect"]
    assert result.verdict is Verdict(expected["verdict"]), result.reasons
    if expected["content"] == "unchanged":
        assert result.content == request["content"], "a refused response leaves content alone"
    else:
        assert result.content == expected["content"]

    if "timeout" in case:
        # Else a host with its own longer bound passes: same verdict, five seconds later.
        assert elapsed < case["timeout"] * 4, f"took {elapsed:.1f}s for a {case['timeout']}s bound"
    if wanted := expected.get("reason_contains"):
        # The operator's half of V4: a reason the plugin gave has to arrive.
        assert any(wanted in reason for reason in result.reasons), result.reasons
    shown = [
        json.loads(line)
        for line in (calls.read_text(encoding="utf-8").splitlines() if calls.exists() else [])
    ]
    asked = [entry for entry in shown if entry["hook"] != "handshake"]
    if expected.get("hooks_called") is not None:
        assert [entry["hook"] for entry in asked] == expected["hooks_called"]
    if expected.get("every_plugin_saw_the_original"):
        # S5: a scripted plugin answers regardless of input, so it records what it was shown.
        assert [entry["content"] for entry in asked] == [request["content"]] * len(asked)
