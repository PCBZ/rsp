"""Host cases: a plugin's answer goes in, the host's behaviour is asserted.

The other direction from `test_conformance.py`, and the one that needs a
runner per host rather than per plugin — a host is a library, not a process,
so a kit cannot spawn it. What a kit can ship is the cases and the plugin that
follows them; this file is the twenty lines that point them at `rsp`.

Seventeen clauses were uncovered because a plugin's response cannot settle a
requirement on the host. These settle some of them.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

from rsp.runtime import OnError, Plugin, Runtime, Verdict

ROOT = pathlib.Path(__file__).parent.parent
CASES = sorted((ROOT / "conformance" / "host").glob("*.json"))
REPLAY = [sys.executable, str(ROOT / "plugins/rsp-replay/main.py")]


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_host_case(
    path: pathlib.Path, tmp_path: pathlib.Path, monkeypatch, record_property
) -> None:
    case = json.loads(path.read_text())
    record_property("clause", case["clause"])
    record_property("plugin", "rsp (host)")

    script = tmp_path / "script.json"
    script.write_text(json.dumps(case["plugin"]))
    monkeypatch.setenv("RSP_REPLAY", str(script))

    runtime = Runtime(
        [
            Plugin(
                name="replay",
                command=REPLAY,
                on_error=OnError(case.get("on_error", "block")),
                timeout=case.get("timeout", 5.0),
            )
        ]
    )
    request = case["request"]
    result = runtime.evaluate(request["hook"], request["content"])

    expected = case["expect"]
    assert result.verdict is Verdict(expected["verdict"]), result.reasons
    if expected["content"] == "unchanged":
        assert result.content == request["content"], "a refused response leaves content alone"
    else:
        assert result.content == expected["content"]
