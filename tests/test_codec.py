"""Codec tests for #6: one object on stdout, and nothing else."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

from rsp.codec import Outcome, call, decode, encode

ECHO = [sys.executable, "plugins/rsp-echo/main.py"]


def script(body: str) -> list[str]:
    return [sys.executable, "-c", body]


def test_encode_keeps_content_as_utf8() -> None:
    """Escaped content would break span arithmetic: a plugin reports byte
    offsets into what it received (S1), and u-escapes are different bytes."""
    content = "密钥 secret"
    raw = encode({"hook": "on_chunk", "content": content})
    assert content.encode("utf-8") in raw
    assert b"\\u" not in raw


def test_reported_spans_index_the_bytes_we_sent() -> None:
    content = "密钥 secret"
    reply = call(ECHO, {"rsp_version": "0.1", "hook": "on_chunk", "content": content})
    assert reply.ok
    span = reply.payload["spans"][0]
    assert content.encode("utf-8")[span["start"] : span["end"]] == b"secret"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b'{"verdict":"ALLOW"}', Outcome.OK),
        (b'  {"verdict":"ALLOW"}  \n', Outcome.OK),
        (b"", Outcome.EMPTY),
        (b"   \n", Outcome.EMPTY),
        (b"not json at all", Outcome.MALFORMED),
        (b'{"verdict":"ALLOW"', Outcome.MALFORMED),
        (b'{"a":1}{"b":2}', Outcome.MALFORMED),
        (b'{"a":1}\ntrailing', Outcome.MALFORMED),
        (b"[1,2]", Outcome.MALFORMED),
        (b'"a string"', Outcome.MALFORMED),
        (b"\xff\xfe not utf-8", Outcome.MALFORMED),
    ],
)
def test_decode_accepts_exactly_one_object(raw: bytes, expected: Outcome) -> None:
    outcome, payload = decode(raw)
    assert outcome is expected
    assert (payload is not None) == (expected is Outcome.OK)


def test_diagnostics_on_stdout_are_rejected() -> None:
    """T2 from the host's side. A debug line before the response is not a
    parsing inconvenience — it means the plugin treats stdout as a log, and the
    host cannot tell a stray line from a response it should act on."""
    chatty = script(
        "import sys; sys.stdin.read(); print('loading rules...'); print('{\"verdict\":\"ALLOW\"}')"
    )
    reply = call(chatty, {"hook": "on_chunk", "content": "x"})
    assert reply.outcome is Outcome.MALFORMED
    assert reply.payload is None


def test_silent_plugin_is_empty_not_ok() -> None:
    reply = call(script("import sys; sys.stdin.read()"), {"hook": "on_chunk", "content": "x"})
    assert reply.outcome is Outcome.EMPTY


def test_output_from_a_failed_process_is_not_parsed() -> None:
    """A verdict printed on the way down is a fragment, however well-formed:
    the plugin did not finish deciding."""
    dying = script('import sys; sys.stdin.read(); print(\'{"verdict":"ALLOW"}\'); sys.exit(3)')
    reply = call(dying, {"hook": "on_chunk", "content": "x"})
    assert reply.outcome is Outcome.CRASHED
    assert reply.payload is None
    assert b"ALLOW" in reply.invocation.stdout  # kept for the operator, not acted on


def test_process_failures_reach_the_caller_unchanged() -> None:
    reply = call(script("import time; time.sleep(30)"), {"hook": "on_chunk"}, timeout=0.5)
    assert reply.outcome is Outcome.TIMEOUT
    assert reply.payload is None


def test_round_trip_matches_the_conformance_case() -> None:
    case = json.loads(pathlib.Path("conformance/cases/spans-are-utf8-bytes.json").read_text())
    reply = call(ECHO, case["request"])
    assert reply.ok
    assert reply.payload == case["expect"]["response"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_values_never_reach_the_wire(value: float) -> None:
    """NaN and Infinity are not JSON (RFC 8259); Python writes them anyway.
    A retriever score of NaN would otherwise go out as something a strict
    plugin rejects, making a working plugin look broken."""
    reply = call(ECHO, {"hook": "on_retrieve", "content": "x", "metadata": {"score": value}})
    assert reply.outcome is Outcome.UNENCODABLE
    assert reply.payload is None
    assert reply.invocation is None  # nothing was spawned


@pytest.mark.parametrize("raw", [b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'])
def test_non_finite_values_are_rejected_on_the_way_in(raw: bytes) -> None:
    """Accepting these would make this host take responses that a Go or Rust
    host rejects — the divergence surfaces later as "works here, fails there"."""
    outcome, payload = decode(raw)
    assert outcome is Outcome.MALFORMED
    assert payload is None


def test_finite_floats_still_work() -> None:
    reply = call(ECHO, {"hook": "on_retrieve", "content": "x", "metadata": {"score": 0.87}})
    assert reply.ok
