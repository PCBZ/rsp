"""Codec tests: one object on stdout, and nothing else (T2)."""

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
    """A plugin's offsets index the bytes it received (S1), and u-escapes are other bytes."""
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
    """T2 from the host's side: it cannot tell a stray line from a response."""
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
    """A verdict printed on the way down is from a plugin that did not finish deciding."""
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
    case = json.loads(
        pathlib.Path("conformance/cases/spans-are-utf8-bytes.json").read_text(encoding="utf-8")
    )
    reply = call(ECHO, case["request"])
    assert reply.ok
    assert reply.payload == case["expect"]["response"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_values_never_reach_the_wire(value: float) -> None:
    """Python writes NaN and Infinity, which are not JSON (RFC 8259); a strict plugin refuses."""
    reply = call(ECHO, {"hook": "on_retrieve", "content": "x", "metadata": {"score": value}})
    assert reply.outcome is Outcome.UNENCODABLE
    assert reply.payload is None
    assert reply.invocation is None  # nothing was spawned


@pytest.mark.parametrize("raw", [b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'])
def test_non_finite_values_are_rejected_on_the_way_in(raw: bytes) -> None:
    """Accepting these would take responses that a Go or Rust host rejects."""
    outcome, payload = decode(raw)
    assert outcome is Outcome.MALFORMED
    assert payload is None


def test_finite_floats_still_work() -> None:
    reply = call(ECHO, {"hook": "on_retrieve", "content": "x", "metadata": {"score": 0.87}})
    assert reply.ok


def test_a_string_that_cannot_be_utf8_is_unencodable() -> None:
    """Inherited, not written: call() catches this because UnicodeEncodeError is a ValueError."""
    reply = call([sys.executable, "-c", "pass"], {"hook": "on_chunk", "content": "\ud800"})
    assert reply.outcome is Outcome.UNENCODABLE
    assert reply.invocation is None  # nothing was spawned


def test_a_key_that_repeats_once_written_is_refused() -> None:
    """json.dumps writes an integer key as a string: one key twice on the wire (T4).

    Not a conformance case: JSON has no integer keys, so a case file cannot hold it.
    """
    with pytest.raises(ValueError, match="repeated"):
        encode({"hook": "on_chunk", "metadata": {1: "a", "1": "b"}})


def test_an_integer_past_the_interoperable_range_is_not_sent() -> None:
    """T4 binds both directions, however deeply a host nested its metadata."""
    with pytest.raises(ValueError, match="interoperable"):
        encode({"hook": "on_chunk", "metadata": {"a": [{"n": 2**53}]}})


def test_ordinary_requests_still_encode() -> None:
    assert encode({"hook": "on_chunk", "content": "密钥", "metadata": {"n": 2**53 - 1}})


def test_a_request_that_contains_itself_is_refused() -> None:
    """A ValueError, which evaluate turns into a verdict; a RecursionError escapes it (E2)."""
    cycle: dict[str, object] = {}
    cycle["self"] = cycle

    with pytest.raises(ValueError, match="contain itself"):
        encode({"hook": "on_chunk", "metadata": cycle})


def test_the_same_object_twice_is_not_a_cycle() -> None:
    shared = {"x": 1}

    assert encode({"hook": "on_chunk", "metadata": {"a": shared, "b": shared}})


def test_output_that_is_only_non_json_whitespace_is_malformed() -> None:
    """EMPTY means the plugin said nothing, and a space JSON does not allow is something."""
    outcome, payload = decode("\u00a0".encode())

    assert outcome is Outcome.MALFORMED
    assert payload is None
