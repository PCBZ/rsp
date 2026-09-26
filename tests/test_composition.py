"""Verdict composition: dispatch, compose, and decide (D9, E1, H3, S5)."""

from __future__ import annotations

import sys

import pytest

from rsp.runtime import ConfigError, OnError, Plugin, Runtime, Verdict

ECHO = [sys.executable, "plugins/rsp-echo/main.py"]


def fake(
    name: str,
    response: dict,
    *,
    hooks: tuple[str, ...] = ("on_chunk", "on_retrieve"),
    on_error: OnError = OnError.BLOCK,
) -> Plugin:
    """A plugin that answers the handshake properly and then says one thing."""
    declaration = {
        "rsp_version": "0.1",
        "name": name,
        "version": "1.0",
        "hooks": list(hooks),
        "deterministic": True,
    }
    body = (
        "import json, sys\n"
        "req = json.load(sys.stdin)\n"
        f"print(json.dumps({declaration!r} if req.get('hook') == 'handshake' else {response!r}))\n"
    )
    return Plugin(name=name, command=[sys.executable, "-c", body], on_error=on_error)


def runtime(*plugins: Plugin) -> Runtime:
    return Runtime(plugins)


def _handshake_then(statement: str) -> str:
    declaration = {"rsp_version": "0.1", "name": "x", "version": "1.0", "hooks": ["on_chunk"]}
    return (
        "import json, sys\n"
        "req = json.load(sys.stdin)\n"
        f"if req.get('hook') == 'handshake': print(json.dumps({declaration!r}))\n"
        f"else: {statement}\n"
    )


def test_strictest_verdict_wins() -> None:
    result = runtime(
        fake("quiet", {"verdict": "ALLOW"}),
        fake("noisy", {"verdict": "FLAG", "reason": "looks odd"}),
    ).evaluate("on_chunk", "text")
    assert result.verdict is Verdict.FLAG
    assert result.provenance["rsp.plugins"] == ["quiet", "noisy"]


def test_block_short_circuits_the_rest() -> None:
    """A plugin after a BLOCK is not called: its verdict would be about content
    already rejected, and calling it invites it to expect calls it won't get."""
    never_runs = fake("late", {"verdict": "ALLOW"})
    result = runtime(fake("early", {"verdict": "BLOCK", "reason": "aws key"}), never_runs).evaluate(
        "on_chunk", "text"
    )
    assert result.blocked
    assert result.provenance["rsp.plugins"] == ["early"]  # "late" never spoke


def test_spans_from_several_plugins_apply_once_to_the_original() -> None:
    """S5: both plugins address the same bytes, and a replacement of a
    different length must not shift the other's range."""
    result = runtime(
        fake(
            "a",
            {
                "verdict": "REDACT",
                "spans": [{"start": 0, "end": 3, "type": "x"}],
                "replacement": "[LONG REPLACEMENT]",
            },
        ),
        fake(
            "b",
            {
                "verdict": "REDACT",
                "spans": [{"start": 7, "end": 10, "type": "y"}],
                "replacement": "[B]",
            },
        ),
    ).evaluate("on_chunk", "0123456789")
    assert result.content == "[LONG REPLACEMENT]3456[B]"
    assert result.provenance["rsp.types"] == ["x", "y"]


def test_overlapping_spans_from_different_plugins_coalesce() -> None:
    result = runtime(
        fake(
            "low",
            {
                "verdict": "REDACT",
                "severity": "low",
                "spans": [{"start": 0, "end": 4}],
                "replacement": "[A]",
            },
        ),
        fake(
            "high",
            {
                "verdict": "REDACT",
                "severity": "critical",
                "spans": [{"start": 2, "end": 6}],
                "replacement": "[B]",
            },
        ),
    ).evaluate("on_chunk", "0123456789")
    assert result.content == "[B]6789"  # S6: highest severity keeps its replacement
    assert result.provenance["rsp.severity"] == "critical"


def test_a_plugin_is_not_called_on_a_hook_it_did_not_declare() -> None:
    """H3. The plugin here would BLOCK if reached."""
    ingest_only = fake("ingest", {"verdict": "BLOCK"}, hooks=("on_chunk",))
    assert runtime(ingest_only).evaluate("on_retrieve", "text").verdict is Verdict.ALLOW


@pytest.mark.parametrize(
    "misbehaviour",
    ["__import__('os')._exit(1)", "print('not json')", "pass"],
    ids=["crash", "garbage", "silence"],
)
def test_a_failing_plugin_blocks_by_default(misbehaviour: str) -> None:
    """E1. Each of these answers the handshake, then fails on content."""
    plugin = Plugin(name="flaky", command=[sys.executable, "-c", _handshake_then(misbehaviour)])
    assert runtime(plugin).evaluate("on_chunk", "text").blocked


def test_on_error_allow_lets_the_chunk_through() -> None:
    crashing = Plugin(
        name="crashing",
        command=[sys.executable, "-c", _handshake_then("__import__('os')._exit(1)")],
        on_error=OnError.ALLOW,
    )
    result = runtime(crashing).evaluate("on_chunk", "text")
    assert result.verdict is Verdict.ALLOW
    assert "on_error=allow" in result.reasons[0]


def test_an_unrecognized_verdict_is_not_a_verdict() -> None:
    """Guessing at 'ALLOOW' is how a typo becomes a silent allow (V1)."""
    result = runtime(fake("typo", {"verdict": "ALLOOW"})).evaluate("on_chunk", "text")
    assert result.blocked
    assert "ALLOOW" in result.reasons[0]


def test_an_invalid_span_blocks_the_whole_chunk() -> None:
    """S3 and E1. Applying the plugin's other spans would let it report nothing
    by reporting garbage, and the host cannot tell which claims were sound."""
    result = runtime(
        fake(
            "liar",
            {
                "verdict": "REDACT",
                "spans": [{"start": 0, "end": 3}, {"start": 99, "end": 200}],
                "replacement": "[X]",
            },
        )
    ).evaluate("on_chunk", "0123456789")
    assert result.blocked
    assert result.content == "0123456789"  # unchanged: nothing was applied


def test_a_plugin_that_cannot_introduce_itself_stops_construction() -> None:
    """Loud beats silent: the alternative is an index nobody is guarding."""
    with pytest.raises(ConfigError, match="handshake failed"):
        runtime(Plugin(name="absent", command=["./not-a-plugin"]))


def test_reasons_stay_out_of_provenance() -> None:
    """Q8: provenance is written onto a stored node, and a plugin's free text
    can quote the bytes it matched."""
    result = runtime(
        fake("chatty", {"verdict": "FLAG", "reason": "found AKIA1234 in line 2"})
    ).evaluate("on_chunk", "text")
    assert "AKIA1234" in result.reasons[0]
    assert not any("AKIA1234" in str(v) for v in result.provenance.values())


def test_the_reference_plugin_still_composes() -> None:
    result = runtime(Plugin(name="echo", command=ECHO)).evaluate("on_chunk", "密钥 secret")
    assert result.verdict is Verdict.REDACT
    assert result.content == "密钥 [REDACTED:echo-test]"


@pytest.mark.parametrize(
    ("label", "response"),
    [
        ("verdict is a list", {"verdict": ["BLOCK"]}),
        (
            "offsets are strings",
            {"verdict": "REDACT", "spans": [{"start": "0", "end": "3"}], "replacement": "[X]"},
        ),
        (
            "offsets are booleans",
            {"verdict": "REDACT", "spans": [{"start": True, "end": True}], "replacement": "[X]"},
        ),
        ("spans is not a list", {"verdict": "REDACT", "spans": {"start": 0}, "replacement": "[X]"}),
        ("a span is not an object", {"verdict": "REDACT", "spans": ["0-3"], "replacement": "[X]"}),
        (
            "severity is a number",
            {
                "verdict": "REDACT",
                "spans": [{"start": 0, "end": 3}],
                "replacement": "[X]",
                "severity": 9,
            },
        ),
        (
            "type is a number",
            {
                "verdict": "REDACT",
                "spans": [{"start": 0, "end": 3, "type": 7}],
                "replacement": "[X]",
            },
        ),
        ("replacement is missing", {"verdict": "REDACT", "spans": [{"start": 0, "end": 3}]}),
        ("REDACT with no spans", {"verdict": "REDACT", "replacement": "[X]"}),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_a_hostile_payload_cannot_crash_the_host(label: str, response: dict) -> None:
    """Every one of these raised before: a plugin chose when the host fell
    over, which is the attack D2 isolates it for."""
    result = runtime(fake("hostile", response)).evaluate("on_chunk", "0123456789")
    assert result.blocked, label
    assert result.content == "0123456789"


def test_on_error_covers_semantic_failures_too() -> None:
    """A plugin that returns an unusable response has failed as surely as one
    that crashed, and on_error=allow was set with both in mind."""
    lenient = fake("typo", {"verdict": "ALLOOW"}, on_error=OnError.ALLOW)
    result = runtime(lenient).evaluate("on_chunk", "text")
    assert result.verdict is Verdict.ALLOW
    assert "on_error=allow" in result.reasons[0]


def test_duplicate_plugin_names_are_refused() -> None:
    """Names key the declarations, so a duplicate hands one plugin another's
    capabilities — and a guard that never runs looks like one that found
    nothing."""
    with pytest.raises(ConfigError, match="configured twice"):
        runtime(fake("same", {"verdict": "ALLOW"}), fake("same", {"verdict": "BLOCK"}))


def test_reasons_accumulated_before_a_block_survive_it() -> None:
    result = runtime(
        fake("first", {"verdict": "FLAG", "reason": "looks odd"}),
        fake("second", {"verdict": "BLOCK", "reason": "aws key"}),
    ).evaluate("on_chunk", "text")
    assert result.reasons == ["first: looks odd", "second: aws key", "second: BLOCK"]


def test_an_unencodable_replacement_is_an_unusable_span() -> None:
    """isinstance(x, str) checks the type; it does not check that the value can
    reach a plugin. A lone surrogate passes the first and fails the second."""
    result = runtime(
        fake(
            "hostile",
            {"verdict": "REDACT", "spans": [{"start": 0, "end": 3}], "replacement": "\ud800"},
        )
    ).evaluate("on_chunk", "0123456789")
    assert result.blocked
    assert result.content == "0123456789"


def test_content_the_host_cannot_encode_is_blocked_before_any_plugin_runs() -> None:
    """A host can read a lone surrogate out of a mis-encoded file. No plugin
    can be asked about content that cannot go on the wire."""
    would_allow = fake("never-called", {"verdict": "ALLOW"})
    result = runtime(would_allow).evaluate("on_chunk", "\ud800")
    assert result.blocked
    assert "not encodable" in result.reasons[0]
    assert "rsp.plugins" not in result.provenance  # nothing was consulted


def test_evaluate_does_not_raise_on_metadata_that_contains_itself() -> None:
    """E2 has no exceptions, including for a host that hands in something no
    encoder can walk. Before the cycle check this was a RecursionError out of
    evaluate, which is the one thing the clause forbids."""
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    runtime = Runtime([Plugin(name="echo", command=ECHO)])

    result = runtime.evaluate("on_chunk", "text", metadata=cycle)

    assert result.verdict is Verdict.BLOCK
    assert result.content == "text"


def test_a_voided_response_contributes_nothing_to_provenance() -> None:
    """A REDACT whose spans the host refuses is void in full (S3, V3).

    Provenance is stored on the node; reasons are not. A severity surviving
    the response it arrived in is a claim no plugin still standing has made,
    written where a host routes on it.
    """
    voided = fake(
        "unplaceable",
        {
            "verdict": "REDACT",
            "spans": [{"start": 0, "end": 9999}],
            "replacement": "[X]",
            "severity": "critical",
            "reason": "found something it could not point at",
        },
        on_error=OnError.ALLOW,
    )

    result = runtime(voided).evaluate("on_chunk", "hello")

    assert result.verdict is Verdict.ALLOW
    assert result.provenance == {"rsp.verdict": "ALLOW"}
    assert not any("could not point at" in reason for reason in result.reasons)
    assert any("unusable spans" in reason for reason in result.reasons)
