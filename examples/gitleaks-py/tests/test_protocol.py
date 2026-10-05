"""Which report becomes which verdict, through a stand-in binary.

A stand-in rather than gitleaks so the interesting case can be provoked: a
finding whose position cannot be confirmed.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from protocol import REPLACEMENT, respond

FAKE = pathlib.Path(__file__).parents[2] / "testdata" / "fake-gitleaks.sh"
KEY = "AKIALALEMEL33243OLIB"


@pytest.fixture
def fake(monkeypatch):
    """A gitleaks that writes what the test chose and exits how it chose."""

    def staged(report: str, exit_code: str) -> None:
        monkeypatch.setenv("RSP_GITLEAKS", str(FAKE))
        monkeypatch.setenv("FAKE_GITLEAKS_REPORT", report)
        monkeypatch.setenv("FAKE_GITLEAKS_EXIT", exit_code)

    return staged


def chunk(content: str) -> dict:
    return {"rsp_version": "0.1", "hook": "on_chunk", "content": content}


def report(column: int) -> str:
    return json.dumps(
        [
            {
                "RuleID": "aws-access-token",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": column,
                "EndColumn": column + 19,
                "Match": KEY,
            }
        ]
    )


def test_allows_a_chunk_nothing_was_found_in(fake):
    fake("", "0")

    assert respond(chunk("nothing here")) == {"verdict": "ALLOW"}


def test_redacts_what_it_can_place(fake):
    fake(report(13), "2")

    got = respond(chunk(f"deploy with {KEY} today"))

    assert got["verdict"] == "REDACT"
    assert got["spans"] == [{"start": 12, "end": 32, "type": "aws-access-token"}]
    assert got["replacement"] == REPLACEMENT


def test_blocks_rather_than_redacting_only_what_it_can_place(fake):
    """Reporting the good span publishes the other secret, and ALLOW both."""
    both = json.dumps(json.loads(report(13)) + json.loads(report(99)))
    fake(both, "2")

    got = respond(chunk(f"deploy with {KEY} today"))

    assert got["verdict"] == "BLOCK"
    assert got["reason"]


def test_blocks_on_a_finding_with_no_position(fake):
    fake(json.dumps([{"RuleID": "aws-access-token", "Match": KEY}]), "2")

    assert respond(chunk(KEY))["verdict"] == "BLOCK"


def test_refuses_to_answer_when_the_binary_fails(fake):
    """Nothing on stdout, exactly like a clean chunk (E1, D3)."""
    fake("", "1")

    with pytest.raises(RuntimeError):
        respond(chunk(KEY))


def test_refuses_to_answer_on_a_report_that_is_not_a_report(fake):
    fake("not json", "2")

    with pytest.raises(json.JSONDecodeError):
        respond(chunk(KEY))


def test_declares_the_wrapped_tools_version_in_its_own(fake):
    """D4: the adapter's version alone would outlive the ruleset it judged with."""
    fake("8.30.1", "0")

    got = respond({"rsp_version": "0.1", "hook": "handshake"})

    assert got["version"] == "0.1.0+8.30.1"
    assert got["name"] == "rsp-gitleaks-py"


def test_refuses_a_missing_report_when_gitleaks_says_it_found_something(fake):
    """Exit 2 is gitleaks saying it found something.

    Nothing written is then a report that went missing, and no findings is the
    one reading of it that publishes the chunk (E1, D3).
    """
    fake("", "2")

    with pytest.raises(RuntimeError):
        respond(chunk(KEY))


def test_refuses_a_report_that_is_not_a_list(fake):
    fake('{"RuleID": "aws-access-token"}', "2")

    with pytest.raises(TypeError):
        respond(chunk(KEY))


def test_an_empty_report_with_a_clean_exit_is_still_a_clean_chunk(fake):
    """On a chunk that does hold a key, or this is the first test again.

    Nothing written means nothing found only when the status says the run was
    clean, which is what the two tests above turn on.
    """
    fake("", "0")

    assert respond(chunk(KEY)) == {"verdict": "ALLOW"}
