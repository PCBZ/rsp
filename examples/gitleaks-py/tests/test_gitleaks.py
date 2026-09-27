"""Line-and-column to byte offsets. No binary needed: a report is data.

The table is `examples/gitleaks-offsets.json`, shared with the other adapters,
because the numbers in it are facts about gitleaks rather than about any of
them. What stays here is what this language makes possible and they do not.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from gitleaks import to_spans

TABLE = json.loads(
    (pathlib.Path(__file__).parent.parent.parent / "gitleaks-offsets.json").read_text("utf-8")
)
KEY = "AKIALALEMEL33243OLIB"


@pytest.mark.parametrize("case", TABLE["tests"], ids=[c["comment"] for c in TABLE["tests"]])
def test_every_case_in_the_shared_table(case):
    why = "\n".join(TABLE["notes"][flag] for flag in case["flags"])
    produced = to_spans(case["findings"], case["content"].encode("utf-8"))

    assert produced == case["spans"], f"{case['tcId']}: {case['comment']}\n{why}"


def test_the_table_did_not_lose_cases():
    """A path that resolved to nothing would leave the parametrize empty."""
    assert len(TABLE["tests"]) >= 13


def test_offsets_index_bytes_and_not_code_points():
    """A str sliced with byte offsets is the failure only this language has.

    Go is correct by construction, Rust panics and TypeScript truncates. Here
    the wrong text comes back with nothing raised, so a key reported as
    redacted stays in the chunk.
    """
    content = f"密钥 {KEY}"
    finding = {
        "RuleID": "aws-access-token",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 8,
        "EndColumn": 27,
        "Match": KEY,
    }

    (span,) = to_spans([finding], content.encode("utf-8"))

    assert content.encode("utf-8")[span["start"] : span["end"]].decode("utf-8") == KEY
    assert content[span["start"] : span["end"]] != KEY, "the str slice is the trap being guarded"


def test_drops_a_span_inside_a_character():
    """Only the boundary check can refuse offsets whose Match is the bytes they cover."""
    inside = {
        "RuleID": "private-key",
        "StartLine": 1,
        "EndLine": 1,
        "StartColumn": 2,
        "EndColumn": 3,
        "Match": "\udcaf\udc86",
    }

    assert to_spans([inside], f"密钥 {KEY}".encode()) == []
