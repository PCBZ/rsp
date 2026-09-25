"""The offset table the three adapters share.

A number in it is a transcription of what gitleaks emitted, and nothing else
checks transcriptions: each adapter asserts its own arithmetic agrees with the
table, so a table that is wrong is a suite that agrees about the wrong answer.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from rsp.spans import Span, valid_span

ROOT = pathlib.Path(__file__).parent.parent
TABLE = json.loads((ROOT / "examples" / "gitleaks-offsets.json").read_text(encoding="utf-8"))
CASES = TABLE["tests"]

# Where each adapter reads it. A suite that quietly stopped would still pass
# its own tests, which is the failure this file exists to prevent.
READERS = (
    "examples/gitleaks-ts/test/gitleaks.test.ts",
    "examples/gitleaks-go/gitleaks_test.go",
    "examples/gitleaks-rs/tests/gitleaks.rs",
)


@pytest.mark.parametrize("case", CASES, ids=[c["comment"] for c in CASES])
def test_every_span_is_one_the_host_would_apply(case: dict) -> None:
    """The adapters check this too, which is the point: if the table asked for
    a span S3 refuses, three suites would agree the adapter should produce it.
    """
    content = case["content"].encode("utf-8")
    for span in case["spans"]:
        assert valid_span(Span(span["start"], span["end"]), content), span


@pytest.mark.parametrize("case", CASES, ids=[c["comment"] for c in CASES])
def test_every_span_slices_to_a_match_of_its_case(case: dict) -> None:
    """An offset is useful exactly when it indexes the host's bytes."""
    content = case["content"].encode("utf-8")
    matches = [finding.get("Match") for finding in case["findings"]]
    for span in case["spans"]:
        assert content[span["start"] : span["end"]].decode("utf-8") in matches


def test_every_flag_has_a_note_and_every_note_is_used() -> None:
    """The notes carry the reasons the three suites used to carry in comments.
    One nobody cites is a reason that left with the case it explained."""
    flagged = {flag for case in CASES for flag in case["flags"]}
    assert flagged - set(TABLE["notes"]) == set(), "a case cites a note that is not there"
    assert set(TABLE["notes"]) - flagged == set(), "a note explains nothing"


def test_case_ids_are_unique() -> None:
    ids = [case["tcId"] for case in CASES]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("reader", READERS)
def test_each_adapter_still_reads_the_table(reader: str) -> None:
    """Up to the closing quote, because a substring is satisfied by a path
    with anything appended — which is how this passed when the Rust reader was
    pointed at `gitleaks-offsets.json.bak`. A wrong path that still resolves
    nowhere is caught by that adapter's own suite, which refuses to run on an
    empty table."""
    text = (ROOT / reader).read_text(encoding="utf-8")
    assert re.search(r"gitleaks-offsets\.json[\"']", text), "the path stopped pointing at the table"
