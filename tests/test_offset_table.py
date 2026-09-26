"""The offset table the three adapters share; nothing else checks its transcriptions."""

from __future__ import annotations

import json
import re

import jsonschema
import pytest

from plugins import ROOT
from rsp.spans import Span, valid_span

TABLE_PATH = ROOT / "examples" / "gitleaks-offsets.json"
TABLE = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
CASES = TABLE["tests"]

# A suite that quietly stopped reading the table would still pass its own tests.
READERS = (
    "examples/gitleaks-ts/test/gitleaks.test.ts",
    "examples/gitleaks-go/gitleaks_test.go",
    "examples/gitleaks-rs/tests/gitleaks.rs",
)


@pytest.mark.parametrize("case", CASES, ids=[c["comment"] for c in CASES])
def test_every_span_is_one_the_host_would_apply(case: dict) -> None:
    """Otherwise three suites would agree an adapter should produce a span S3 refuses."""
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
    """A note nobody cites is a reason that left with the case it explained."""
    flagged = {flag for case in CASES for flag in case["flags"]}
    assert flagged - set(TABLE["notes"]) == set(), "a case cites a note that is not there"
    assert set(TABLE["notes"]) - flagged == set(), "a note explains nothing"


def test_case_ids_are_unique() -> None:
    ids = [case["tcId"] for case in CASES]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("reader", READERS)
def test_each_adapter_still_reads_the_table(reader: str) -> None:
    """Up to the closing quote, so `gitleaks-offsets.json.bak` does not match.

    A path that resolves nowhere fails that adapter's own suite, which refuses an empty table.
    """
    text = (ROOT / reader).read_text(encoding="utf-8")
    assert re.search(r"gitleaks-offsets\.json[\"']", text), "the path stopped pointing at the table"


def test_the_table_matches_the_schema_it_declares() -> None:
    """A named schema nobody runs drifts from the file it describes.

    Structure only: range, boundary and Match cannot be said in JSON Schema.
    """
    schema_path = TABLE_PATH.parent / TABLE["schema"]
    assert schema_path.is_file(), f"the table names {TABLE['schema']}, which is not there"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(TABLE)
