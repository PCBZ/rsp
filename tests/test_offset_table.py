"""The offset table every adapter shares; nothing else checks its transcriptions."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess

import jsonschema
import pytest

from plugins import MANIFEST, ROOT
from rsp.spans import Span, valid_span

TABLE_PATH = ROOT / "examples" / "gitleaks-offsets.json"
TABLE = json.loads(TABLE_PATH.read_text(encoding="utf-8"))
CASES = TABLE["tests"]

# A suite that quietly stopped reading the table would still pass its own tests.
ADAPTERS = tuple(path.parent for path in sorted(ROOT.glob(f"examples/*/{MANIFEST}")))
# Quoted, so a doc comment naming the table is not a reader, nor is
# `gitleaks-offsets.json.bak`.
QUOTED = re.compile(r"gitleaks-offsets\.json[\"']")


@pytest.mark.parametrize("case", CASES, ids=[c["comment"] for c in CASES])
def test_every_span_is_one_the_host_would_apply(case: dict) -> None:
    """Otherwise every suite would agree an adapter should produce a span S3 refuses."""
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


def _tracked(adapter: pathlib.Path) -> list[pathlib.Path]:
    """What the repo holds for this adapter, so build output is not searched."""
    names = subprocess.run(
        ["git", "ls-files", "-z", str(adapter.relative_to(ROOT))],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    return [ROOT / name.decode() for name in names if name]


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda path: path.name)
def test_each_adapter_still_reads_the_table(adapter: pathlib.Path) -> None:
    """Derived rather than listed: an eighth adapter is covered by shipping its manifest.

    A path that resolves nowhere fails that adapter's own suite, which refuses an empty table.
    """
    assert any(
        QUOTED.search(path.read_text(encoding="utf-8", errors="replace"))
        for path in _tracked(adapter)
        if path.is_file()
    ), f"{adapter.name} stopped pointing at the table"


def test_the_table_matches_the_schema_it_declares() -> None:
    """A named schema nobody runs drifts from the file it describes.

    Structure only: range, boundary and Match cannot be said in JSON Schema.
    """
    schema_path = TABLE_PATH.parent / TABLE["schema"]
    assert schema_path.is_file(), f"the table names {TABLE['schema']}, which is not there"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(TABLE)
