"""The plugin guide quotes a plugin the conformance cases run against.

A snippet that exists only in prose drifts from the code it describes and
nobody notices, because prose does not fail. Every code block in the guide
names the file it came from, and this checks it is still there.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
GUIDE = ROOT / "WRITING-A-PLUGIN.md"

# ```ts
# // path/to/file.ts
# ...lines...
# ```
QUOTED = re.compile(r"```\w+\n(?://|#) (\S+)\n(.*?)```", re.DOTALL)
BLOCKS = QUOTED.findall(GUIDE.read_text(encoding="utf-8"))


def test_the_guide_quotes_something() -> None:
    """Otherwise the check below is vacuous, and a rewrite that dropped every
    quote would pass it."""
    assert len(BLOCKS) >= 4


@pytest.mark.parametrize(("source", "snippet"), BLOCKS, ids=[source for source, _ in BLOCKS])
def test_every_quote_is_still_in_the_file(source: str, snippet: str) -> None:
    quoted = [line for line in snippet.splitlines() if line.strip()]
    lines = (ROOT / source).read_text(encoding="utf-8").splitlines()

    for line in quoted:
        assert line in lines, f"{source} no longer contains: {line.strip()}"

    # In order and together, so a quote cannot be assembled from lines that
    # are scattered through the file and no longer mean what it shows.
    first = lines.index(quoted[0])
    assert lines[first : first + len(quoted)] == quoted, f"{source}: the quote is no longer one run"


def test_the_byte_offset_example_is_arithmetic_that_holds() -> None:
    """The page teaches S1 with two numbers, and a wrong one teaches the
    mistake it is warning about."""
    text = GUIDE.read_text(encoding="utf-8")
    example = re.search(r"content:\s+(\S+) (\S+)\n", text)
    assert example, "the byte-offset example is no longer in the form the code can check"
    prefix, key = example.groups()
    stated = re.search(r"starts at character (\d+), and at byte (\d+)", text)
    assert stated, "the example no longer states both numbers"

    content = f"{prefix} {key}"
    character, byte = (int(n) for n in stated.groups())

    assert content.index(key) == character, "the character index is wrong"
    assert content.encode("utf-8").index(key.encode("utf-8")) == byte, "the byte offset is wrong"
    assert character != byte, "an example where they agree teaches nothing"


def test_the_invented_transcripts_are_valid_protocol() -> None:
    """The `$` examples show a plugin that does not exist, so no quote can
    keep them honest — but a declaration missing a required field, or a span
    outside its own content, would teach something the spec refuses."""
    text = GUIDE.read_text(encoding="utf-8")
    exchanges = re.findall(r"\$ echo '([^']+)' \| my-plugin\n(\{[^\n]+)", text)
    assert len(exchanges) >= 2, "the transcripts are no longer in the form the code can check"

    for raw_request, raw_response in exchanges:
        request, response = json.loads(raw_request), json.loads(raw_response)
        assert request["rsp_version"] == "0.1"

        if request["hook"] == "handshake":
            for field in ("rsp_version", "name", "version", "hooks"):
                assert field in response, f"a declaration needs {field} (H2)"
            continue

        assert response["verdict"] in {"ALLOW", "FLAG", "REDACT", "BLOCK"}, "V1"
        if response["verdict"] == "REDACT":
            assert "replacement" in response, "V3"
            content = request["content"].encode("utf-8")
            for span in response["spans"]:
                assert 0 <= span["start"] < span["end"] <= len(content), f"S3: {span}"
