"""Each quoted block in the plugin guide must still be in the file it names: prose cannot fail."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from plugins import ECHO, ROOT
from rsp.spans import Span, valid_span

GUIDE = ROOT / "WRITING-A-PLUGIN.md"

# A fenced block whose first line is a comment naming its source file.
QUOTED = re.compile(r"```\w+\n(?://|#) (\S+)\n(.*?)```", re.DOTALL)
BLOCKS = QUOTED.findall(GUIDE.read_text(encoding="utf-8"))
COMMAND = re.compile(r"\$ echo '([^']+)' \| my-plugin")
# Any line after the command, so a lost reply fails the test rather than going unmatched.
EXCHANGE = re.compile(COMMAND.pattern + r"\n([^\n]*)")


def test_the_guide_quotes_something() -> None:
    """Otherwise the check below is vacuous."""
    assert len(BLOCKS) >= 4


@pytest.mark.parametrize(("source", "snippet"), BLOCKS, ids=[source for source, _ in BLOCKS])
def test_every_quote_is_still_in_the_file(source: str, snippet: str) -> None:
    quoted = [line for line in snippet.splitlines() if line.strip()]
    lines = (ROOT / source).read_text(encoding="utf-8").splitlines()

    for line in quoted:
        assert line in lines, f"{source} no longer contains: {line.strip()}"

    # In order and together: scattered lines no longer mean what the quote shows.
    first = lines.index(quoted[0])
    assert lines[first : first + len(quoted)] == quoted, f"{source}: the quote is no longer one run"


def test_the_byte_offset_example_is_arithmetic_that_holds() -> None:
    """A wrong number would teach the mistake S1 warns about."""
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
    """The `$` examples show a plugin that does not exist, so no quote keeps them honest."""
    text = GUIDE.read_text(encoding="utf-8")
    exchanges = EXCHANGE.findall(text)
    # Counted apart: a malformed exchange would otherwise just not match.
    assert len(exchanges) == len(COMMAND.findall(text)), "a transcript has no response"
    assert len(exchanges) >= 2, "the transcripts are no longer in the form the code can check"

    for raw_request, raw_response in exchanges:
        request, response = json.loads(raw_request), json.loads(raw_response)
        assert isinstance(response, dict), f"a response is not an object: {raw_response}"
        assert request["rsp_version"] == "0.1"

        if request["hook"] == "handshake":
            for field in ("rsp_version", "name", "version", "hooks"):
                assert field in response, f"a declaration needs {field} (H2)"
            continue

        assert response["verdict"] in {"ALLOW", "FLAG", "REDACT", "BLOCK"}, "V1"
        if response["verdict"] != "REDACT":
            continue

        assert "replacement" in response, "V3"
        content = request["content"].encode("utf-8")
        for span in response["spans"]:
            # The host's own predicate rather than a second copy of S3.
            assert valid_span(Span(span["start"], span["end"]), content), f"S3: {span}"
            assert span["start"] < span["end"], "an empty span redacts nothing (S3)"


README = ROOT / "README.md"
# The one block under "Use it": prose a reader is invited to copy, which has
# to run rather than merely still be quotable.
USE_IT = re.search(
    r"## Use it\n.*?```python\n(.*?)```", README.read_text(encoding="utf-8"), re.DOTALL
)


def test_the_readme_shows_a_host_how_to_use_it() -> None:
    """Otherwise the test below passes by finding nothing."""
    assert USE_IT, "README no longer carries a Python block under `## Use it`"


def test_the_readme_snippet_runs_and_guards(tmp_path: pathlib.Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Run as written, against the echo plugin, with what a reader supplies supplied.

    A snippet nobody runs documents the host it was written against. What is
    bound here is what a reader already has — a pipeline, a splitter, an
    embedding, documents, results, a query. Every name that is ours comes
    from the snippet's own imports, so renaming one of them fails this.
    """
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.ingestion import IngestionPipeline
    from llama_index.core.node_parser import SentenceSplitter
    from llama_index.core.schema import Document, NodeWithScore, TextNode

    blocked = "This paragraph contains RSP-BLOCK and must never be stored."
    secret = "The key is a secret value you must not index."
    (tmp_path / "rsp.toml").write_text(
        f'[[plugins]]\nname = "echo"\ncommand = {json.dumps(ECHO)}\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    namespace: dict[str, object] = {
        "IngestionPipeline": IngestionPipeline,
        "SentenceSplitter": SentenceSplitter,
        "embedding": MockEmbedding(embed_dim=8),
        "documents": [Document(text=blocked), Document(text=secret)],
        "retrieved": [NodeWithScore(node=TextNode(text=blocked), score=0.9)],
        "query": "anything",
    }
    exec(USE_IT.group(1), namespace)  # noqa: S102

    indexed = [node.get_content() for node in namespace["indexed"]]  # type: ignore[union-attr]
    assert not [text for text in indexed if "RSP-BLOCK" in text], indexed
    assert any("[REDACTED:echo-test]" in text for text in indexed), indexed
    assert namespace["kept"] == [], "a blocked node should leave the result set"
