"""The demo, through the real pipeline and a real scanner; the README's numbers come from here."""

from __future__ import annotations

import builtins
import pathlib
import shutil
import sys
from typing import TYPE_CHECKING, Any

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from plugins import REQUIRED, ROOT, for_role
from rsp.cli import main
from rsp.config import load
from rsp.ingest import CHUNK, documents, ingest
from rsp.runtime import ConfigError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from llama_index.core.schema import BaseNode

DOCS = ROOT / "demo" / "sample-docs"
CONFIG = ROOT / "demo" / "rsp.toml"

# What was planted, and where. Nothing else in the corpus may be flagged.
PLANTED = {"deploy-notes.md": "aws-access-token", "runbook-backups.md": "private-key"}
SECRETS = ("AKIA47CQZHT2MVPF3JXB", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU")


@pytest.fixture(scope="module")
def gitleaks() -> None:
    wrapper = next(one for one in for_role("gitleaks") if one.name == "rsp-gitleaks-ts")
    if why := wrapper.unavailable():
        if wrapper.supported and REQUIRED:
            pytest.fail(why)
        pytest.skip(why)


def test_the_planted_secrets_are_redacted_and_nothing_else_is(gitleaks: None) -> None:
    report = ingest(DOCS, load(CONFIG))

    assert len(report.redacted) == len(PLANTED), "one chunk per planted secret"
    assert {one.types for one in report.redacted} == set(PLANTED.values())
    assert {pathlib.Path(one.source).name for one in report.redacted} == set(PLANTED)
    assert report.indexed == report.scanned, "redaction keeps the chunk (V3)"
    assert not report.blocked, "a scanner that can place its findings does not block"


def test_no_planted_secret_survives_into_the_index(gitleaks: None) -> None:
    """The claim the demo exists to make, asked of the store rather than of a count.

    What the store was handed, not what `ingest` returned: a host writes the
    nodes it was given, so "the store never saw it" is the claim and "not in
    the result" is weaker.
    """
    from llama_index.core.node_parser import SentenceSplitter
    from llama_index.core.schema import MetadataMode
    from llama_index.core.vector_stores import SimpleVectorStore

    from rsp.ingest import documents

    indexed: list[Any] = []

    class Recording(SimpleVectorStore):
        """pydantic allows no undeclared attributes, so the list is outside."""

        def add(self, nodes: Sequence[BaseNode], **kwargs: Any) -> list[str]:
            indexed.extend(nodes)
            return super().add(nodes, **kwargs)

    kept = ingest(DOCS, load(CONFIG), store=Recording())
    chunks = SentenceSplitter(chunk_size=CHUNK, chunk_overlap=0)(documents(DOCS))
    before = "".join(chunk.get_content() for chunk in chunks)

    assert kept.redacted, "the corpus is supposed to contain secrets"
    assert len(indexed) == kept.indexed, "the store holds the index this reports"
    for secret in SECRETS:
        assert secret in before, "planted, or this test proves nothing"
    for node in indexed:
        # Every mode, since a secret kept out of the text and left in the
        # metadata reaches an embedding and the LLM all the same (Q8).
        written = "".join(node.get_content(metadata_mode=mode) for mode in MetadataMode)
        for secret in SECRETS:
            assert secret not in written, f"{node.metadata.get('file_path')} carried it in"


def test_the_demo_runs_from_any_directory(
    gitleaks: None, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The config names its plugin beside itself, not beside whoever ran it."""
    monkeypatch.chdir(tmp_path)

    report = ingest(DOCS, load(CONFIG))

    assert len(report.redacted) == len(PLANTED)


def test_the_corpus_is_mostly_clean(gitleaks: None) -> None:
    """Precision: a corpus where everything is flagged proves nothing about a scanner."""
    report = ingest(DOCS, load(CONFIG))

    assert report.scanned > 2 * len(PLANTED), "most chunks must be ordinary prose"


def test_a_missing_scanner_stops_the_run_before_it_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed, as early as possible, rather than index a corpus nobody scanned (E2)."""
    monkeypatch.setenv("RSP_GITLEAKS", "/nonexistent/gitleaks")
    if shutil.which("node") is None:
        pytest.skip("the wrapper needs node")

    with pytest.raises(ConfigError, match="handshake"):
        ingest(DOCS, load(CONFIG))


def test_the_command_reports_that_refusal_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RSP_GITLEAKS", "/nonexistent/gitleaks")
    if shutil.which("node") is None:
        pytest.skip("the wrapper needs node")

    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 1
    assert "handshake failed" in capsys.readouterr().err


def test_the_command_prints_the_summary(gitleaks: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 0

    printed = capsys.readouterr().out
    assert "scanned" in printed
    assert "REDACT" in printed and "aws-access-token" in printed
    for secret in SECRETS:
        assert secret not in printed, "a report that quotes the secret is another copy"


def test_the_command_explains_a_missing_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The only sentence a user sees when they installed rsp without it.

    Refuses llama_index, not `rsp.ingest`, which imports it inside its functions.
    """
    real = builtins.__import__

    def without_llama_index(name: str, *rest: object, **kwargs: object) -> object:
        if name.startswith("llama_index"):
            raise ImportError(f"No module named {name!r}")
        return real(name, *rest, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", without_llama_index)

    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 1
    assert "llamaindex" in capsys.readouterr().err


def test_a_directory_with_nothing_to_read_says_so(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError, match="nothing to ingest"):
        documents(tmp_path)


def test_a_blocked_chunk_is_named_in_the_report(tmp_path: pathlib.Path) -> None:
    """A report that omits it leaves the index quietly smaller than its source."""
    corpus = tmp_path / "docs"
    corpus.mkdir()
    (corpus / "notes.md").write_text("Ordinary prose.\n")
    (corpus / "refused.md").write_text("This paragraph contains RSP-BLOCK.\n")
    config = tmp_path / "rsp.toml"
    config.write_text(
        f'[[plugins]]\nname = "echo"\ncommand = ["{sys.executable}", '
        f'"{ROOT / "plugins/rsp-echo/main.py"}"]\n'
    )

    report = ingest(corpus, load(config))

    assert len(report.blocked) == 1
    [item] = report.blocked
    assert item.source.endswith("refused.md")
    assert report.indexed == report.scanned - 1


def test_a_node_without_a_source_still_reports_a_range() -> None:
    from llama_index.core.schema import TextNode

    from rsp.ingest import _lines_of

    assert _lines_of(TextNode(text="anything")) == "?"


def test_the_range_covers_the_chunk_as_it_was_read(gitleaks: None) -> None:
    """Not as redacted, which stops short of the key; the runbook's key ends on line 15."""
    [finding] = [one for one in ingest(DOCS, load(CONFIG)).redacted if "backups" in one.source]

    first, last = (int(part) for part in finding.lines.split("-"))
    assert last >= 15, f"{finding.lines} does not reach the end of the key"
    assert first == 1


def test_a_missing_scanner_fails_before_the_corpus_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dead plugin costs nothing else, and the failure is the handshake's, not a splitter's."""
    monkeypatch.setenv("RSP_GITLEAKS", "/nonexistent/gitleaks")
    if shutil.which("node") is None:
        pytest.skip("the wrapper needs node")
    seen: list[pathlib.Path] = []
    monkeypatch.setattr("rsp.ingest.documents", seen.append)

    with pytest.raises(ConfigError, match="handshake"):
        ingest(DOCS, load(CONFIG))

    assert not seen, "the corpus was read before the plugin was checked"


def test_the_line_range_reads_each_source_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Caching offsets rather than text keeps no scanned secret alive in memory."""
    from llama_index.core.schema import TextNode

    from rsp import ingest as module

    source = DOCS / min(p.name for p in DOCS.iterdir() if p.is_file())
    module._newlines_as_of.cache_clear()
    reads = 0
    original = pathlib.Path.read_text

    def counted(self: pathlib.Path, *args: object, **kwargs: object) -> str:
        nonlocal reads
        if self == source:
            reads += 1
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pathlib.Path, "read_text", counted)
    for start in (0, 10, 20):
        node = TextNode(text="x", metadata={"file_path": str(source)})
        node.start_char_idx, node.end_char_idx = start, start + 5
        module._lines_of(node)

    assert reads == 1, f"read the source {reads} times for three findings"


@pytest.mark.parametrize(
    ("text", "span", "want"),
    [
        ("hello\n", (0, 6), "1-1"),
        ("a\nb\nc\n", (0, 6), "1-3"),
        ("hello\nworld", (6, 11), "2-2"),
        ("hello\n", (6, 6), "2-2"),
    ],
    ids=["ends on a newline", "three lines", "the second line", "an empty chunk"],
)
def test_the_last_line_holds_the_chunk_s_last_character(
    tmp_path: pathlib.Path, text: str, span: tuple[int, int], want: str
) -> None:
    """An exclusive end read as a position names the line after the one it ends."""
    from llama_index.core.schema import TextNode

    from rsp.ingest import _lines_of

    source = tmp_path / "doc.md"
    source.write_text(text, encoding="utf-8")
    node = TextNode(text="x", metadata={"file_path": str(source)})
    node.start_char_idx, node.end_char_idx = span

    assert _lines_of(node) == want


def test_a_rewritten_source_is_read_again(tmp_path: pathlib.Path) -> None:
    """Offsets cached under a path alone outlive the file they came from."""
    from llama_index.core.schema import TextNode

    from rsp.ingest import _lines_of

    source = tmp_path / "doc.md"
    node = TextNode(text="x", metadata={"file_path": str(source)})
    node.start_char_idx, node.end_char_idx = 0, 6

    source.write_text("hello\n", encoding="utf-8")
    assert _lines_of(node) == "1-1"

    source.write_text("a\nb\nc\n", encoding="utf-8")
    assert _lines_of(node) == "1-3"


def test_chunking_does_not_depend_on_where_the_corpus_lives(tmp_path: pathlib.Path) -> None:
    """The splitter subtracts a document's metadata from the chunk budget.

    An absolute path in there makes the same corpus chunk differently in two
    checkouts, so a scanner is handed different text in one chunk — a verdict
    that moved for a reason nobody chose. Through `documents`, because a test
    that builds its own exclusion lists asserts nothing about the code.
    """
    from llama_index.core.node_parser import SentenceSplitter

    from rsp.ingest import CHUNK

    text = (DOCS / "runbook-backups.md").read_text(encoding="utf-8")
    boundaries = set()
    for depth in (1, 12):
        # Two checkouts of one corpus, at directory names of different length.
        corpus = tmp_path.joinpath(*["d" * 40] * depth) / "sample-docs"
        corpus.mkdir(parents=True)
        (corpus / "runbook-backups.md").write_text(text, encoding="utf-8")

        nodes = SentenceSplitter(chunk_size=CHUNK, chunk_overlap=0)(documents(corpus))
        boundaries.add(tuple(node.start_char_idx for node in nodes))

    assert len(boundaries) == 1, f"two checkouts, {len(boundaries)} chunkings: {boundaries}"


def test_the_path_is_kept_out_of_what_a_document_carries() -> None:
    """Both lists, which is also what Q8 asks of anything on a node."""
    for document in documents(DOCS):
        assert "file_path" in document.excluded_embed_metadata_keys
        assert "file_path" in document.excluded_llm_metadata_keys
