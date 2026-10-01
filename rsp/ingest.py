"""Run a directory through the pipeline and report what did not make it in.

Needs the `llamaindex` extra. The embedding is a stand-in so the demo needs no
API key: what it shows is which chunks were kept, redacted, or refused.
"""

from __future__ import annotations

import pathlib
from bisect import bisect_left
from functools import cache
from typing import TYPE_CHECKING, Any, NamedTuple

from rsp.runtime import Plugin, Runtime

if TYPE_CHECKING:
    from llama_index.core.schema import BaseNode

    from rsp.runtime import Result

# Large enough for a PEM block: a secret split across two chunks is invisible to on_chunk.
CHUNK = 256
_READABLE = (".md", ".txt", ".rst")


class Finding(NamedTuple):
    """Where to look, never what was found: quoting a secret makes a second copy (Q8)."""

    verdict: str
    types: str
    source: str
    lines: str


class Report(NamedTuple):
    scanned: int
    indexed: int
    findings: list[Finding]

    @property
    def blocked(self) -> list[Finding]:
        return [one for one in self.findings if one.verdict == "BLOCK"]

    @property
    def redacted(self) -> list[Finding]:
        return [one for one in self.findings if one.verdict == "REDACT"]


def documents(directory: pathlib.Path) -> list[Any]:
    from llama_index.core.schema import Document

    found = sorted(p for p in directory.rglob("*") if p.suffix in _READABLE and p.is_file())
    if not found:
        raise FileNotFoundError(f"{directory}: nothing to ingest")
    return [_document(Document, path) for path in found]


def _document(Document: Any, path: pathlib.Path) -> Any:  # noqa: N803
    """One file, with its path kept out of the text the splitter budgets for.

    The splitter subtracts a document's metadata from the chunk size, so an
    absolute path in there chunks the same corpus differently depending on
    where it is checked out — and a scanner then sees different text in one
    chunk. Excluding it is also what Q8 asks of anything a node carries.
    """
    document = Document(text=path.read_text(encoding="utf-8"), metadata={"file_path": str(path)})
    for excluded in (document.excluded_embed_metadata_keys, document.excluded_llm_metadata_keys):
        excluded.append("file_path")
    return document


def _newlines(source: str) -> tuple[int, ...]:
    """Where the line breaks are in a file on disk, read once per version of it."""
    stat = pathlib.Path(source).stat()
    return _newlines_as_of(source, stat.st_mtime_ns, stat.st_size)


@cache
def _newlines_as_of(source: str, mtime_ns: int, size: int) -> tuple[int, ...]:
    """Keyed on when the file was written, so a rewritten one is read again.

    Offsets and not the text: a cache of contents would hold every scanned
    secret for as long as the process lives.
    """
    return tuple(
        at for at, char in enumerate(pathlib.Path(source).read_text("utf-8")) if char == "\n"
    )


def _lines_of(node: BaseNode) -> str:
    """The chunk's line range, since the host never sees a span (S4).

    A single line number would send a reader to the top of the chunk as if the
    secret were there.
    """
    source = node.metadata.get("file_path")
    start = getattr(node, "start_char_idx", None)
    end = getattr(node, "end_char_idx", None)
    if source is None or start is None or end is None:
        return "?"
    # From the offsets, not the content: a redacted node's text has been rewritten.
    newlines = _newlines(source)
    # end is exclusive, so the last line is the one holding its last character.
    # Taken from end itself, a chunk ending on a newline reaches the empty line
    # after it; below start, an empty chunk ends before it begins.
    return f"{bisect_left(newlines, start) + 1}-{bisect_left(newlines, max(start, end - 1)) + 1}"


def _finding(verdict: str, provenance: dict[str, Any], node: BaseNode) -> Finding:
    types = provenance.get("rsp.types") or ["unknown"]
    return Finding(
        verdict=verdict,
        types=", ".join(types),
        source=node.metadata.get("file_path", "?"),
        lines=_lines_of(node),
    )


def ingest(directory: pathlib.Path, plugins: list[Plugin], *, store: Any = None) -> Report:
    """One directory in, a `Report` out; `store` takes the kept chunks, default nowhere.

    A host that wants an index to retrieve from passes one. It is also where
    the claim is checked: what the index was handed is a stronger answer than
    a count of what came back.
    """
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.ingestion import IngestionPipeline
    from llama_index.core.node_parser import SentenceSplitter

    from rsp.guards import RSPIngestGuard

    findings: list[Finding] = []

    def record(node: BaseNode, result: Result) -> None:
        findings.append(_finding("BLOCK", result.provenance, node))

    runtime = Runtime(plugins)  # handshakes before the corpus is read
    chunks = SentenceSplitter(chunk_size=CHUNK, chunk_overlap=0)(documents(directory))
    kept = IngestionPipeline(
        transformations=[
            RSPIngestGuard(runtime=runtime, on_block=record),
            MockEmbedding(embed_dim=8),
        ],
        # No docstore: it would store documents whole, past every guard (K1).
        vector_store=store,
    ).run(nodes=chunks)

    findings += [
        _finding("REDACT", node.metadata, node)
        for node in kept
        if node.metadata.get("rsp.verdict") == "REDACT"
    ]
    return Report(scanned=len(chunks), indexed=len(kept), findings=findings)
