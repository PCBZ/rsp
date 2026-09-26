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
    return [
        Document(text=path.read_text(encoding="utf-8"), metadata={"file_path": str(path)})
        for path in found
    ]


@cache
def _newlines(source: str) -> tuple[int, ...]:
    """Where the line breaks are in a file on disk.

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
    return f"{bisect_left(newlines, start) + 1}-{bisect_left(newlines, end) + 1}"


def _finding(verdict: str, provenance: dict[str, Any], node: BaseNode) -> Finding:
    types = provenance.get("rsp.types") or ["unknown"]
    return Finding(
        verdict=verdict,
        types=", ".join(types),
        source=node.metadata.get("file_path", "?"),
        lines=_lines_of(node),
    )


def ingest(directory: pathlib.Path, plugins: list[Plugin]) -> Report:
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
    ).run(nodes=chunks)

    findings += [
        _finding("REDACT", node.metadata, node)
        for node in kept
        if node.metadata.get("rsp.verdict") == "REDACT"
    ]
    return Report(scanned=len(chunks), indexed=len(kept), findings=findings)
