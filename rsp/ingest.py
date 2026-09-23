"""Run a directory through the pipeline and report what did not make it in.

Needs the `llamaindex` extra. The embedding is a stand-in — a demo that asks
for an API key is a demo nobody runs — so what this shows is which chunks were
kept, redacted, or refused, not retrieval quality.
"""

from __future__ import annotations

import pathlib
from typing import TYPE_CHECKING, Any, NamedTuple

from rsp.runtime import Plugin, Runtime

if TYPE_CHECKING:
    from llama_index.core.schema import BaseNode

    from rsp.runtime import Result

# Small enough to retrieve precisely, large enough to hold a PEM block. A
# secret split across two chunks is invisible to a scanner that needs its whole
# shape, which is a property of where this hook sits, not of the scanner.
CHUNK = 256
READABLE = (".md", ".txt", ".rst")


class Finding(NamedTuple):
    """Where to go and look. Never what was found — a report that quotes a
    secret is a second copy of it, in a log this time (Q8)."""

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

    found = sorted(p for p in directory.rglob("*") if p.suffix in READABLE and p.is_file())
    if not found:
        raise FileNotFoundError(f"{directory}: nothing to ingest")
    return [
        Document(text=path.read_text(encoding="utf-8"), metadata={"file_path": str(path)})
        for path in found
    ]


def ingest(directory: pathlib.Path, plugins: list[Plugin]) -> Report:
    from llama_index.core.embeddings import MockEmbedding
    from llama_index.core.ingestion import IngestionPipeline
    from llama_index.core.node_parser import SentenceSplitter

    from rsp.guards import RSPIngestGuard

    findings: list[Finding] = []

    def record(node: BaseNode, result: Result) -> None:
        findings.append(_finding("BLOCK", result.provenance, node))

    splitter = SentenceSplitter(chunk_size=CHUNK, chunk_overlap=0)
    chunks = splitter(documents(directory))
    kept = IngestionPipeline(
        transformations=[
            RSPIngestGuard(runtime=Runtime(plugins), on_block=record),
            MockEmbedding(embed_dim=8),
        ],
        # No docstore: with one, `store_doc_text` would persist the documents
        # whole, down a path no transformation sees (K1).
    ).run(nodes=chunks)

    findings += [
        _finding("REDACT", node.metadata, node)
        for node in kept
        if node.metadata.get("rsp.verdict") == "REDACT"
    ]
    return Report(scanned=len(chunks), indexed=len(kept), findings=findings)


def _finding(verdict: str, provenance: dict[str, Any], node: BaseNode) -> Finding:
    types = provenance.get("rsp.types") or ["unknown"]
    return Finding(
        verdict=verdict,
        types=", ".join(types),
        source=node.metadata.get("file_path", "?"),
        lines=_lines_of(node),
    )


def _lines_of(node: BaseNode) -> str:
    """The chunk's line range.

    A range rather than a line, because that is what the host knows: it never
    sees a span (S4), so it can say which text was judged and not where in it
    the finding was. A single line number here would send a reader to the top
    of a chunk and let them believe the secret is there.
    """
    source = node.metadata.get("file_path")
    if source is None:
        return "?"
    document = pathlib.Path(source).read_text(encoding="utf-8")
    start = getattr(node, "start_char_idx", None) or 0
    first = document[:start].count("\n") + 1
    return f"{first}-{first + node.get_content().count(chr(10))}"
