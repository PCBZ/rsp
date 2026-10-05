"""A whole host, as small as one gets: three documents in, a guarded index out.

Runs with no network and no API key — the plugin is `plugins/rsp-echo`, which
picks its verdict from markers in the text, and the embedding is a stand-in.

    uv run --extra llamaindex python examples/host/main.py
"""

from __future__ import annotations

import pathlib

from llama_index.core import VectorStoreIndex
from llama_index.core.embeddings import MockEmbedding
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import BaseNode, Document, TextNode

from rsp.config import load
from rsp.guards import RSPIngestGuard, RSPRetrieveGuard
from rsp.runtime import Result, Runtime

HERE = pathlib.Path(__file__).parent
QUERY = "what should I read first"


def documents() -> list[Document]:
    """One document per file, with the path kept out of the chunk budget.

    A splitter subtracts a document's metadata from the chunk size, so an
    absolute path in there chunks the same corpus differently depending on
    where it is checked out — and excluding it is what the protocol asks of
    anything a node carries anyway.
    """
    found = []
    for path in sorted(HERE.glob("docs/*.md")):
        document = Document(text=path.read_text("utf-8"), metadata={"file_path": path.name})
        document.excluded_embed_metadata_keys.append("file_path")
        document.excluded_llm_metadata_keys.append("file_path")
        found.append(document)
    return found


def main() -> None:
    runtime = Runtime(load(HERE / "rsp.toml"))  # every plugin handshakes here, or this raises
    embedding = MockEmbedding(embed_dim=8)
    refused: list[str] = []

    def record(node: BaseNode, result: Result) -> None:
        refused.append(f"{node.metadata.get('file_path')}: {result.provenance['rsp.verdict']}")

    # The guard sits after the splitter and before the embedding, which is the
    # whole claim: a blocked chunk is never embedded and never stored, so there
    # is nothing to delete afterwards.
    indexed = IngestionPipeline(
        transformations=[
            SentenceSplitter(chunk_size=256, chunk_overlap=0),
            RSPIngestGuard(runtime=runtime, on_block=record),
            embedding,
        ]
    ).run(documents=documents())

    print(f"{len(indexed)} chunks indexed, {len(refused)} refused")
    for line in refused:
        print(f"  blocked  {line}")
    for node in indexed:
        verdict = node.metadata.get("rsp.verdict")
        if verdict != "ALLOW":
            print(f"  {verdict.lower():8} {node.metadata.get('file_path')}")

    # An index predating the guard, or written by something else: the chunk is
    # already in the store, so the only place left to catch it is on the way out.
    older = TextNode(text="RSP-BLOCK: indexed before anyone installed a guard.")
    index = VectorStoreIndex([*indexed, older], embed_model=embedding)

    retrieved = index.as_retriever(similarity_top_k=4).retrieve(QUERY)
    kept = RSPRetrieveGuard(runtime=runtime).postprocess_nodes(retrieved, query_str=QUERY)

    print(f"\nretrieved {len(retrieved)}, answered with {len(kept)}")
    for item in kept:
        print(f"  kept     {item.node.metadata.get('file_path') or '(no source)'}")


if __name__ == "__main__":
    main()
