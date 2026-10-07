"""A whole host, as small as one gets: four documents in, a guarded index out.

Two plugins judge every chunk — `plugins/rsp-echo` in Python and
`examples/gitleaks-go` in Go — and nothing below knows which is which. The Go
one needs its toolchain and the binary it wraps; the Python one needs neither,
and the embedding is a stand-in, so there is no API key either.

    uv run --extra llamaindex python examples/host/main.py
"""

from __future__ import annotations

import pathlib
import shutil

from llama_index.core import VectorStoreIndex
from llama_index.core.embeddings import MockEmbedding
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import BaseNode, Document, TextNode

from rsp.config import load
from rsp.guards import RSPIngestGuard, RSPRetrieveGuard
from rsp.runtime import Plugin, Result, Runtime

HERE = pathlib.Path(__file__).parent
QUERY = "what should I read first"
# What each configured plugin needs before it can be started. The host needs
# none of it — it starts a command and reads JSON back — so this is the
# example saying which of the two this machine can run, not the protocol.
NEEDS = {"echo": ("python3",), "gitleaks-go": ("go", "gitleaks")}


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


def plugins() -> list[Plugin]:
    """The configured plugins this machine can start, saying which it skipped."""
    runnable = []
    for plugin in load(HERE / "rsp.toml"):
        needs = NEEDS.get(plugin.name, (plugin.command[0],))
        absent = [tool for tool in needs if shutil.which(tool) is None]
        if absent:
            print(f"skipping {plugin.name}: no {', '.join(absent)}")
        else:
            runnable.append(plugin)
    return runnable


def main() -> None:
    runtime = Runtime(plugins())  # every plugin handshakes here, or this raises
    answering = ", ".join(plugin.name for plugin in runtime.plugins)
    print(f"plugins: {answering} — each judges every chunk")
    embedding = MockEmbedding(embed_dim=8)
    refused: list[str] = []

    def record(node: BaseNode, result: Result) -> None:
        refused.append(f"{node.metadata.get('file_path'):24} {result.reasons[0]}")

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
            # The type, not the plugin: provenance names everyone who answered,
            # and both of these answer every chunk. What came back says which
            # of them had something to say about it.
            found = ", ".join(node.metadata.get("rsp.types", ()))
            print(f"  {verdict.lower():8} {node.metadata.get('file_path'):24} {found}")

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
