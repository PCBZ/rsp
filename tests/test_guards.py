"""The vertical slice: documents into a real pipeline, then look in the store.

Everything else in this suite asks the runtime what it decided. This asks the
framework what it kept, which is the only question K1 is about — blocked
content must never be embedded or stored, and a verdict that says BLOCK proves
nothing on its own.

So the store here records what it was handed. "Not in the returned nodes" is a
weaker claim than "the store never saw it", and the difference is where the
interesting failure lives: a host can persist content down a path the
transformation chain never touches.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from llama_index.core.embeddings import MockEmbedding
from llama_index.core.ingestion import IngestionPipeline
from llama_index.core.node_parser import SentenceSplitter
from llama_index.core.schema import Document, MetadataMode, NodeWithScore, TextNode
from llama_index.core.storage.docstore import SimpleDocumentStore
from llama_index.core.vector_stores import SimpleVectorStore

from plugins import Implementation, for_role
from rsp.guards import RSPIngestGuard, RSPRetrieveGuard
from rsp.runtime import Plugin, Runtime

if TYPE_CHECKING:
    from collections.abc import Sequence

    from llama_index.core.schema import BaseNode

ECHO = next(one for one in for_role("echo"))
GITLEAKS = for_role("gitleaks")

# The echo plugin's markers (plugins/rsp-echo/main.py).
BLOCKED = "This paragraph contains RSP-BLOCK and must never be stored."
REDACTED = "The key is a secret value you must not index."
CLEAN = "Deployment notes. Nothing sensitive in this paragraph."


class Recording(SimpleVectorStore):
    """A vector store that remembers what it was asked to hold.

    The list lives outside the model because SimpleVectorStore is a pydantic
    object and an undeclared attribute on one is not a place to put state.
    """

    def add(self, nodes: Sequence[BaseNode], **kwargs: Any) -> list[str]:
        SEEN.extend(node.get_content() for node in nodes)
        return super().add(nodes, **kwargs)


SEEN: list[str] = []


@pytest.fixture(autouse=True)
def _forget() -> None:
    SEEN.clear()


@pytest.fixture(scope="module")
def echo() -> Runtime:
    return Runtime([Plugin(name=ECHO.name, command=list(ECHO.command))])


def pipeline(runtime: Runtime, **kwargs: Any) -> IngestionPipeline:
    """The guard where a host would put it: after splitting, before embedding.

    Order is the whole design. A guard before the splitter judges documents the
    index will never hold, and one after the embedding judges content that has
    already been vectorized.
    """
    return IngestionPipeline(
        transformations=[
            SentenceSplitter(chunk_size=128, chunk_overlap=0),
            RSPIngestGuard(runtime=runtime),
            MockEmbedding(embed_dim=8),
        ],
        vector_store=Recording(),
        **kwargs,
    )


def test_blocked_content_never_reaches_the_vector_store(echo: Runtime) -> None:
    """K1. The reason this protocol exists rather than a scanner that runs
    after the fact."""
    nodes = pipeline(echo).run(documents=[Document(text=BLOCKED), Document(text=CLEAN)])

    assert CLEAN in SEEN
    assert not [text for text in SEEN if "RSP-BLOCK" in text], SEEN
    assert [node.get_content() for node in nodes] == [CLEAN]


def test_the_store_receives_the_redacted_text_and_not_the_original(echo: Runtime) -> None:
    """S4. The host never sees a span, so it cannot apply one wrongly — but it
    can store the node it was handed before the runtime rewrote it."""
    pipeline(echo).run(documents=[Document(text=REDACTED)])

    assert len(SEEN) == 1
    assert "secret" not in SEEN[0]
    assert "[REDACTED:echo-test]" in SEEN[0]


def test_provenance_reaches_the_host_and_not_the_embedding(echo: Runtime) -> None:
    """Q8, checked against the text the framework would embed rather than
    against the list that is supposed to keep it out. Asserting on the
    exclusion list would only prove we filled in a list."""
    nodes = pipeline(echo).run(documents=[Document(text=REDACTED)])
    node = nodes[0]

    assert node.metadata["rsp.verdict"] == "REDACT"
    # Equality, not a substring search: "REDACT" occurs inside the replacement
    # string legitimately, and a test that trips over its own fixture proves
    # nothing. What must hold is that neither rendering carries any metadata.
    content = node.get_content(metadata_mode=MetadataMode.NONE)
    for mode in (MetadataMode.EMBED, MetadataMode.LLM):
        assert node.get_content(metadata_mode=mode) == content, f"metadata reached {mode.value}"
    assert node.metadata, "provenance should still be there for the host to read"


def test_a_docstore_keeping_document_text_stores_what_the_guard_rejected(
    echo: Runtime,
) -> None:
    """The failure a verdict cannot show you, pinned so the reason for the
    constraint below is executable rather than advice.

    `IngestionPipeline.run` defaults to `store_doc_text=True`, and the docstore
    is written from the input documents — a path the transformations never
    touch. So the guard drops the node, the vector store never sees it, and the
    text of the blocked document is persisted anyway.
    """
    docstore = SimpleDocumentStore()
    pipeline(echo, docstore=docstore).run(documents=[Document(text=BLOCKED, doc_id="b")])

    assert not SEEN, "the vector store is guarded"
    kept = docstore.docs["b"].get_content()
    assert "RSP-BLOCK" in kept, "expected the unguarded path to keep it"


def test_a_docstore_without_document_text_keeps_nothing(echo: Runtime) -> None:
    """The configuration a host must use: hashes are enough to deduplicate,
    and text outside the guarded path is text nobody judged."""
    docstore = SimpleDocumentStore()
    pipeline(echo, docstore=docstore).run(
        documents=[Document(text=BLOCKED, doc_id="b")], store_doc_text=False
    )

    assert not docstore.docs
    assert not SEEN


def test_a_blocked_node_shrinks_the_result_set(echo: Runtime) -> None:
    """The retrieve side. BLOCK there removes an item from the result set and
    nothing already stored (K2)."""
    guard = RSPRetrieveGuard(runtime=echo)
    scored = [
        NodeWithScore(node=TextNode(text=CLEAN), score=0.9),
        NodeWithScore(node=TextNode(text=BLOCKED), score=0.8),
    ]

    kept = guard.postprocess_nodes(scored, query_str="anything")

    assert [item.node.get_content() for item in kept] == [CLEAN]


@pytest.mark.parametrize("implementation", GITLEAKS, ids=lambda one: one.name)
def test_a_third_party_detector_through_the_whole_chain(
    implementation: Implementation,
) -> None:
    """The claim the proposal makes, with nothing of ours doing the detecting:
    a credential gitleaks recognises, through the real pipeline, into a store
    that reports what it kept.

    Once per implementation of the role, because "the host does not care what
    the plugin is written in" is a claim about the host, and a claim tested
    against one language is a claim about that language.
    """
    if not implementation.installed:
        pytest.skip(f"not installed: {implementation.missing}")
    runtime = Runtime([Plugin(name=implementation.name, command=list(implementation.command))])
    key = "AKIALALEMEL33243OLIB"

    pipeline(runtime).run(documents=[Document(text=f"deploy with {key} today")])

    assert len(SEEN) == 1
    assert key not in SEEN[0]
    assert "[REDACTED:secret]" in SEEN[0]


def test_a_retrieved_node_is_handed_back_redacted(echo: Runtime) -> None:
    """REDACT on the retrieve side rewrites the item rather than dropping it:
    the result set keeps its size and loses the secret."""
    guard = RSPRetrieveGuard(runtime=echo)

    kept = guard.postprocess_nodes(
        [NodeWithScore(node=TextNode(text=REDACTED), score=0.7)], query_str="anything"
    )

    assert len(kept) == 1
    assert "secret" not in kept[0].node.get_content()
    assert "[REDACTED:echo-test]" in kept[0].node.get_content()


def test_tagging_a_node_twice_does_not_repeat_the_exclusions(echo: Runtime) -> None:
    """A node can pass more than one guard — on_chunk at ingest, on_retrieve
    later — and an exclusion list that grows every time is a list nobody
    trusts."""
    node = TextNode(text=REDACTED)
    guard = RSPRetrieveGuard(runtime=echo)

    for _ in range(2):
        guard.postprocess_nodes([NodeWithScore(node=node, score=0.5)], query_str="q")

    for keys in (node.excluded_embed_metadata_keys, node.excluded_llm_metadata_keys):
        assert len(keys) == len(set(keys)), keys
    assert set(node.excluded_embed_metadata_keys) >= set(node.metadata)
