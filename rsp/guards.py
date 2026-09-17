"""Host call site — issue #1. This file does not run yet.

Written against the real llama-index-core 0.14.24 API, calling an ``rsp.runtime``
that does not exist. The runtime's API is whatever this file needs it to be;
SPEC.md is reverse-engineered from that, not the other way round.

Verified signatures:
    TransformComponent.__call__(nodes: Sequence[BaseNode], **kwargs) -> Sequence[BaseNode]
    BaseNodePostprocessor._postprocess_nodes(nodes: List[NodeWithScore],
                                             query_bundle: QueryBundle | None = None)
"""

from collections.abc import Sequence
from typing import Any

from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import BaseNode, NodeWithScore, QueryBundle, TransformComponent
from pydantic import PrivateAttr

from rsp.runtime import Runtime, Verdict  # does not exist yet — #4, #5, #6, #7


def tag(node: BaseNode, provenance: dict[str, Any]) -> None:
    """Record findings on the node without letting them reach an embedding or the LLM.

    LlamaIndex folds metadata into the text it vectorizes, so a naive
    metadata.update() would embed "this chunk held an aws-access-key" — a
    smaller version of the problem RSP exists to prevent. Provenance is for the
    host to read, not for the index to carry (Q8).
    """
    node.metadata.update(provenance)
    for key in provenance:
        if key not in node.excluded_embed_metadata_keys:
            node.excluded_embed_metadata_keys.append(key)
        if key not in node.excluded_llm_metadata_keys:
            node.excluded_llm_metadata_keys.append(key)


class RSPIngestGuard(TransformComponent):
    """on_chunk. A blocked node is not returned, so it is never embedded."""

    config_path: str = "rsp.yaml"
    _runtime: Runtime = PrivateAttr()

    def model_post_init(self, context: Any) -> None:
        self._runtime = Runtime.from_config(self.config_path)

    def __call__(self, nodes: Sequence[BaseNode], **kwargs: Any) -> Sequence[BaseNode]:
        kept: list[BaseNode] = []
        for node in nodes:
            result = self._runtime.evaluate(
                hook="on_chunk",
                content=node.get_content(),
                metadata={"source": node.metadata.get("file_path"), "node_id": node.id_},
            )
            if result.verdict is Verdict.BLOCK:
                continue
            if result.verdict is Verdict.REDACT:
                # Span application is the runtime's job, not the host's: the host
                # never sees a span and cannot get UTF-8 boundaries wrong (D6).
                node.set_content(result.content)
            tag(node, result.provenance)
            kept.append(node)
        return kept


class RSPRetrieveGuard(BaseNodePostprocessor):
    """on_retrieve. A blocked node is dropped from the result set (Q3)."""

    config_path: str = "rsp.yaml"
    _runtime: Runtime = PrivateAttr()

    def model_post_init(self, context: Any) -> None:
        self._runtime = Runtime.from_config(self.config_path)

    def _postprocess_nodes(
        self,
        nodes: list[NodeWithScore],
        query_bundle: QueryBundle | None = None,
    ) -> list[NodeWithScore]:
        kept: list[NodeWithScore] = []
        for scored in nodes:
            result = self._runtime.evaluate(
                hook="on_retrieve",
                content=scored.node.get_content(),
                metadata={"node_id": scored.node.id_, "score": scored.score},
            )
            if result.verdict is Verdict.BLOCK:
                continue
            if result.verdict is Verdict.REDACT:
                scored.node.set_content(result.content)
            tag(scored.node, result.provenance)
            kept.append(scored)
        return kept


# on_response has no equivalent seam in LlamaIndex: response synthesis is not a
# pluggable pipeline stage the way transformations and postprocessors are.
# Open, tracked separately from #1 — see the note on this issue.
