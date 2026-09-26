"""LlamaIndex adapters: the host side of the protocol.

Pass `store_doc_text=False` to `IngestionPipeline.run` when a docstore is
configured: it writes documents down a path no transformation sees (K1).
"""

from collections.abc import Callable, Sequence
from typing import Any

from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import BaseNode, NodeWithScore, QueryBundle, TransformComponent
from pydantic import ConfigDict

from rsp.runtime import Result, Runtime, Verdict


def tag(node: BaseNode, provenance: dict[str, Any]) -> None:
    """Record findings on the node, out of reach of the embedding and the LLM (Q8).

    LlamaIndex folds metadata into the text it embeds, so a plain update would
    embed "this chunk held an aws-access-key".
    """
    node.metadata.update(provenance)
    for excluded in (node.excluded_embed_metadata_keys, node.excluded_llm_metadata_keys):
        excluded.extend(key for key in provenance if key not in excluded)


class RSPIngestGuard(TransformComponent):
    """on_chunk. A blocked node is not returned, so it is never embedded.

    `on_block` is how an operator learns what was dropped: a blocked node leaves
    no trace in the pipeline's output.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)
    runtime: Runtime
    on_block: Callable[[BaseNode, Result], None] | None = None

    def __call__(self, nodes: Sequence[BaseNode], **kwargs: Any) -> Sequence[BaseNode]:
        kept: list[BaseNode] = []
        for node in nodes:
            result = self.runtime.evaluate(
                hook="on_chunk",
                content=node.get_content(),
                metadata={"source": node.metadata.get("file_path"), "node_id": node.id_},
            )
            if result.blocked:
                if self.on_block is not None:
                    self.on_block(node, result)
                continue
            if result.verdict is Verdict.REDACT:
                # span application is the runtime's job (D6)
                node.set_content(result.content)
            tag(node, result.provenance)
            kept.append(node)
        return kept


class RSPRetrieveGuard(BaseNodePostprocessor):
    """on_retrieve. A blocked node is dropped from the result set (Q3)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    runtime: Runtime

    def _postprocess_nodes(
        self,
        nodes: list[NodeWithScore],
        query_bundle: QueryBundle | None = None,
    ) -> list[NodeWithScore]:
        kept: list[NodeWithScore] = []
        for scored in nodes:
            result = self.runtime.evaluate(
                hook="on_retrieve",
                content=scored.node.get_content(),
                metadata={"node_id": scored.node.id_, "score": scored.score},
            )
            if result.blocked:
                continue
            if result.verdict is Verdict.REDACT:
                scored.node.set_content(result.content)
            tag(scored.node, result.provenance)
            kept.append(scored)
        return kept


# No on_response guard: LlamaIndex has no seam for it, and §4 reserves the hook.
