# A host, in one file

What a RAG pipeline looks like with RSP in it. Three documents in, a guarded
index out, and nothing to install:

```console
$ uv run --extra llamaindex python examples/host/main.py
2 chunks indexed, 1 refused
  blocked  runbook-incident.md: BLOCK
  redact   deploy-notes.md

retrieved 3, answered with 2
  kept     onboarding.md
  kept     deploy-notes.md
```

No network, no API key, no gitleaks: the plugin is `plugins/rsp-echo`, which
picks its verdict from markers in the text, and the embedding is a stand-in.
The documents are fabricated, and none of them holds a real credential.

## What the two guards are for

**`RSPIngestGuard` runs after the splitter and before the embedding.** That is
the whole claim: a blocked chunk is never embedded and never stored, so there
is nothing to delete afterwards and nothing recoverable from a vector. One
document here is refused outright and one comes back with its span rewritten —
same pipeline, different verdict, decided by a plugin this code knows nothing
about.

**`RSPRetrieveGuard` runs on what came back.** The example puts a node into
the store directly, the way an index built before anyone installed a guard
already holds one, and that node is retrieved and then dropped on the way out.
An index you did not fill is the reason this second seam exists.

## Where to look

| | |
|---|---|
| `main.py` | the whole host, about sixty lines |
| `rsp.toml` | one plugin, named by a path relative to this file |
| `docs/` | three documents: one refused, one redacted, one clean |

A real host swaps the stand-in embedding for its own and `rsp-echo` for a
scanner — `examples/gitleaks-py` wraps gitleaks in thirty lines, and six other
languages do the same thing beside it. Nothing else changes.
