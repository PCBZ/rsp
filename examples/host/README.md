# A host, in one file

What a RAG pipeline looks like with RSP in it. Four documents in, a guarded
index out, and two plugins in two languages judging every chunk:

```console
$ uv run --extra llamaindex python examples/host/main.py
plugins: echo, gitleaks-go — each judges every chunk
3 chunks indexed, 1 refused
  blocked  runbook-incident.md      echo: marker RSP-BLOCK
  redact   deploy-notes.md          echo-test
  redact   mirror-credentials.md    aws-access-token

retrieved 4, answered with 3
  kept     deploy-notes.md
  kept     onboarding.md
  kept     mirror-credentials.md
```

## Two languages, one pipeline

`echo` is Python and standard library only; `gitleaks-go` is Go wrapping the
gitleaks binary. **The host code is the same either way** — it starts a
command, writes one JSON object, reads one back. Nothing in `main.py` knows
what either is written in, and nothing would change if you added a third in
Rust or Swift: `examples/` has five more.

Which one found what is in the last column. `echo-test` is Python's, from the
word *secret*; `aws-access-token` is gitleaks', from a key shaped the way real
ones are. Each caught something the other did not.

That column is the finding's type, not the plugin's name, because provenance
records everyone who **answered** — and both of these answer every chunk,
including the ones where they find nothing.

## Running it with less

The Python half needs nothing installed:

```console
$ uv run --extra llamaindex python examples/host/main.py
skipping gitleaks-go: no go, gitleaks
plugins: echo — each judges every chunk
3 chunks indexed, 1 refused
  blocked  runbook-incident.md      echo: marker RSP-BLOCK
  redact   deploy-notes.md          echo-test
```

Note what is missing: `mirror-credentials.md` is indexed with the key still in
it. A host is exactly as strict as the plugins it can start, which is the
argument for the handshake failing loudly rather than a plugin failing quietly.

## The two guards

**`RSPIngestGuard` runs after the splitter and before the embedding.** That is
the whole claim: a blocked chunk is never embedded and never stored, so there
is nothing to delete afterwards and nothing recoverable from a vector.

**`RSPRetrieveGuard` runs on what came back.** The example puts a node into
the store directly, the way an index built before anyone installed a guard
already holds one, and that node is retrieved and then dropped on the way out.
An index you did not fill is the reason this second seam exists.

## Where to look

| | |
|---|---|
| `main.py` | the whole host, about seventy lines |
| `rsp.toml` | two plugins, named by paths relative to this file |
| `docs/` | four documents: one refused, two redacted, one clean |

Every document here is fabricated, including the key. Swap `rsp-echo` for a
scanner you trust and the stand-in embedding for a real one; nothing else
changes.
