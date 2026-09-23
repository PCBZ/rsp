# Demo

Eight documents that read like an internal wiki. Two have a credential in the
place credentials end up: pasted into a runbook during an incident, never
taken out. Both fabricated. Run from the repository root:

```console
$ rsp ingest demo/sample-docs --config demo/rsp.toml
scanned 11 chunks
  REDACT aws-access-token   demo/sample-docs/deploy-notes.md:1-14
  REDACT private-key        demo/sample-docs/runbook-backups.md:1-13
11 chunks indexed, 0 blocked, 2 redacted
```

Nothing of ours detects: the config names the gitleaks wrapper, and gitleaks
is the unmodified binary. Needs it on `PATH` (or `RSP_GITLEAKS`), `node`, and
`uv sync --extra llamaindex`. The embedding is a stand-in — a demo that wants
an API key is a demo nobody runs.

**REDACT, not BLOCK.** A chunk with one credential in it is usually still
worth having. BLOCK is for a finding the scanner cannot place, and for a
scanner that cannot run: with `RSP_GITLEAKS=/nonexistent` the handshake fails
and the command exits 1 — the host refuses to exist rather than indexing a
corpus nobody scanned.

**A line range, not a line.** The host never sees a span (S4), so it knows
which chunk was judged, not where in it the finding was.

**Six of the eight are ordinary prose**, including a meeting note that spends
a page on credential handling and an FAQ explaining redaction. Neither is
flagged — the half of the claim a corpus of nothing but secrets cannot make.

## What chunking costs

`on_chunk` sees one chunk at a time, and the private key is four lines:

| chunk size | chunks it spans | detected |
|---|---|---|
| 512 | 1 | yes |
| 256 | 1 | yes |
| 128 | 2 | **no** |

At 128 neither fragment matches — the rule needs `BEGIN` and `END` together —
so the key is indexed in halves by a host that did everything the spec asks.
This is what `on_document` is reserved against (SPEC.md section 4). The demo
runs at 256.
