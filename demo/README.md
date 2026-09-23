# Demo

Eight documents that read like an internal wiki. Two of them have a credential
in the place credentials actually end up: pasted into a runbook during an
incident, and never taken out. Both are fabricated.

```console
$ rsp ingest demo/sample-docs --config demo/rsp.toml
scanned 11 chunks
  REDACT aws-access-token   demo/sample-docs/deploy-notes.md:1-20
  REDACT private-key        demo/sample-docs/runbook-backups.md:1-13
11 chunks indexed, 0 blocked, 2 redacted
```

Nothing of ours did the detecting: `demo/rsp.toml` names the gitleaks wrapper,
and gitleaks is the unmodified binary.

## REDACT, not BLOCK

The proposal illustrated this with `BLOCK`, and the real answer is better. A
chunk with one credential in it is usually still worth having — the sentence
around the secret is often the sentence somebody is searching for — so the
credential is replaced and the chunk is indexed.

`BLOCK` is what happens when the scanner finds something and cannot say where:
redacting the rest would leave that one in place, so none of it goes
downstream. Six of the eight documents are ordinary prose, including a meeting
note that discusses credentials at length and an FAQ that explains redaction.
Neither is flagged, which is the half of the claim that a corpus of nothing but
secrets could not make.

## The line range is a range on purpose

The host never sees a span (S4) — the runtime applies them and hands back
content. So the report can say which chunk was judged, and not where in it the
finding was. A single line number would send a reader to the top of a chunk and
let them believe the secret is there.

## Where the chunk size stops being an implementation detail

`on_chunk` sees one chunk at a time, and a secret larger than a chunk is not in
any of them. The private key in `runbook-backups.md` is four lines:

| chunk size | chunks the key spans | detected |
|---|---|---|
| 512 | 1 | yes |
| 256 | 1 | yes |
| 128 | 2 | **no** |

At 128 tokens neither fragment matches, because the rule needs `BEGIN` and
`END` together. The key is indexed, in halves, by a host that did everything
the specification asks. This is what `on_document` is reserved against
(SPEC.md section 4), and it is a property of where the hook sits rather than of
the scanner. The demo runs at 256.

## When the scanner is missing

```console
$ RSP_GITLEAKS=/nonexistent rsp ingest demo/sample-docs --config demo/rsp.toml
gitleaks: handshake failed (CRASHED)
$ echo $?
1
```

Not "everything was blocked" — the host refuses to exist. A plugin that cannot
introduce itself fails at construction rather than mid-ingest (E2), so there is
no window in which documents are indexed by a host whose scanner is gone.

## Running it

From the repository root — `demo/rsp.toml` names the wrapper by a relative
path, and a command is resolved against the working directory the way the
operating system resolves any command. A deployment would use an absolute path
or something on `PATH`.

Needs `gitleaks` on `PATH` (or `RSP_GITLEAKS`), `node`, and the extra:

```bash
uv sync --extra llamaindex
```

The embedding is a stand-in: a demo that asks for an API key is a demo nobody
runs. What this shows is which chunks were kept, redacted, or refused — not
retrieval quality.
