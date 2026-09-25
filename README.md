# RSP

A protocol for scanning content **before** it reaches a vector store.

Everything that ships today scans after storage, where an embedding already
exists and the text is recoverable from it. RSP puts the scanner at the
ingest hook instead, so that blocked means it was never there.

```console
$ rsp ingest demo/sample-docs --config demo/rsp.toml
scanned 11 chunks
  REDACT aws-access-token   demo/sample-docs/deploy-notes.md:1-14
  REDACT private-key        demo/sample-docs/runbook-backups.md:1-17
11 chunks indexed, 0 blocked, 2 redacted
```

Nothing in that run is ours except the wiring: the detector is
[gitleaks](https://github.com/gitleaks/gitleaks), unmodified, and the pipeline
is LlamaIndex.

## What it is

`SPEC.md` is the deliverable — twenty-eight clauses, each with the reasoning
that produced it, twenty-three of them settled by a conformance case rather
than by assertion. The code in `rsp/` is one host implementation, and exists
to prove the clauses are implementable.

A plugin is a command. It reads one JSON object on stdin, writes one on
stdout, and exits:

```console
$ echo '{"rsp_version":"0.1","hook":"on_chunk","content":"key: AKIA47CQZHT2MVPF3JXB"}' | my-scanner
{"verdict":"REDACT","spans":[{"start":5,"end":25,"type":"aws"}],"replacement":"[REDACTED]"}
```

Offsets are bytes into UTF-8, half-open. The host applies them; a plugin never
sees the content again. [Writing a plugin](WRITING-A-PLUGIN.md) is the page to
start from — the four messages, and the three things that bite.

## Try it

```bash
uv sync --extra llamaindex
uv run rsp ingest demo/sample-docs --config demo/rsp.toml   # needs gitleaks and node
```

## Check your own plugin

```console
$ python conformance/run.py -- my-scanner
```

Copy `conformance/` and `plugins/` next to your plugin. Standard library only,
and nothing in it imports this host: you are checking against the protocol,
not against our implementation of it. `conformance/README.md` explains roles
and the host cases.

## Where things are

| | |
|---|---|
| `SPEC.md` | the protocol |
| `WRITING-A-PLUGIN.md` | the on-ramp, quoting a plugin under test |
| `conformance/` | cases, a runner, and a plugin that misbehaves on request |
| `rsp/` | the reference host — five layers, one-way imports, zero dependencies |
| `plugins/rsp-echo` | the reference plugin, whose verdicts are chosen by markers |
| `examples/gitleaks-{ts,go}` | the same real scanner wrapped twice, in two languages |
| `demo/` | eight documents, two of them with fabricated credentials |

Decisions (D1–D9) and open questions live in the
[wiki](https://github.com/PCBZ/rsp/wiki). Clause IDs — `S1`, `E4` — resolve
inside a clone; issue numbers do not, so the spec never cites one.

## Status

v0.1 is the first freeze. Four clauses have no conformance case and
`SPEC.md` §10 says which and why. Two of them — blocked content never reaching
storage, and a dropped retrieval hit — are the ones a host case cannot observe
without the host offering somewhere to look, and they are the two the protocol
is most about. That is the honest state of it.
