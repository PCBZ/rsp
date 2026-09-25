# Writing a plugin

A plugin is a command. The host starts it, writes one JSON object to its
stdin, reads one from its stdout, and lets it exit. There is no SDK, no
library to link, and no language requirement — if it can read stdin and write
stdout, it can be a plugin.

The code excerpts are quoted from `examples/gitleaks-ts`, a real plugin the
conformance cases run against, and a test checks each quote is still in the
file it names. The `$` transcripts are invented — no plugin here is called
`my-plugin` — so a test checks their JSON against the protocol instead.

## The whole of it

```ts
// examples/gitleaks-ts/src/main.ts
const request: Request = JSON.parse(await read(process.stdin));
process.stdout.write(`${JSON.stringify(respond(request))}\n`);
```

## Two kinds of call

**The handshake** comes first, once, before any content. The host asks who you
are and what you can do:

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | my-plugin
{"rsp_version":"0.1","name":"my-plugin","version":"0.1.0","hooks":["on_chunk"],"deterministic":true}
```

`hooks` is what the host may ask you about; it will not call you on anything
else. `deterministic` says whether the same content always gets the same
answer — say `false` if a model is involved, and the host will not cache you.

**A content call** is the other kind. One chunk in, one verdict out:

```console
$ echo '{"rsp_version":"0.1","hook":"on_chunk","content":"key: AKIA47CQZHT2MVPF3JXB"}' | my-plugin
{"verdict":"REDACT","spans":[{"start":5,"end":25,"type":"aws"}],"replacement":"[REDACTED]"}
```

## Four verdicts

| | |
|---|---|
| `ALLOW` | nothing found. Carries no other field |
| `FLAG` | worth recording, not worth changing |
| `REDACT` | mask these ranges. Carries `spans` and `replacement` |
| `BLOCK` | this chunk must not be indexed |

```ts
// examples/gitleaks-ts/src/protocol.ts
  // ALLOW carries nothing else: the common case is the cheap one (V2).
  if (findings.length === 0) return { verdict: "ALLOW" };
```

`BLOCK` is for a finding you cannot place. If your scanner says there is a
secret but cannot say where, redacting the rest would leave that one in the
chunk:

```ts
// examples/gitleaks-ts/src/protocol.ts
  if (spans.length !== findings.length) {
    return {
      verdict: "BLOCK",
      reason: "gitleaks reported a finding whose position could not be confirmed",
      severity: "critical",
    };
  }
```

## Three things that bite

### stdout is the protocol channel

Exactly one JSON object on it, and nothing else. A banner, a progress line, a
warning — anything extra and the host cannot tell your response from your
logging, so it trusts neither. Diagnostics go to stderr, where the host reads
them for the operator and never for a decision.

Wrapping a tool that prints its own banner? Turn it off. The gitleaks adapter
passes `--no-banner` for exactly this reason.

### Offsets are bytes, not characters

A span is a half-open range of **byte** offsets into the UTF-8 encoding of the
content. This is the trap that catches every language whose strings are not
bytes:

```
content:  密钥 AKIA47CQZHT2MVPF3JXB
          ^
          AKIA starts at character 3, and at byte 7
```

Python counts code points, JavaScript counts UTF-16 units, Go and Rust count
bytes. Send a character index and the host either masks the wrong range or
refuses the span outright — both ends must also land on a character boundary.

The safe move is to compute on the encoded bytes and never on the string:

```ts
// examples/gitleaks-ts/src/gitleaks.ts
  const bytes = Buffer.from(content, "utf8");
```

### A wrapper's version must carry the tool's

If your plugin wraps something else, the version you declare has to include
the wrapped tool's. The host caches verdicts against your version, and the
thing that decides a verdict is the tool: it gains a rule, the answer changes
for content that did not, and a cache keyed on your version alone keeps
serving the old one.

```ts
// examples/gitleaks-ts/src/protocol.ts
    version: `0.1.0+${version()}`,
```

## Check it

```console
$ python conformance/run.py -- my-plugin
```

Run from a clone of this repository, or copy `conformance/` and `plugins/`
next to your plugin — the kit is standard library only and imports nothing
from the reference host. Without `--role` it tries every set of cases and
tells you which one you satisfy; `conformance/README.md` explains roles.

Failing something you did not intend to implement is information, not a
verdict. Failing `stdout-is-protocol-only` is a verdict.

## Then what

`SPEC.md` is the normative text — twenty-eight clauses, each with the
reasoning that produced it. This page is the parts a first plugin needs; the
spec is what settles an argument.
