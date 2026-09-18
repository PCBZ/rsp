# RSP — RAG Security Protocol, v0.1 (draft)

**Status: skeleton.** Every clause below is backed by a call site in this
repository — `rsp/guards.py` (#1) for the host side, `plugins/rsp-echo/main.py`
(#2) for the plugin side. Anything not yet exercised by one is in [Open
questions](#8-open-questions), not stated as a requirement.

Key words MUST, MUST NOT, SHOULD, and MAY are as in RFC 2119. Every normative
clause carries a Rationale, because a rule whose reason is lost gets deleted or
inverted by the next person to read it.

---

## 1. Roles

**Host** — the RAG system. Calls plugins at defined points and acts on what they
return. Implements no detection.

**Plugin** — a security tool. Receives content, returns a verdict. Runs as a
subprocess.

**R1.** A host MUST NOT require a plugin to link against any library.
*Rationale: the tools worth wrapping are binaries in other languages. A plugin
is a process that reads JSON and writes JSON; `rsp-echo` uses only its
language's standard library, and any plugin can.*

---

## 2. Transport

**T1.** The host MUST invoke a plugin as a subprocess, write exactly one JSON
object to its stdin, and read exactly one JSON object from its stdout. The
plugin then exits.
*Rationale: one call, one process. A stream implies a persistent process and the
framing rules that go with it; v0.1 does not need them (Q6).*

**T2.** A plugin MUST write nothing to stdout but that one response object.
Diagnostics MUST go to stderr.
*Rationale: stdout is the protocol channel. A debug line printed there corrupts
the response, and the host cannot tell the difference.*
Fixture: `stdout-is-protocol-only`

**T3.** Both sides MUST ignore fields they do not recognize, in every message.
*Rationale: without this, adding an optional field is a breaking change, so in
practice nothing is ever added.*
Fixture: `unknown-fields-ignored`

---

## 3. Handshake

**H1.** Before the first content call, the host MUST invoke the plugin with
`{"hook": "handshake"}` and read its declaration.
*Rationale: its own invocation rather than the opening message of a stream,
which would presume a persistent process (T1).*
Fixture: `handshake`

**H2.** A declaration MUST contain `rsp_version`, `name`, `version`, and
`hooks`. It MAY contain `deterministic` (default `false`) and
`max_inline_bytes`.
*Rationale: `hooks` tells the host what not to call; `version` is part of the
cache key; `deterministic` decides whether caching is legal at all — a plugin
backed by a model must be able to say no. Everything else is speculative and is
left out until a plugin needs it.*

**H3.** The host MUST NOT invoke a plugin on a hook it did not declare.

---

## 4. Hooks

| Hook | When | `BLOCK` means |
|---|---|---|
| `on_chunk` | After chunking, before embedding | Never indexed |
| `on_retrieve` | After a retrieval hit, before the content reaches a model | Dropped from this result set |

**K1.** Content blocked at `on_chunk` MUST NOT be embedded or stored.
*Rationale: the reason this protocol exists. Everything shipping today
intercepts after storage, where content stays recoverable through embedding
inversion. This is the only hook where blocked means it was never there.*

**K2.** `BLOCK` at `on_retrieve` removes the item from the result set. It does
not remove anything already stored.
*Rationale: the same word means different things on either side of the vector
store, and a plugin author who assumes otherwise believes they are destroying
data when they are not.*

`on_response` is **reserved**, not specified: the reference host has no seam for
it (#23). `on_source` and `on_document` are reserved.

---

## 5. Request

```json
{ "rsp_version": "0.1",
  "hook": "on_chunk",
  "content": "AWS_SECRET_ACCESS_KEY=wJalr...",
  "metadata": { "source": "notes/aws.md", "node_id": "..." } }
```

**Q1.** `content` MUST be a JSON string carrying the text to inspect.
`metadata` is advisory: a plugin MAY use it and MUST NOT require it.
*Rationale: a plugin that needs host-specific metadata only works with that
host, which defeats the point.*

---

## 6. Response

```json
{ "verdict": "REDACT",
  "spans": [{ "start": 24, "end": 64, "type": "aws-secret-key" }],
  "replacement": "[REDACTED:aws-secret-key]",
  "severity": "critical" }
```

**V1.** `verdict` MUST be exactly one of `ALLOW`, `FLAG`, `REDACT`, `BLOCK`.
*Rationale: four outcomes, no error reply. A plugin that fails crashes, and a
crashed plugin is already defined (E1) — a fifth kind of response would be one
more thing for every plugin author to get wrong.*
Fixtures: `verdict-allow`, `verdict-flag`, `verdict-block`

**V2.** `ALLOW` MUST be valid with no other field present.
*Rationale: the common case is the cheap one.*
Fixture: `verdict-allow`

**V3.** `REDACT` MUST carry `spans` and `replacement`.
Fixture: `verdict-redact`

**V4.** `FLAG` and `BLOCK` SHOULD carry `reason`; any verdict MAY carry
`severity`.

---

## 7. Spans

**S1.** A span MUST be a half-open range `[start, end)` of **byte offsets into
the UTF-8 encoding** of `content`.
*Rationale: character offsets have no cross-language meaning — Python counts
code points, JavaScript counts UTF-16 units, Go indexes bytes. In `"密钥
secret"`, `secret` begins at character 3 and byte 7; slicing bytes with the
character index splits the first character and raises. Bytes are the only unit
every language produces identically. Half-open because `end - start` is the
length, which removes an off-by-one from every implementation.*
Fixture: `spans-are-utf8-bytes`

**S2.** A plugin MUST report every occurrence it finds, not only the first.
Fixture: `spans-multiple-occurrences`

**S3.** The host MUST validate every span before using it: within `content`,
`start <= end`, and both ends on a UTF-8 character boundary. An invalid span
MUST be treated as a plugin error (E1).
*Rationale: plugins are untrusted. Without validation, a malicious plugin kills
the host with a decoding exception.*

**S4.** Applying spans is the runtime's work. A host adapter MUST NOT be
required to interpret them.
*Rationale: every host implementation that touches offsets is another chance to
get them wrong; `rsp/guards.py` receives finished content instead.*

---

## 8. Errors

**E1.** A plugin that crashes, times out, exceeds an output limit, or returns
unparseable or invalid output MUST be treated as `BLOCK`, unless that plugin's
configuration says otherwise.
*Rationale: failing open makes the failure invisible — a misconfigured plugin
looks exactly like a clean corpus. An over-blocked chunk can be re-indexed; an
embedded credential cannot be un-embedded.*

**E2.** `Runtime.evaluate` MUST NOT raise. Every failure becomes a verdict, and
by E1 that verdict is `BLOCK`.
*Rationale: if the host had to catch exceptions, every host implementation would
carry error-handling that must be correct for the protocol's central guarantee
to hold. Keeping it in the runtime means no adapter can omit it. Raised on #24.*

---

## 9. Open questions

Not specified. Each is tracked in the [wiki](https://github.com/PCBZ/rsp/wiki/Open-Questions)
and will be settled by a fixture, not by prose.

| | |
|---|---|
| Q1 | Overlapping `REDACT` spans from different plugins |
| Q2 | Whether plugin N+1 sees original or redacted content |
| Q3 | Whether `on_retrieve` reports dropped items to the user |
| Q4 | Timeout default |
| Q6 | Spawn-per-call vs a persistent process, and what the handshake costs per ingest |
| Q8 | What provenance may be recorded on a stored node |

Verdict composition across several plugins — strictest wins, `BLOCK`
short-circuits — is **not specified here**. No call site exercises it yet; it
arrives with the runtime (#7).
