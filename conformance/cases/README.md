# Conformance cases

A case is data: a request, an expected response, and the clause it exercises.
No runner beyond the test suite yet.

Coverage is partial and is meant to be read as debt. Every clause a plugin-side
case can settle has one; the rest are host-side (span validation, blocked
content never reaching storage, errors becoming `BLOCK`) and cannot be tested
until the runtime exists. `SPEC.md` lists exactly which ones, and a clause
still lacking evidence when this version is tagged is deleted rather than
shipped.

```json
{ "name": "...", "clause": "S1", "plugin": "echo",
  "request":  { ... },
  "expect":   { "response": { ... } } }
```

`plugin` names a **role**, not an implementation: which kind of plugin can
answer the case. `echo` is the reference plugin, whose verdicts are selected by
content markers. `gitleaks` is any adapter over that binary, and the runner
resolves it to every one installed — so a case runs against all of them and
they have to agree.

That is the difference between testing a protocol and testing a program. These
cases named `rsp-gitleaks-ts` until a second adapter over the same tool existed,
at which point seven case files asserting nothing about TypeScript could only be
run against TypeScript.

## How the runner finds a plugin

Each one ships a `conformance.json` beside its source:

```json
{ "name": "rsp-gitleaks-go", "role": "gitleaks",
  "source": ["go", "run", "-C", "{dir}", "."],
  "toolchain": ["go"], "wraps": ["gitleaks"] }
```

`{dir}` is the directory the file is in. An adapter in a new language is a new
directory; the runner changes not at all.

**This file is a convention of this kit, not part of RSP.** A plugin cannot
declare how to start it — you have to start it to hear the declaration — so
that knowledge lives in configuration, which is the host's business.

## Two kinds of case, one of which does not exist yet

Every case here is a **plugin case**: a request, and the response a conforming
plugin must give. That shape cannot express a requirement on the host — H4
(a declaration may lower a host limit, never raise one), S3 (validate a span
before using it), K1 (blocked content is never embedded), E1–E3 (a failure
becomes BLOCK). No plugin response settles any of them.

Those need a **host case**: a declaration or a plugin response as input, and
the host behaviour required in return. Deferred rather than guessed at here, because
the shape should be designed against a host that exists.

Until then, `SPEC.md` §10 lists host-side clauses as uncovered. That is the
honest state, not an oversight: a clause tested only by our own unit tests has
been verified for this implementation and for no other.
