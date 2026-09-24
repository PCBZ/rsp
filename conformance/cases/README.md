# Conformance cases

A case is data: a request, an expected response, and the clause it exercises.

```json
{ "name": "...", "clause": "S1", "plugin": "echo",
  "request":  { ... },
  "expect":   { "response": { ... } } }
```

`plugin` names a **role**, not an implementation. `echo` is the reference
plugin, whose verdicts are selected by content markers; `gitleaks` is any
adapter over that binary, and the runner resolves a role to every one
installed — so a case runs against all of them and they have to agree. These
cases named `rsp-gitleaks-ts` until a second adapter existed, at which point
seven files asserting nothing about TypeScript could only be run against
TypeScript.

Each plugin ships a `conformance.json` saying what runs it, so an adapter in a
new language is a new directory. That file is a convention of this kit and not
part of the protocol: a plugin cannot declare how to start it, because you
have to start it to hear the declaration.

## Host cases

Every case here is a **plugin case**: a request, and the response a conforming
plugin must give. A requirement on the *host* needs the other direction, and
those live in `conformance/host/`:

```json
{ "name": "...", "clause": "E1", "kind": "host",
  "plugin": { "behaviour": "crash" },
  "request": { ... },
  "expect":  { "verdict": "BLOCK", "content": "unchanged" } }
```

`plugin` is a script for `plugins/rsp-replay`, which answers with whatever the
case wrote down — or crashes, hangs, or prints nonsense on request. A real
plugin will not fail on cue, and a clause about failure cannot be tested by a
plugin that works.

A host is a library rather than a process, so the kit cannot spawn one: the
runner is per host. `tests/test_host_conformance.py` is this repository's, and
it is twenty lines.

`SPEC.md` section 10 says which clauses each kind still leaves uncovered, and
why.
