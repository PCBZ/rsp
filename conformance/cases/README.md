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

## Host cases do not exist yet

Every case here is a **plugin case**: a request, and the response a conforming
plugin must give. That shape cannot express a requirement on the host — H4 (a
declaration may lower a host limit, never raise one), S3 (validate a span
before using it), K1 (blocked content is never embedded), E1–E3 (a failure
becomes BLOCK). No plugin response settles any of them.

`SPEC.md` section 10 lists those clauses as uncovered. That is the honest
state: a clause tested only by our own unit tests has been verified for this
implementation and for no other.
