# Conformance cases

A case is data: a request, an expected response, and the clause it exercises.
No runner yet — that is #19.

Coverage is partial and is meant to be read as debt. Every clause a plugin-side
case can settle has one; the rest are host-side (span validation, blocked
content never reaching storage, errors becoming `BLOCK`) and cannot be tested
until the runtime exists. `SPEC.md` lists exactly which ones, and #20 deletes
any clause still lacking evidence at freeze time.

```json
{ "name": "...", "clause": "S1", "plugin": "rsp-echo",
  "request":  { ... },
  "expect":   { "response": { ... } } }
```

`plugin` names the plugin a case is written against. These cases target the
reference plugin, whose verdicts are selected by content markers. Cases that any
plugin must pass — framing, stdout discipline, span validity — become
plugin-agnostic in #19.

## Two kinds of case, one of which does not exist yet

Every case here is a **plugin case**: a request, and the response a conforming
plugin must give. That shape cannot express a requirement on the host — H4
(a declaration may lower a host limit, never raise one), S3 (validate a span
before using it), K1 (blocked content is never embedded), E1–E3 (a failure
becomes BLOCK). No plugin response settles any of them.

Those need a **host case**: a declaration or a plugin response as input, and
the host behaviour required in return. Deferred to #19 rather than guessed at
here, because the shape should be designed against a host that exists.

Until then, `SPEC.md` §10 lists host-side clauses as uncovered. That is the
honest state, not an oversight: a clause tested only by our own unit tests has
been verified for this implementation and for no other.
