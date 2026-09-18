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
