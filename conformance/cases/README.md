# Conformance cases

One file per clause in `SPEC.md`. A case is data: a request, an expected
response, and the clause it exercises. No runner yet — that is #19.

```json
{ "name": "...", "clause": "S1", "plugin": "rsp-echo",
  "request":  { ... },
  "expect":   { "response": { ... } } }
```

`plugin` names the plugin a case is written against. These cases target the
reference plugin, whose verdicts are selected by content markers. Cases that any
plugin must pass — framing, stdout discipline, span validity — become
plugin-agnostic in #19.
