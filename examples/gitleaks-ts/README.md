# rsp-gitleaks-ts

An RSP plugin in TypeScript: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary. Not vendored, not
imported as a library — invoked as a subprocess, so its detection rules stay
upstream's problem and this depends on two public interfaces: the `gitleaks
stdin` command and the field names of its JSON report.

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | node src/main.ts
{"rsp_version":"0.1","name":"rsp-gitleaks-ts","version":"0.1.0+8.30.1",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`. No build step: Node 24 runs
TypeScript directly, and `typescript` and `@types/node` are development
dependencies for type checking only.

## Tests

`test/gitleaks.test.ts` is the conversion from gitleaks' positions to byte
offsets, and needs no binary: a report is data. What the binary emits for new
content is a different question, answered by `conformance/cases/gitleaks/` in
CI. `test/binary.test.ts` covers what happens when gitleaks cannot run, using
a shell script that fails on request.
