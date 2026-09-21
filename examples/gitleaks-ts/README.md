# rsp-gitleaks-ts

An RSP plugin in TypeScript. Wraps the **unmodified** [gitleaks](https://gitleaks.io)
binary and translates what it finds into the spans a host should mask.

gitleaks is not vendored here and not linked as a library. It is invoked as a
subprocess, exactly as distributed, so its detection rules stay upstream's and
this plugin depends on two public interfaces: the `gitleaks stdin` command, and
the field names in its JSON report.

That makes this a process that spawns a process — which is why a host kills a
plugin's whole process group rather than just the plugin.

```
src/gitleaks.ts   run the binary; convert its line/column positions to bytes
src/protocol.ts   the request and response shapes, and the mapping between them
src/main.ts       read stdin, write stdout, exit
test/             the conversion, which is the only part with logic
```

## Running it

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' \
    | node --experimental-strip-types src/main.ts
{"rsp_version":"0.1","name":"rsp-gitleaks-ts","version":"0.1.0+8.30.1",...}
```

Requires `gitleaks` on `PATH`, or `RSP_GITLEAKS` pointing at it. No build step:
Node runs TypeScript directly from 22.6 onward, and `typescript` and
`@types/node` are development dependencies for type checking only.

## Configure a host to use it

```yaml
plugins:
  - name: gitleaks
    command: ["node", "--experimental-strip-types", "examples/gitleaks-ts/src/main.ts"]
    hooks: [on_chunk]
```

## What the adapter actually has to get right

**Positions.** gitleaks reports a line plus a column, and its columns are
*byte* columns — they come from Go regexp match indices, and a Go string is a
byte slice. So converting to what `SPEC.md` S1 asks for is arithmetic and needs
no encoding knowledge:

```
start = byte offset of the line + StartColumn - 1
end   = byte offset of the line + EndColumn
```

`StartColumn` is 1-based and `EndColumn` inclusive, which lands exactly on S1's
half-open `[start, end)`. That a tool written without this protocol in mind
already produces the unit S1 requires is the best evidence available that the
unit was chosen well.

**Its version, not just ours.** The handshake reports `0.1.0+8.30.1`. A cache
key contains the plugin version (`D4`), and for a wrapper it is the wrapped
tool that decides verdicts: gitleaks adding a rule changes the answer for
content that has not changed. Keyed on the adapter's version alone, a cache
would keep serving the old one.

**Its judgement, not ours.** `AKIAIOSFODNN7EXAMPLE` is the key AWS prints in
its own documentation, and gitleaks allowlists anything ending `EXAMPLE`. This
plugin returns ALLOW for it, because a wrapper whose verdicts differ from the
tool it wraps is not wrapping it. `conformance/cases/gitleaks/` has that as a
case, and it exists because an earlier version of this example used a
hand-written regex and got it wrong.

## Two kinds of test

`test/gitleaks.test.ts` checks the conversion. Its input is a report, which is
data, so it needs no binary and runs in milliseconds.

`conformance/cases/gitleaks/*.json` are fed to this plugin across a real
process boundary by the host's own harness, which does need the binary. Those
answer a different question: not "is the arithmetic right" but "does the tool
say what we think it says".
