# rsp-gitleaks-go

An RSP plugin in Go: wraps the unmodified [gitleaks](https://github.com/gitleaks/gitleaks)
binary and reports what it finds as byte offsets.

The same wrapper as `examples/gitleaks-ts`, in another language, over the same
tool. It exists so that the protocol's central claim is demonstrated rather
than argued: the seven conformance cases under `conformance/cases/gitleaks/`
were written against the TypeScript one and pass against this one unchanged,
and the corpus suite checks that both return the same verdict and the same
bytes for every file gitleaks tests itself with.

## Running it

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | go run .
{"rsp_version":"0.1","name":"rsp-gitleaks-go","version":"0.1.0+8.30.1",...}
```

Requires `gitleaks` on `PATH`, or `RSP_GITLEAKS` pointing at it. No
dependencies: the standard library is the whole list.

## Configure a host to use it

```yaml
plugins:
  - name: gitleaks
    command: ["/path/to/rsp-gitleaks-go"]
    hooks: [on_chunk]
```

Build it first — `go build .` — rather than paying `go run`'s compile on every
call. A plugin is one process per call (Q6).

## Where the offsets come from

Nothing converts. A Go string is a byte slice, so `content[start:end]` already
means what SPEC.md S1 says it means, and this is the language that choice was
made for: Python, JavaScript and Java all have to convert, and Go does not.

What does need care is gitleaks' own coordinate system, which the TypeScript
adapter documents in the same terms: its columns count from the newline byte
ending the previous line, so only the first line's are the 1-based columns
anyone would assume, and `EndColumn` belongs to `EndLine`, which differs from
`StartLine` whenever a finding spans lines.
