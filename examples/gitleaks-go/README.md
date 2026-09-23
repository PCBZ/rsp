# rsp-gitleaks-go

An RSP plugin in Go: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The same wrapper as `examples/gitleaks-ts`, in another language, over the same
tool — so that "a plugin is a command, whatever it is written in" is
demonstrated rather than argued. The seven conformance cases under
`conformance/cases/gitleaks/` were written against the TypeScript one and pass
against this one unchanged.

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | go run .
{"rsp_version":"0.1","name":"rsp-gitleaks-go","version":"0.1.0+8.30.1",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`. No dependencies. Build it before
using it as a plugin — `go run` compiles on every call, and a call is a
process (Q6).

Nothing converts here: a Go string is a byte slice, so `content[start:end]`
already means what S1 says. The coordinate quirks that do need care are
gitleaks' own, and `gitleaks.go` documents them where the arithmetic is.
