# rsp-gitleaks-rs

An RSP plugin in Rust: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The third adapter over the same tool, after `examples/gitleaks-{ts,go}`. Two
of anything is a coincidence; the seven cases under
`conformance/cases/gitleaks/` were written against the TypeScript one and pass
against this one unchanged, which is the claim being made.

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | cargo run --quiet
{"deterministic":true,"hooks":["on_chunk","on_retrieve"],"name":"rsp-gitleaks-rs",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`. Two dependencies, both serde —
the first adapter here to have any, which is the point of it being third.

A host should point at a built binary rather than at `cargo run`. The
conformance kit runs it from source by default so that a clone needs no build
step, and CI builds it once and sets `RSP_PLUGIN_GITLEAKS_RS` — see
`conformance.json`.

Two things this language makes explicit that the others hide:

A byte offset that lands inside a character **panics** here, where Go quietly
produces mojibake. So `usable` is not defensive; it is what stands between a
malformed report and a plugin that dies instead of answering. Rust says out
loud what S3 is for.

Nothing pumps a child's stdin for you. Go's `cmd.Stdin` and Node's streams
both do it on something other than the calling thread, so neither can deadlock
against a tool that writes its report before draining the chunk. This one
spawns the writer itself, and `tests/protocol.rs` provokes exactly that order
— the test hangs forever if the thread is removed.
