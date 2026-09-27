# rsp-gitleaks-py

An RSP plugin in Python: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The fourth adapter over the same tool, after `examples/gitleaks-{ts,go,rs}`.
The thirteen cases in `examples/gitleaks-offsets.json` and the seven under
`conformance/cases/gitleaks/` run against it unchanged.

```console
$ echo '{"rsp_version":"0.1","hook":"handshake"}' | python3 main.py
{"rsp_version": "0.1", "name": "rsp-gitleaks-py", "version": "0.1.0+8.30.1", ...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`. Standard library only.

It does **not** import `rsp`, and the host gets no shortcut for sharing its
language: same spawn, same handshake, same pipe. A plugin written in the
host's language is a plugin.

## What this language gets wrong that the others cannot

A `str` is indexed by code point. Sliced with the byte offsets S1 requires,
`content[start:end]` returns the wrong text for anything that is not ASCII —
with nothing raised, nothing truncated, and no sign that it happened.

```
content   密钥 AKIALALEMEL33243OLIB
span      [7, 27)
bytes     AKIALALEMEL33243OLIB      what the host will redact
str       LALEMEL33243OLIB          what a str slice returns
```

Go is right by construction, Rust panics, TypeScript truncates. This is the
one that would report a key redacted and leave it in the chunk. So the
content is encoded once, in `protocol.respond`, and every offset below that
line indexes bytes. `tests/test_gitleaks.py` asserts the trap rather than
describing it.

What Python makes easy in return: `subprocess.run` pumps the child's stdin
and stdout for you, so the deadlock `examples/gitleaks-rs` spawns a thread to
avoid cannot happen here.
