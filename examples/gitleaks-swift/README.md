# rsp-gitleaks-swift

An RSP plugin in Swift: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The seventh and last adapter. The thirteen cases in
`examples/gitleaks-offsets.json` and the seven under
`conformance/cases/gitleaks/` run against it unchanged.

```console
$ make && echo '{"rsp_version":"0.1","hook":"handshake"}' | .build/release/rsp-gitleaks-swift
{"rsp_version":"0.1","name":"rsp-gitleaks-swift","version":"0.1.0+8.30.1",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`, and a Swift toolchain. JSON is
in Foundation, so nothing is downloaded — unlike `examples/gitleaks-c` and
`examples/gitleaks-java`, which fetch a library.

## The discipline the other six keep by hand

Each of the other READMEs says the content is encoded once and never indexed
as text. That is the author remembering. Here it is the compiler:

```
error: 'subscript(_:)' is unavailable: cannot subscript String with an Int,
       use a String.Index instead.
```

Every other adapter can make the mistake S1 exists to prevent — Go is right
by accident because its strings are bytes, Rust panics, C truncates at a NUL,
and TypeScript, Python and Java each return the wrong text with nothing
raised. In Swift the line does not build, and `content.utf8` is the only road
to a byte.

It is also a fourth string model: `count` is extended grapheme clusters, so
`密钥 AKIALALEMEL33243OLIB` is 23 clusters and 27 bytes, where the others
count bytes, code points or UTF-16 units.

## What the decoder does, which is not a list of leniencies

`Codable` is how Swift reads JSON, so the request and the report are structs
rather than dictionaries of `Any`. Measuring `JSONDecoder` against T4 turned
up something worse than leniency:

```
{"a":01}                  refused     — a is declared
{"hook":"x","count":01}   accepted    — count is not
```

**It validates only the parts of the document it maps to a type.** How strict
it is depends on the reader's own struct, so two Swift plugins can disagree
about one message. `JSONSerialization` refuses both.

So `StrictJson` reads everything T4 names from the bytes, including what the
decoder would have caught on a field it happened to want.
`conformance/cases/json/t4-a-malformed-number-under-an-unread-field.json`
holds every implementation to it.

## What it does not add

The deadlock is the same: Foundation's `Process` pumps nothing, so stdin goes
out on a queue of its own, which makes this the fifth of seven adapters to
arrange that itself. stderr is inherited, as in C and Rust. Startup is
between Go's and Python's, and the error model is `throws`.
