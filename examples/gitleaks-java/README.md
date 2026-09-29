# rsp-gitleaks-java

An RSP plugin in Java: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The sixth and last adapter over the same tool. The thirteen cases in
`examples/gitleaks-offsets.json` and the seven under
`conformance/cases/gitleaks/` run against it unchanged.

```console
$ make && echo '{"rsp_version":"0.1","hook":"handshake"}' | ./rsp-gitleaks-java
{"rsp_version":"0.1","name":"rsp-gitleaks-java","version":"0.1.0+8.30.1",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`, and a JDK. `make` downloads
gson from Maven Central against a pinned checksum — Java has no JSON in its
standard library, and the jar is not committed here for the reason cJSON is
not committed beside `examples/gitleaks-c`.

## What the measurement said, against what was expected

This adapter was added expecting the JVM to be the data point that makes
spawn-per-call untenable, and it is not:

| | per handshake |
|---|---|
| `true` (the floor) | 2.3 ms |
| C | 2.9 ms |
| **Java, compiled classes** | **44 ms** |
| Node | 75 ms |
| **Java, `java Main.java`** | **317 ms** |

A compiled JVM plugin starts *faster than Node*. What costs is not the
runtime but the build step's absence: running the source directly, the mode
that needs no toolchain at all, is seven times slower. Q6 asks what the
handshake costs per ingest; the answer here is that it depends on whether
the plugin was built, not on which language it was written in.

The launcher `make` writes is a two-line shell script. A host points at that.

## The string model, again

A Java `String` is UTF-16 code units, so `length()` is neither characters nor
bytes: an emoji is one character, two units and four bytes. Only the last is
what a span means. The content is encoded once in `Protocol.respond` and
never indexed as text — the same discipline `examples/gitleaks-ts` needs, in
a language whose indices look more like character indices than they are.

Where it is *better* than C: a `String` carries a length, so content holding
a NUL is judged whole. `examples/gitleaks-c` has to refuse that request,
because a `char *` ends there and the chunk would reach gitleaks shorter than
the host sent it. `testdata/requests.sh` asserts the difference rather than
describing it.

## The deadlock, a fourth time

`ProcessBuilder` pumps nothing. Writing the chunk and then reading the report
deadlocks against a tool that fills its stdout pipe before draining stdin, so
stdin is fed from a thread — as in `examples/gitleaks-rs`, and for the reason
`examples/gitleaks-c` polls both pipes. Go and Node are the only two of the
six that are handed this.
