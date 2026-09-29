# rsp-gitleaks-c

An RSP plugin in C: wraps the unmodified
[gitleaks](https://github.com/gitleaks/gitleaks) binary.

The fifth adapter over the same tool. The thirteen cases in
`examples/gitleaks-offsets.json` and the seven under
`conformance/cases/gitleaks/` run against it unchanged.

```console
$ make && echo '{"rsp_version":"0.1","hook":"handshake"}' | ./rsp-gitleaks-c
{"rsp_version":"0.1","name":"rsp-gitleaks-c","version":"0.1.0+8.30.1",...}
```

Needs `gitleaks` on `PATH`, or `RSP_GITLEAKS`, and cJSON from the system —
`brew install cjson`, `apt-get install libcjson-dev`. Nothing third-party is
vendored here: cJSON is 3512 lines against a core of 854, and committing it
would make this repository responsible for tracking someone else's fixes.

A host should point at the built binary. There is no running from source, so
the conformance kit skips this adapter until `make` has been run, where the
other four need no build step.

## What this language has that the others do not

**Nothing throws.** Every failure is a return value, and a caller that ignores
one carries on with whatever was in the buffer. D3 says every error path ends
in BLOCK; in the other four a path nobody wrote still crashes the process and
the host blocks. Here it does not. Every function returns 0 or -1, `main`
exits non-zero on either, and stdout stays empty when it does.

**A NUL-terminated string cannot hold every valid chunk.** JSON permits
`\u0000` inside a string. cJSON hands back a `char *`, which stops there, so
content carrying one arrives shorter than the host sent it — and the offsets
gitleaks then reports index the truncated text while the host applies them to
the whole. That redacts the wrong bytes, which is worse than missing a
secret. `rsp_escapes_a_nul` refuses the request instead: this plugin cannot
represent that chunk and says so (E1). The other four carry a length and are
unaffected.

**Some mistakes no assertion can see.** `gl_to_spans` checks `strlen(Match)`
against the span's width before `memcmp` reads it. Delete that check and every
test still passes — the comparison reads past Match's terminator and usually
differs anyway. Under `-fsanitize=address` the same run stops on
`heap-buffer-overflow`, so CI builds and runs the suite twice, and
`test_gitleaks.c` keeps a finding whose Match is a strict prefix of its span
purely to give the sanitizer something to walk into.

**Both pipes are polled.** Writing the chunk and then reading the report would
deadlock against a tool that fills stdout before draining stdin. Go and Node
do this for you and Rust spawns a thread; here it is the loop in `spawn.c`.

Polling is necessary and was not sufficient: `POLLOUT` means some room in the
pipe, and a blocking write of more than that waits for the child to take all
of it, which it cannot while its own stdout is full. The write end is
non-blocking, and whether the whole chunk arrived is settled after the loop —
a tool that read part of it judged something other than what the host sent,
whatever its exit status says.

That file exists for the reason `rsp/process.py` is apart from the layers
above it: a pipe is not a report. It starts a command, feeds it, drains it
and reaps it, and reports the exit status without judging it — which of them
mean "found" is gitleaks' convention and belongs to `gitleaks.c`. The other
four adapters get all of this from a standard library in ten to sixteen
lines, which is why only this one has a file for it.
