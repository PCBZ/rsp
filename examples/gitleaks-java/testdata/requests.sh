#!/bin/sh
# One object in, and what that rules out. Run through the built launcher
# rather than the classes, because what main does with a malformed stream is
# not reachable from a unit test.
set -u
binary=${1:-./rsp-gitleaks-java}
failures=0

expect() {
    printf '%b' "$3" | "$binary" >/dev/null 2>&1
    got=$?
    if [ "$got" != "$1" ]; then
        echo "FAIL $2: exited $got, wanted $1"
        failures=$((failures + 1))
    fi
}

ok='{"rsp_version":"0.1","hook":"on_chunk","content":"x"}'
expect 0 "an ordinary request" "$ok"
expect 1 "a NUL byte and more after it" "$ok\\0extra"
expect 1 "trailing characters after the object" "$ok trailing"

# Not an error here, and the contrast is the point: examples/gitleaks-c has to
# refuse this one, because a char * ends at the NUL and the chunk would reach
# gitleaks shorter than the host sent it. A String carries a length, so the
# content is judged whole.
expect 0 "an escaped NUL in the content" \
    '{"rsp_version":"0.1","hook":"on_chunk","content":"a\\u0000b"}'

# Bounded, because failing here is a hang rather than a wrong answer.
loud=$(cd "$(dirname "$0")/../.." && pwd)/testdata/loud-gitleaks.sh
printf '%b' "$ok" | RSP_GITLEAKS=$loud "$binary" >/dev/null 2>&1 &
pid=$!
(sleep 30; kill -9 "$pid" 2>/dev/null) 2>/dev/null &
guard=$!
wait "$pid"
got=$?
{ kill "$guard"; wait "$guard"; } 2>/dev/null
if [ "$got" != 0 ]; then
    echo "FAIL a tool with 400KB to say on stderr: exited $got, wanted 0"
    failures=$((failures + 1))
fi

[ "$failures" = 0 ] && echo ok
exit $((failures > 0))
