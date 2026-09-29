#!/bin/sh
# What main must refuse before anything downstream sees it. Each case is a
# whole request that a reader stopping at the first NUL, or at the end of the
# first object, would answer instead of refusing.
set -u
binary=${1:-./rsp-gitleaks-c}
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
expect 1 "an escaped NUL in the content" '{"rsp_version":"0.1","hook":"on_chunk","content":"a\\u0000b"}'

[ "$failures" = 0 ] && echo ok
exit $((failures > 0))
