#!/bin/sh
# A chunk bigger than a pipe buffer, against tools that mishandle it.
#
# Each case is bounded: a failure here is a hang, not an assertion, so the
# binary runs in the background with a watchdog and an unfinished run reads
# as the failure it is.
set -u
binary=${1:-./rsp-gitleaks-c}
fake=$(cd "$(dirname "$0")" && pwd)/fake-gitleaks.sh
failures=0

chunk=$(head -c 200000 /dev/zero | tr '\0' x)
request="{\"rsp_version\":\"0.1\",\"hook\":\"on_chunk\",\"content\":\"$chunk\"}"

bounded() {
    printf '%s' "$request" | "$binary" >/dev/null 2>&1 &
    pid=$!
    (sleep 25; kill -9 "$pid" 2>/dev/null) 2>/dev/null &
    guard=$!
    wait "$pid"
    got=$?
    { kill "$guard"; wait "$guard"; } 2>/dev/null
    return $got
}

check() {
    if [ "$2" != "$1" ]; then
        echo "FAIL $3: exited $2, wanted $1"
        failures=$((failures + 1))
    fi
}

RSP_GITLEAKS=$fake FAKE_GITLEAKS_PAD=200000 FAKE_GITLEAKS_REPORT= FAKE_GITLEAKS_EXIT=0 \
    bounded
check 0 $? "a tool that fills stdout before reading the chunk"

RSP_GITLEAKS=$fake FAKE_GITLEAKS_DEAF=64 FAKE_GITLEAKS_REPORT= FAKE_GITLEAKS_EXIT=0 \
    bounded
check 1 $? "a tool that reads part of the chunk and exits clean"

[ "$failures" = 0 ] && echo ok
exit $((failures > 0))
