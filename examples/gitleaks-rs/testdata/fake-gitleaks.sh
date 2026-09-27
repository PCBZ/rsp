#!/bin/sh
# A gitleaks that answers as the test chose: $1 report, $2 exit status, and
# $3 bytes of padding to fill stdout before stdin is read. A count, because
# padding that size as an argument nears the length limit.
#
# It drains stdin: exiting unread fails the caller's write instead, or not,
# depending on the OS.
if [ "${3:-0}" -gt 0 ]; then
  head -c "$3" /dev/zero | tr '\0' ' '
fi
cat >/dev/null
printf '%s' "${1:-}"
exit "${2:-0}"
