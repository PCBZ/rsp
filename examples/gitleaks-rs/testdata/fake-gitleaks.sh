#!/bin/sh
# Stands in for gitleaks: writes the report it was handed and exits with the
# status the test asked for. Both arrive as arguments rather than in the
# environment, because tests run on threads of one process and an environment
# is shared by all of them.
#
# $1 report  $2 exit status  $3 "early" to write before draining stdin
#
# Draining stdin at all is the point of the default: a stand-in that exits
# without reading makes the write fail rather than the status, and which of
# the two the caller sees depends on the operating system. "early" is the
# other order, which no version of gitleaks uses and every adapter has to
# survive anyway — it is what fills the stdout pipe under a parent that is
# still writing.
if [ "${3:-}" = early ]; then
  printf '%s' "${1:-}"
  cat >/dev/null
else
  cat >/dev/null
  printf '%s' "${1:-}"
fi
exit "${2:-0}"
