#!/bin/sh
# Stands in for gitleaks: writes the report it was handed and exits with the
# status the test asked for. Both arrive as arguments rather than in the
# environment, because tests run on threads of one process and an environment
# is shared by all of them.
#
# $1 report  $2 exit status  $3 bytes of blank padding
#
# Draining stdin before writing is what a real scan does, and doing it at all
# is the point: a stand-in that exits without reading makes the write fail
# rather than the status, and which of the two the caller sees depends on the
# operating system.
#
# The padding is written first, and is how a test fills the stdout pipe while
# stdin is still unread — the one order that deadlocks a parent writing the
# chunk from its own thread. It is generated here rather than passed in
# because an argument has a length limit and a pipe buffer is near it.
if [ "${3:-0}" -gt 0 ]; then
  head -c "$3" /dev/zero | tr '\0' ' '
fi
cat >/dev/null
printf '%s' "${1:-}"
exit "${2:-0}"
