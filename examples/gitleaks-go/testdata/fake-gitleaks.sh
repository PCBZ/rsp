#!/bin/sh
# Stands in for gitleaks: reads the chunk the way a real scan does, writes the
# report it was handed, and exits with the status the test asked for.
#
# Draining stdin is the point. A stand-in that exits without reading makes the
# write fail rather than the status, and which of the two the caller sees
# depends on the operating system.
cat >/dev/null
printf '%s' "${FAKE_GITLEAKS_REPORT:-}"
exit "${FAKE_GITLEAKS_EXIT:-0}"
