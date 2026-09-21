#!/bin/sh
# Stands in for gitleaks: reads the chunk the way a real scan does, writes no
# report, and exits with the status the test asked for.
#
# Draining stdin is the point. A stand-in that exits without reading makes the
# write fail rather than the status, and which of the two the adapter sees
# depends on the operating system — so a test built on `false` asserts a
# different thing on Linux than on macOS. Here the status is the only variable.
cat >/dev/null
exit "${FAKE_GITLEAKS_EXIT:-0}"
