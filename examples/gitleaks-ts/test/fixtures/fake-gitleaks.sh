#!/bin/sh
# A gitleaks that answers as the test chose. It drains stdin first: exiting
# unread fails the caller's write instead, or not, depending on the OS.
cat >/dev/null
printf '%s' "${FAKE_GITLEAKS_REPORT:-}"
exit "${FAKE_GITLEAKS_EXIT:-0}"
