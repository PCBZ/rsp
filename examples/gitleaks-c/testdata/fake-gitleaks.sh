#!/bin/sh
# A gitleaks that answers as the test chose.
#
# FAKE_GITLEAKS_PAD writes that many blanks before reading anything, which is
# how a test fills the caller's stdout pipe while its stdin is still unread —
# the one order that deadlocks a parent writing a chunk from the same thread.
# No gitleaks does this; every adapter has to survive it.
#
# FAKE_GITLEAKS_DEAF reads that many bytes and exits, leaving the rest of the
# chunk unread and unjudged.
if [ "${FAKE_GITLEAKS_PAD:-0}" -gt 0 ]; then
  head -c "$FAKE_GITLEAKS_PAD" /dev/zero | tr '\0' ' '
fi
if [ "${FAKE_GITLEAKS_DEAF:-0}" -gt 0 ]; then
  head -c "$FAKE_GITLEAKS_DEAF" >/dev/null
  printf '%s' "${FAKE_GITLEAKS_REPORT:-}"
  exit "${FAKE_GITLEAKS_EXIT:-0}"
fi
cat >/dev/null
printf '%s' "${FAKE_GITLEAKS_REPORT:-}"
exit "${FAKE_GITLEAKS_EXIT:-0}"
