#!/bin/sh
# A gitleaks with a great deal to say on stderr, which is where it reports
# what it scanned. A caller that pipes stderr and never reads it stops the
# tool once the pipe fills, and then waits for it.
cat >/dev/null
head -c 400000 /dev/zero | tr '\0' 'x' >&2
exit 0
