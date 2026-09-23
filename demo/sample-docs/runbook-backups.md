# Runbook: backups

Nightly at 02:00 UTC, retained for thirty days.

## Restoring

Fetch the archive from the backup bucket and unpack it into a scratch volume.
The restore script expects the deploy key below, which somebody copied out of
the vault so the runbook would be self-contained:

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBK2FVYPDaZrGZbHBmnPmrPBcVYSFVTYvfPyTcHNMYuZQAAAJhUqM8aVKjP
GgAAAAtzc2gtZWQyNTUxOQAAACBK2FVYPDaZrGZbHBmnPmrPBcVYSFVTYvfPyTcHNMYuZQ
-----END OPENSSH PRIVATE KEY-----

Do not do this. The restore script can read the vault directly; the key is here
because the runbook was written in a hurry during an outage.

## Verifying

Compare the row count against the metrics dashboard before switching traffic.
