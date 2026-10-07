# Deploy notes

The staging cluster is rebuilt nightly. Rollouts are gated on the smoke
suite, and a failed gate leaves the previous revision serving.

Credentials for the mirror live in the vault under `infra/mirror`. The
secret itself must never be pasted into a runbook.
