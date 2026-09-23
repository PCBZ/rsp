# Onboarding

Welcome to the platform team. This page is what a new engineer reads first,
and it is deliberately boring: everything here is public inside the company.

## Accounts

Ask your manager to add you to the `platform` group. Access to staging comes
with the group; production access is requested separately and reviewed weekly.

## The stack

The ingest service reads documents from the shared drive, splits them into
chunks, and writes embeddings to the vector store. Retrieval happens in the
query service, which is a separate deployment with its own scaling rules.

## Getting help

The team channel is `#platform`. For anything urgent, the on-call rotation is
in the runbook. Please do not direct-message individuals for outages — the
rotation exists so that nobody has to guess who is awake.
