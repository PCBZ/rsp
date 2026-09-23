# Vector store

One collection per environment, one namespace per source.

## Sizing

The store is sized by vector count, not by document size, which surprises
people. A hundred short documents cost more than ten long ones. If a source
produces many tiny files, consider concatenating them before ingest.

## Compaction

Automatic, nightly. Manual compaction exists and is in the store's own runbook.
Do not run it during business hours: it holds a read lock long enough to push
query latency past the alert threshold.

## Backups

The store is not backed up. This is deliberate — it is derived data, and the
recovery procedure is to re-ingest from the source of truth. Re-ingesting the
whole corpus takes about four hours, which is the number that matters when
somebody asks how long a store rebuild takes.

## Access

The query service has read access. The ingest service has write access. Nobody
has both, and there is no human credential for either — access is through the
services, and the services authenticate with workload identity.
