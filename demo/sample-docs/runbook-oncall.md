# Runbook: on-call

The rotation is weekly, handover on Monday morning.

## What you are responsible for

Ingest failures, query latency, and the embedding provider's rate limits. You
are not responsible for the model's answers; quality complaints go to the
product channel and are triaged there.

## Alerts

`ingest_backlog` fires when the queue is older than fifteen minutes. In almost
every case the cause is the embedding provider, and in almost every case the
correct action is to wait. Escalate if the backlog is still growing after an
hour, because that means retries are failing rather than queueing.

`query_p99` fires at two seconds. The usual cause is a store compaction, which
finishes on its own. If it does not, the store's own runbook has the manual
compaction procedure and you should follow that rather than restarting nodes.

`guard_errors` fires when a scanner plugin fails. This one is not a wait: a
failing scanner blocks ingest by design, so the backlog will grow until the
plugin is fixed or removed from the configuration. Both are deploys.

## Handover

Write what happened in the channel, even if nothing did. The next person reads
the last week before they read anything else.
