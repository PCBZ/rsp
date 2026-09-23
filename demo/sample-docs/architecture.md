# Architecture

Three services, one queue, and a vector store.

The ingest service is stateless. It reads a document, splits it, and hands each
chunk to the embedding provider. Nothing about a document survives a restart
except what reached the store.

The query service holds no state either. It embeds the question, asks the store
for neighbours, and passes what comes back to the model. Ranking happens in the
store, not in our code, which is why the store's configuration is part of the
deployment and not part of the application.

The queue exists so that a slow embedding provider cannot make document upload
fail. It is not a durability mechanism: a document that fails to embed is
retried three times and then reported.
