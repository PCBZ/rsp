# FAQ

## Why is my document not in the index?

Three reasons, in order of likelihood. It is still in the queue; the file type
is not one we read; or a scanner refused it. The ingest report says which.

## Why can I not find a document I know was indexed?

Retrieval is nearest-neighbour, not search. A document can be indexed and never
come back for a question that does not resemble it. If you expect a document to
answer a question, try the question first and the keywords second.

## Can I delete something after it is indexed?

Yes, but understand what that does and does not do. Deleting removes the vector
and the stored text. It does not remove what the model may have said about the
document while it was there, and it does not undo an embedding somebody
exported in the meantime.

## Why does the guard redact instead of refusing?

Because a chunk with one credential in it is usually still worth having. The
sentence around the secret is often the sentence someone is searching for. A
refusal is what happens when the scanner cannot say where the secret is, and
then keeping any of it would be a guess.

## Who can see the ingest report?

Everyone on the platform team. It names files and lines, never the contents of
what was found — it is a pointer to go and look, not a second copy.
