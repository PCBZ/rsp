#!/usr/bin/env node
/**
 * The entry point, and nothing else: read one JSON object from stdin, write
 * one to stdout, exit (SPEC.md T1).
 *
 * Diagnostics would go to stderr. stdout is the protocol channel, and a stray
 * line on it is indistinguishable from a response (SPEC.md T2) — which is why
 * the adapter passes --no-banner to gitleaks.
 */
import { respond, type Request } from "./protocol.ts";

async function read(stream: AsyncIterable<Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

const request: Request = JSON.parse(await read(process.stdin));
process.stdout.write(`${JSON.stringify(respond(request))}\n`);
