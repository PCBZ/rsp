#!/usr/bin/env node
/**
 * One JSON object in, one out, then exit (T1). Diagnostics go to stderr: a
 * stray line on stdout is indistinguishable from a response (T2).
 */
import { respond, type Request } from "./protocol.ts";

async function read(stream: AsyncIterable<Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

const request: Request = JSON.parse(await read(process.stdin));
process.stdout.write(`${JSON.stringify(respond(request))}\n`);
