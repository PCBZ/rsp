#!/usr/bin/env node
/** One JSON object in, one out, then exit (T1); diagnostics to stderr (T2). */
import { respond, type Request } from "./protocol.ts";
import { parse } from "./strictjson.ts";

async function read(stream: AsyncIterable<Buffer>): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

const request = parse(await read(process.stdin)) as Request;
process.stdout.write(`${JSON.stringify(respond(request))}\n`);
