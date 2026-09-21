/**
 * The protocol side: what a request looks like, what a response must be, and
 * the mapping between them.
 *
 * Kept apart from the adapter so that the shape SPEC.md requires lives in one
 * file, and so someone porting this to another language has one place to look.
 */
import { scan, toSpans, version, type Span } from "./gitleaks.ts";

export interface Request {
  rsp_version?: string;
  hook?: string;
  content?: string;
  /** Advisory: a plugin may read it and must not require it (SPEC.md M2). */
  metadata?: Record<string, unknown>;
}

export type Response =
  | { verdict: "ALLOW" }
  | { verdict: "REDACT"; spans: Span[]; replacement: string; severity: string };

export interface Declaration {
  rsp_version: string;
  name: string;
  version: string;
  hooks: string[];
  deterministic: boolean;
}

export const REPLACEMENT = "[REDACTED:secret]";

/**
 * What this plugin tells a host about itself (SPEC.md H2).
 *
 * The version carries the binary's, not just the adapter's. A cache key
 * contains the plugin version (D4), and for a wrapper it is the wrapped tool
 * that decides verdicts: gitleaks adding a rule changes the answer for content
 * that has not changed, and a cache keyed on the adapter's version alone would
 * keep serving the old one. Costs one extra call to the binary, once.
 */
export function declaration(): Declaration {
  return {
    rsp_version: "0.1",
    name: "rsp-gitleaks-ts",
    version: `0.1.0+${version()}`,
    hooks: ["on_chunk", "on_retrieve"],
    deterministic: true,
  };
}

/** One request in, one response out. */
export function respond(request: Request): Response | Declaration {
  if (request.hook === "handshake") return declaration();

  const content = request.content ?? "";
  const spans = toSpans(scan(content), content);
  // ALLOW carries no other field, because the common case should be the cheap
  // one to produce (SPEC.md V2).
  if (spans.length === 0) return { verdict: "ALLOW" };

  return { verdict: "REDACT", spans, replacement: REPLACEMENT, severity: "critical" };
}
