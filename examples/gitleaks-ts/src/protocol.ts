/**
 * The protocol side, kept apart from the adapter so the shape SPEC.md requires
 * lives in one file — including for whoever ports this to another language.
 */
import { scan, toSpans, version, type Span } from "./gitleaks.ts";

export interface Request {
  rsp_version?: string;
  hook?: string;
  content?: string;
  /** Advisory: readable, never required (M2). */
  metadata?: Record<string, unknown>;
}

export type Response =
  | { verdict: "ALLOW" }
  | { verdict: "REDACT"; spans: Span[]; replacement: string; severity: string }
  | { verdict: "BLOCK"; reason: string; severity: string };

export interface Declaration {
  rsp_version: string;
  name: string;
  version: string;
  hooks: string[];
  deterministic: boolean;
}

export const REPLACEMENT = "[REDACTED:secret]";

/**
 * What this plugin says it is (H2). The version carries the binary's: for a
 * wrapper it is the tool that decides verdicts, and the cache is keyed on this
 * string (D4).
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

export function respond(request: Request): Response | Declaration {
  if (request.hook === "handshake") return declaration();

  const content = request.content ?? "";
  const findings = scan(content);
  const spans = toSpans(findings, content);

  // ALLOW carries nothing else: the common case is the cheap one (V2).
  if (findings.length === 0) return { verdict: "ALLOW" };

  // A finding with no span is a secret we cannot point at; redacting the rest
  // would leave it in the chunk (V4).
  if (spans.length !== findings.length) {
    return {
      verdict: "BLOCK",
      reason: "gitleaks reported a finding whose position could not be confirmed",
      severity: "critical",
    };
  }

  return { verdict: "REDACT", spans, replacement: REPLACEMENT, severity: "critical" };
}
