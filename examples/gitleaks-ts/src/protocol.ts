/** The shape SPEC.md requires, apart from the tool so a port has one file to read. */
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

/** What this plugin says it is (H2), versioned with the tool that decides (D4). */
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

  // Redacting the rest would leave an unplaced secret in the chunk.
  if (spans.length !== findings.length) {
    return {
      verdict: "BLOCK",
      reason: "gitleaks reported a finding whose position could not be confirmed",
      severity: "critical",
    };
  }

  return { verdict: "REDACT", spans, replacement: REPLACEMENT, severity: "critical" };
}
