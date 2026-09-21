/**
 * The adapter: run gitleaks, translate what it says into spans.
 *
 * gitleaks is not copied here and not imported as a library. It is invoked as
 * a subprocess, exactly as distributed, so the 222 detection rules stay
 * upstream's problem and this file depends only on two public interfaces: the
 * `gitleaks stdin` command, and the fields of its JSON report.
 *
 * Which makes this a process that spawns a process. The host kills a plugin's
 * whole process group for that reason.
 */
import { spawnSync } from "node:child_process";

/** A range to mask, in byte offsets into the UTF-8 encoding of the content. */
export interface Span {
  start: number;
  end: number;
  type: string;
}

/**
 * The fields of a gitleaks finding this adapter reads. The report carries more
 * — commit, author, entropy, fingerprint — none of which a chunk has.
 */
export interface Finding {
  RuleID: string;
  StartLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
}

export const GITLEAKS = process.env.RSP_GITLEAKS ?? "gitleaks";

/**
 * Byte offsets of each finding, from gitleaks' line and column numbers.
 *
 * gitleaks reports a position as a line plus a column, and its columns are
 * **byte** columns: they come from Go regexp match indices, and a Go string is
 * a byte slice. So the conversion is arithmetic — no encoding knowledge — which
 * is the cleanest evidence available that SPEC.md S1 chose a reachable unit.
 *
 * StartColumn is 1-based and EndColumn is inclusive, so `[start, end)` in S1's
 * half-open form is `lineStart + StartColumn - 1` to `lineStart + EndColumn`.
 */
export function toSpans(findings: Finding[], content: string): Span[] {
  const lineStarts = byteOffsetOfEachLine(content);
  const spans: Span[] = [];

  for (const finding of findings) {
    const lineStart = lineStarts[finding.StartLine - 1];
    if (lineStart === undefined) continue; // a line the content does not have
    spans.push({
      start: lineStart + finding.StartColumn - 1,
      end: lineStart + finding.EndColumn,
      type: finding.RuleID,
    });
  }
  return spans;
}

/** Byte offset at which each line begins, counting bytes and not characters. */
function byteOffsetOfEachLine(content: string): number[] {
  const offsets = [0];
  const bytes = Buffer.from(content, "utf8");
  for (let at = 0; at < bytes.length; at++) {
    if (bytes[at] === 0x0a) offsets.push(at + 1);
  }
  return offsets;
}

/**
 * Run the binary once, synchronously: one request, one answer, exit. There is
 * nothing to overlap, and the exit status is deliberately ignored — gitleaks
 * exits 1 when it finds something, which is a failure for a CI gate and a
 * success for us.
 */
function run(args: string[], input: string): string {
  const { stdout, error } = spawnSync(GITLEAKS, args, { input, encoding: "utf8" });
  if (error) throw error;
  return stdout.trim();
}

/** Ask the binary what it is, so a cache key can include it (SPEC.md D4). */
export function version(): string {
  return run(["version"], "");
}

/** Findings for one chunk. An empty report means nothing was found. */
export function scan(content: string): Finding[] {
  // --no-banner keeps the protocol channel clean.
  const report = run(
    ["stdin", "--no-banner", "--report-format", "json", "--report-path", "/dev/stdout"],
    content,
  );
  return report === "" ? [] : (JSON.parse(report) as Finding[]);
}
