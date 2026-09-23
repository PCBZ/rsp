/**
 * Runs gitleaks as distributed — not copied, not imported — through two public
 * interfaces: the `gitleaks stdin` command and its report's fields. Which
 * makes this a process that spawns one, and is why the host kills a plugin's
 * whole process group.
 */
import { spawnSync } from "node:child_process";

/** A range to mask, in byte offsets into the UTF-8 encoding of the content. */
export interface Span {
  start: number;
  end: number;
  type: string;
}

/** The part of a gitleaks report a chunk can have. */
export interface Finding {
  RuleID: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
}

/** Read per call, not once at import, so a test can point it elsewhere. */
export function binary(): string {
  return process.env.RSP_GITLEAKS ?? "gitleaks";
}

/** Separates "found something" from gitleaks failing, which shares 1. */
const FOUND = 2;

/**
 * Byte offsets from gitleaks' positions. Its columns are byte columns, from Go
 * regexp indices into a byte slice, so the conversion is arithmetic (S1).
 *
 * They count from the newline byte ending the previous line, not from the
 * line's first byte, so only line one matches the 1-based column anyone
 * assumes. EndColumn belongs to EndLine, which differs whenever a finding
 * spans lines. Anything that does not slice `Match` back out is dropped, and
 * the caller turns a dropped finding into a BLOCK.
 */
export function toSpans(findings: Finding[], content: string): Span[] {
  const bytes = Buffer.from(content, "utf8");
  const lineStarts = byteOffsetOfEachLine(bytes);
  const spans: Span[] = [];

  for (const finding of findings) {
    const from = columnOrigin(lineStarts, finding.StartLine);
    const to = columnOrigin(lineStarts, finding.EndLine);
    if (from === undefined || to === undefined) continue;

    const span = {
      start: from + finding.StartColumn - 1,
      end: to + finding.EndColumn,
      type: finding.RuleID,
    };
    // What S3 will check, checked here: subarray truncates out-of-range
    // indices instead of failing, and an empty Match satisfies the slice
    // comparison from any equal pair. An adapter should not hand the host a
    // span it is going to reject.
    if (!usable(span, bytes)) continue;
    if (bytes.subarray(span.start, span.end).toString("utf8") !== finding.Match) continue;
    spans.push(span);
  }
  return spans;
}

/** In range, non-empty, and on character boundaries at both ends. */
function usable(span: Span, bytes: Buffer): boolean {
  const boundary = (at: number) => at === bytes.length || (bytes[at]! & 0xc0) !== 0x80;
  return (
    span.start >= 0 &&
    span.end <= bytes.length &&
    span.end > span.start &&
    boundary(span.start) &&
    boundary(span.end)
  );
}

/** The byte gitleaks counts this line's columns from, or undefined if absent. */
function columnOrigin(lineStarts: number[], line: number): number | undefined {
  if (line === 1) return 0;
  const start = lineStarts[line - 1];
  return start === undefined ? undefined : start - 1;
}

/** Byte offset at which each line begins, counting bytes and not characters. */
function byteOffsetOfEachLine(bytes: Buffer): number[] {
  const offsets = [0];
  for (let at = 0; at < bytes.length; at++) {
    if (bytes[at] === 0x0a) offsets.push(at + 1);
  }
  return offsets;
}

/**
 * Runs the binary once, synchronously: one request, one answer, exit. The
 * status is why this exists — a gitleaks that could not run prints nothing,
 * exactly like a clean chunk, so ignoring it would turn every failure into an
 * ALLOW (E1, D3).
 */
function run(args: string[], input: string): string {
  const { stdout, stderr, status, error } = spawnSync(binary(), args, {
    input,
    encoding: "utf8",
  });
  if (error) throw error;
  if (status !== 0 && status !== FOUND) {
    throw new Error(`gitleaks exited ${status}: ${stderr.trim()}`);
  }
  return stdout.trim();
}

/** Carried in the declaration, so a cache key includes it (D4). */
export function version(): string {
  return run(["version"], "");
}

/** Findings for one chunk. */
export function scan(content: string): Finding[] {
  // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its writability
  // pre-check. --no-banner keeps stdout to the report alone.
  const report = run(
    [
      "stdin",
      "--no-banner",
      "--report-format",
      "json",
      "--report-path",
      "-",
      "--exit-code",
      String(FOUND),
    ],
    content,
  );
  return report === "" ? [] : (JSON.parse(report) as Finding[]);
}
