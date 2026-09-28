/** Wraps gitleaks using only `gitleaks stdin` and its report. */
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
function binary(): string {
  return process.env.RSP_GITLEAKS ?? "gitleaks";
}

/** Separates "found something" from gitleaks failing, which shares 1. */
const FOUND = 2;

/**
 * Converts gitleaks' positions to byte offsets, dropping a finding it cannot
 * place. The quirks it corrects are the notes in gitleaks-offsets.json.
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
    // `usable` first (S3): subarray truncates out-of-range indices and decodes
    // a stray continuation byte as U+FFFD, so a bad span can still match.
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

function byteOffsetOfEachLine(bytes: Buffer): number[] {
  const offsets = [0];
  for (let at = 0; at < bytes.length; at++) {
    if (bytes[at] === 0x0a) offsets.push(at + 1);
  }
  return offsets;
}

/**
 * Runs the binary once, synchronously (T1), returning what it wrote and how it
 * exited. A failed run prints nothing, like a clean chunk, so only the status
 * tells them apart (E1, D3).
 */
function run(args: string[], input: string): { report: string; status: number | null } {
  const { stdout, stderr, status, error } = spawnSync(binary(), args, {
    input,
    encoding: "utf8",
  });
  if (error) throw error;
  if (status !== 0 && status !== FOUND) {
    throw new Error(`gitleaks exited ${status}: ${stderr.trim()}`);
  }
  return { report: stdout.trim(), status };
}

export function version(): string {
  return run(["version"], "").report;
}

export function scan(content: string): Finding[] {
  // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its writability
  // pre-check. --no-banner keeps stdout to the report alone.
  const { report, status } = run(
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
  // Exit 0 with nothing written is a clean chunk. Exit 2 is gitleaks saying it
  // found something, so nothing written is a report that went missing, and
  // reading it as no findings is the ALLOW E1 refuses.
  if (status === FOUND && report === "") {
    throw new Error("gitleaks reported findings and wrote no report");
  }
  if (report === "") return [];
  const findings: unknown = JSON.parse(report);
  if (!Array.isArray(findings)) {
    throw new Error("gitleaks wrote a report that is not a list of findings");
  }
  return findings as Finding[];
}
