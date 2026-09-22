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
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
}

/** Read per call, not once at import, so a test can point it elsewhere. */
export function binary(): string {
  return process.env.RSP_GITLEAKS ?? "gitleaks";
}

/**
 * The exit code gitleaks is told to use for "found something", so that it is
 * distinct from the code it uses for its own failures.
 */
const FOUND = 2;

/**
 * Byte offsets of each finding, from gitleaks' line and column numbers.
 *
 * Its columns are **byte** columns: they come from Go regexp match indices,
 * and a Go string is a byte slice. So the conversion is arithmetic — no
 * encoding knowledge — which is the cleanest evidence available that SPEC.md S1
 * chose a reachable unit.
 *
 * What the arithmetic has to know is where gitleaks counts a column from, and
 * it is not the first byte of the line: detect/location.go computes
 * `startColumn = start - prevNewLine + 1`, where prevNewLine is the index of
 * the newline *byte* ending the previous line. The first line has no such byte
 * and counts from zero, so its columns are the 1-based ones anyone would
 * expect and every later line's are one lower. A finding can also end on a
 * different line than it starts on — a PEM block does — and EndColumn is
 * relative to that end line.
 *
 * Findings that do not slice `Match` back out are dropped. A span off by one
 * redacts the wrong bytes and a short one leaves part of the secret in the
 * chunk, so a position this adapter cannot confirm is not worth reporting —
 * the caller turns the shortfall into a BLOCK rather than a partial redaction.
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
    if (bytes.subarray(span.start, span.end).toString("utf8") !== finding.Match) continue;
    spans.push(span);
  }
  return spans;
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
 * Run the binary once, synchronously: one request, one answer, exit. There is
 * nothing to overlap.
 *
 * The exit status is the whole reason this function exists. A gitleaks that
 * cannot run — bad config, unwritable report path — writes nothing to stdout,
 * which is exactly what a clean chunk produces. Reading only the report would
 * turn every such failure into an ALLOW, so this throws instead: the plugin
 * dies without answering, and the host's error path blocks the chunk (E1, D3).
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

/** Ask the binary what it is, so a cache key can include it (SPEC.md D4). */
export function version(): string {
  return run(["version"], "");
}

/** Findings for one chunk. An empty report means nothing was found. */
export function scan(content: string): Finding[] {
  // --no-banner keeps stdout to the report alone; "-" is gitleaks' own spelling
  // of stdout, and /dev/stdout is not: gitleaks checks the report path is
  // writable before it scans, and opening that file fails.
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
