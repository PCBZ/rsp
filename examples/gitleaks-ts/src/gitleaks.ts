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
