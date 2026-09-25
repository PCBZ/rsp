//! Wraps the gitleaks binary, through the same two interfaces as the Go and
//! TypeScript plugins: the `gitleaks stdin` command and its report's fields.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::Error;

/// A range to mask, in byte offsets (S1). Rust indexes a `str` by byte, so
/// `&content[start..end]` already means that — but it panics rather than
/// mis-slicing when an offset lands inside a character, which is why
/// `usable` runs before any slice does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    #[serde(rename = "type")]
    pub kind: String,
}

/// The part of a gitleaks report a chunk can have. Every field defaults, so a
/// finding that arrives without a position is a finding with line zero rather
/// than a parse failure — the difference between a BLOCK and a crash.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Finding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    pub start_line: i64,
    pub end_line: i64,
    pub start_column: i64,
    pub end_column: i64,
    #[serde(rename = "Match")]
    pub matched: String,
}

/// Separates "found something" from gitleaks failing, which shares 1.
const FOUND: i32 = 2;

/// How to start the tool. A command rather than a path so a test can put a
/// stand-in here with its answers already attached.
pub struct Gitleaks {
    command: Vec<String>,
}

impl Gitleaks {
    pub fn from_env() -> Self {
        let binary = std::env::var("RSP_GITLEAKS").unwrap_or_else(|_| "gitleaks".into());
        Self::new(vec![binary])
    }

    pub fn new(command: Vec<String>) -> Self {
        Self { command }
    }

    /// Runs the binary once. The status is why this exists: a gitleaks that
    /// could not run prints nothing, exactly like a clean chunk, so ignoring
    /// it would turn every failure into an ALLOW (E1, D3).
    fn run(&self, args: &[&str], input: &str) -> Result<String, Error> {
        let (binary, rest) = self.command.split_first().ok_or("no gitleaks command")?;
        let mut child = Command::new(binary)
            .args(rest)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        // On a thread, because a report large enough to fill the stdout pipe
        // would otherwise deadlock a parent still writing the chunk it is a
        // report of. Go and Node pump the child's stdin for you; Rust does not.
        let mut stdin = child.stdin.take().ok_or("stdin was not a pipe")?;
        let chunk = input.to_owned();
        let writer = thread::spawn(move || stdin.write_all(chunk.as_bytes()));

        let output = child.wait_with_output()?;
        // A closed pipe means the tool exited early; its status says why, so
        // this failure is not the one worth reporting.
        let _ = writer.join();

        if !output.status.success() && output.status.code() != Some(FOUND) {
            return Err(format!("gitleaks exited with {}", output.status).into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }

    /// Carried in the declaration so a cache key includes it (D4).
    pub fn version(&self) -> Result<String, Error> {
        self.run(&["version"], "")
    }

    /// The findings for one chunk.
    pub fn scan(&self, content: &str) -> Result<Vec<Finding>, Error> {
        // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
        // writability pre-check. --no-banner keeps stdout to the report alone.
        let report = self.run(
            &[
                "stdin",
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--exit-code",
                "2",
            ],
            content,
        )?;
        if report.is_empty() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_str(&report)?)
    }
}

/// Converts gitleaks' positions into byte offsets.
///
/// Its columns count from the newline byte ending the previous line, not from
/// the line's first byte, so only line one matches the 1-based column anyone
/// assumes. EndColumn belongs to EndLine, which differs whenever a finding
/// spans lines. Anything that does not slice Match back out is dropped, and
/// the caller turns a dropped finding into a BLOCK.
pub fn to_spans(findings: &[Finding], content: &str) -> Vec<Span> {
    let origins = column_origins(content);
    findings
        .iter()
        .filter_map(|finding| {
            let from = origin(&origins, finding.start_line)?;
            let to = origin(&origins, finding.end_line)?;
            let start = usize::try_from(from + finding.start_column - 1).ok()?;
            let end = usize::try_from(to + finding.end_column).ok()?;
            // What S3 will check, checked here: an adapter should not hand the
            // host a span it is going to reject, and in this language an
            // unchecked one takes the plugin down instead of the verdict.
            if !usable(start, end, content) || content[start..end] != finding.matched {
                return None;
            }
            Some(Span {
                start,
                end,
                kind: finding.rule_id.clone(),
            })
        })
        .collect()
}

/// Whether a span is in range, non-empty, and on character boundaries at both
/// ends. `is_char_boundary` is false past the end, so the range check is its.
pub fn usable(start: usize, end: usize, content: &str) -> bool {
    start < end && content.is_char_boundary(start) && content.is_char_boundary(end)
}

/// The byte gitleaks counts this line's columns from.
fn origin(origins: &[i64], line: i64) -> Option<i64> {
    if line == 1 {
        return Some(0);
    }
    if line < 1 || line > origins.len() as i64 {
        return None;
    }
    Some(origins[line as usize - 1] - 1)
}

/// Where each line begins.
fn column_origins(content: &str) -> Vec<i64> {
    let mut starts = vec![0];
    for (at, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(at as i64 + 1);
        }
    }
    starts
}
