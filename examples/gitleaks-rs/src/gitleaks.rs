//! Wraps gitleaks using only `gitleaks stdin` and its report.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::Error;

/// A range to mask, in byte offsets (S1), which is what a `str` indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    #[serde(rename = "type")]
    pub kind: String,
}

/// The part of a gitleaks report a chunk can have. Fields default, so a finding
/// without a position becomes a BLOCK rather than a parse failure.
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

/// How to start the tool: a command, so a test can attach a stand-in's answers.
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

    /// Runs the binary once. A failed run prints nothing, like a clean chunk,
    /// so only the status tells them apart (E1, D3).
    fn run(&self, args: &[&str], input: &str) -> Result<String, Error> {
        let (binary, rest) = self.command.split_first().ok_or("no gitleaks command")?;
        let mut child = Command::new(binary)
            .args(rest)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        // On a thread: a tool that fills stdout before reading would deadlock a
        // parent still writing the chunk. Go and Node do so for you; Rust does not.
        let mut stdin = child.stdin.take().ok_or("stdin was not a pipe")?;
        let chunk = input.to_owned();
        let writer = thread::spawn(move || stdin.write_all(chunk.as_bytes()));

        let output = child.wait_with_output()?;
        // A closed pipe means the tool exited early, and its status says why.
        let _ = writer.join();

        if !output.status.success() && output.status.code() != Some(FOUND) {
            return Err(format!("gitleaks exited with {}", output.status).into());
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }

    pub fn version(&self) -> Result<String, Error> {
        self.run(&["version"], "")
    }

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

/// Converts gitleaks' positions to byte offsets, dropping a finding it cannot
/// place. The quirks it corrects are the notes in gitleaks-offsets.json.
pub fn to_spans(findings: &[Finding], content: &str) -> Vec<Span> {
    let origins = column_origins(content);
    findings
        .iter()
        .filter_map(|finding| {
            let from = origin(&origins, finding.start_line)?;
            let to = origin(&origins, finding.end_line)?;
            // Checked: a column is someone else's number, and overflow panics in
            // debug and wraps in release where a dropped finding is owed.
            let start = from.checked_add(finding.start_column)?.checked_sub(1)?;
            let end = to.checked_add(finding.end_column)?;
            let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
            // `usable` first (S3): slicing off a char boundary panics the plugin.
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
