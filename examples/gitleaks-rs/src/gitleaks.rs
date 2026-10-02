//! Wraps gitleaks using only `gitleaks stdin` and its report.

use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;

use serde::Deserialize;

use crate::Error;

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
    fn run(&self, args: &[&str], input: &str) -> Result<(String, Option<i32>), Error> {
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
        Ok((
            String::from_utf8(output.stdout)?.trim().to_owned(),
            output.status.code(),
        ))
    }

    pub fn version(&self) -> Result<String, Error> {
        Ok(self.run(&["version"], "")?.0)
    }

    pub fn scan(&self, content: &str) -> Result<Vec<Finding>, Error> {
        // "-" is gitleaks' own spelling of stdout; /dev/stdout fails its
        // writability pre-check. --no-banner keeps stdout to the report alone.
        let (report, status) = self.run(
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
        // Exit 0 with nothing written is a clean chunk. Exit 2 is gitleaks
        // saying it found something, so nothing written is a report that went
        // missing, and reading it as no findings is the ALLOW E1 refuses.
        if status == Some(FOUND) && report.is_empty() {
            return Err("gitleaks reported findings and wrote no report".into());
        }
        if report.is_empty() {
            return Ok(Vec::new());
        }
        Ok(serde_json::from_str(&report)?)
    }
}
