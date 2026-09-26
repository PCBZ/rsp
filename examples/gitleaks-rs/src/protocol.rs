//! The shape SPEC.md requires, apart from the tool so a port has one file to read.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::gitleaks::{to_spans, Gitleaks};
use crate::Error;

/// What a host sends. serde ignores unknown fields (D8).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Request {
    pub rsp_version: String,
    pub hook: String,
    pub content: String,
    /// Advisory: readable, never required (M2).
    pub metadata: Value,
}

pub const REPLACEMENT: &str = "[REDACTED:secret]";

/// What this plugin says it is (H2), versioned with the tool that decides (D4).
pub fn declare(gitleaks: &Gitleaks) -> Result<Value, Error> {
    Ok(json!({
        "rsp_version": "0.1",
        "name": "rsp-gitleaks-rs",
        "version": format!("0.1.0+{}", gitleaks.version()?),
        "hooks": ["on_chunk", "on_retrieve"],
        "deterministic": true,
    }))
}

pub fn respond(gitleaks: &Gitleaks, request: &Request) -> Result<Value, Error> {
    if request.hook == "handshake" {
        return declare(gitleaks);
    }

    let findings = gitleaks.scan(&request.content)?;
    if findings.is_empty() {
        return Ok(json!({"verdict": "ALLOW"}));
    }

    let spans = to_spans(&findings, &request.content);
    // Redacting the rest would leave an unplaced secret in the chunk.
    if spans.len() != findings.len() {
        return Ok(json!({
            "verdict": "BLOCK",
            "reason": "gitleaks reported a finding whose position could not be confirmed",
            "severity": "critical",
        }));
    }

    Ok(json!({
        "verdict": "REDACT",
        "spans": spans,
        "replacement": REPLACEMENT,
        "severity": "critical",
    }))
}
