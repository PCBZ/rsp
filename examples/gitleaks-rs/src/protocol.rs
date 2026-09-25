//! The protocol side, kept apart from the adapter so the shape SPEC.md
//! requires lives in one file — including for whoever ports this again.

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

/// What this plugin says it is (H2). The version carries the binary's: for a
/// wrapper it is the tool that decides verdicts, and the cache is keyed on
/// this string (D4).
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
    // ALLOW carries nothing else: the common case is the cheap one (V2).
    if findings.is_empty() {
        return Ok(json!({"verdict": "ALLOW"}));
    }

    let spans = to_spans(&findings, &request.content);
    // A finding with no span is a secret we cannot point at; redacting the
    // rest would leave it in the chunk (V4).
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
