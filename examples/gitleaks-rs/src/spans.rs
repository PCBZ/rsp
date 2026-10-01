//! gitleaks' line and column positions as the byte offsets S1 asks for.

use serde::Serialize;

use crate::gitleaks::Finding;

/// A range to mask, in byte offsets (S1), which is what a `str` indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    #[serde(rename = "type")]
    pub kind: String,
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
            // `get` and not an index (S3): slicing off a boundary panics the
            // plugin, and out of range is someone else's number being wrong.
            if content.get(start..end)? != finding.matched {
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

/// The byte gitleaks counts this line's columns from.
fn origin(origins: &[i64], line: i64) -> Option<i64> {
    usize::try_from(line)
        .ok()
        .filter(|&at| at >= 1)
        .and_then(|at| origins.get(at - 1))
        .copied()
}

/// The byte each line's columns are counted from: the newline above it, and 0
/// for the first, which has none.
fn column_origins(content: &str) -> Vec<i64> {
    let mut origins = vec![0];
    for (at, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            origins.push(at as i64);
        }
    }
    origins
}
