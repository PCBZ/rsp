//! Line-and-column to byte offsets. No binary needed: a report is data.
//!
//! The table is `examples/gitleaks-offsets.json`, shared with the Go and
//! TypeScript adapters, because the numbers in it are facts about gitleaks
//! rather than about any of the three. What stays here is what this language
//! makes possible and the others do not.

use std::collections::BTreeMap;

use rsp_gitleaks::gitleaks::{to_spans, Finding};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Case {
    #[serde(rename = "tcId")]
    id: u32,
    comment: String,
    flags: Vec<String>,
    content: String,
    findings: Vec<Finding>,
    spans: Value,
}

#[derive(Deserialize)]
struct Table {
    notes: BTreeMap<String, String>,
    tests: Vec<Case>,
}

fn table() -> Table {
    let raw = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../gitleaks-offsets.json"
    ));
    serde_json::from_str(raw).expect("the shared offset table should parse")
}

#[test]
fn converts_every_case_in_the_shared_table() {
    let table = table();
    // A path that resolved to nothing would leave this test green and empty.
    assert!(table.tests.len() >= 13, "the table lost cases");

    for case in &table.tests {
        let produced = serde_json::to_value(to_spans(&case.findings, &case.content)).unwrap();
        let why: Vec<&str> = case
            .flags
            .iter()
            .map(|flag| table.notes[flag].as_str())
            .collect();
        assert_eq!(
            produced,
            case.spans,
            "{}: {}\n{}",
            case.id,
            case.comment,
            why.join("\n")
        );
    }
}

const KEY: &str = "AKIALALEMEL33243OLIB";

fn finding(rule: &str, columns: (i64, i64), matched: &str) -> Finding {
    Finding {
        rule_id: rule.into(),
        start_line: 1,
        end_line: 1,
        start_column: columns.0,
        end_column: columns.1,
        matched: matched.into(),
    }
}

#[test]
fn drops_a_span_inside_a_character() {
    // Offsets inside 密, with Match the bytes they actually cover, so only the
    // boundary check can refuse them. Each adapter spells those two bytes in
    // its own way and none of the spellings is valid UTF-8, which is why this
    // case cannot live in a JSON table with the rest.
    let case = finding("private-key", (2, 3), "\u{fffd}");

    assert!(to_spans(&[case], &format!("密钥 {KEY}")).is_empty());
}

#[test]
fn drops_a_column_that_cannot_be_added_to() {
    // A report is data, and these are the largest numbers JSON can hand a
    // 64-bit field. Unchecked they overflow, which is a panic in the debug
    // build a clone runs through `cargo run` and a wrapped span in release —
    // a plugin that dies or lies where it should have said BLOCK. Only this
    // language is hurt: Go wraps without trapping and JavaScript has no
    // integer to overflow.
    for column in [i64::MAX, i64::MIN] {
        let case = finding("aws-access-token", (column, column), KEY);
        assert!(to_spans(&[case], KEY).is_empty());
    }
}
