//! Line-and-column to byte offsets. No binary needed: a report is data.
//! Cases belong in the shared table; only what it cannot hold stays here.

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
    // Offsets inside 密, with Match what they cover, so only the boundary check
    // refuses them. The shared table cannot hold it: those bytes are not UTF-8.
    let case = finding("private-key", (2, 3), "\u{fffd}");

    assert!(to_spans(&[case], &format!("密钥 {KEY}")).is_empty());
}

#[test]
fn drops_a_column_that_cannot_be_added_to() {
    // Only Rust needs this: Go wraps without trapping and JavaScript has no integer.
    for column in [i64::MAX, i64::MIN] {
        let case = finding("aws-access-token", (column, column), KEY);
        assert!(to_spans(&[case], KEY).is_empty());
    }
}

#[test]
fn many_distinct_keys_do_not_cost_quadratically() {
    // A ratio rather than a duration: a wall clock measures the machine the
    // test happens to run on, and an unoptimised build on a loaded runner has
    // little room under any fixed bound. Ten times the keys costs ten times
    // linear and a hundred times quadratic, and a load that slows one
    // measurement slows the one beside it.
    fn spent(keys: usize) -> std::time::Duration {
        let mut message = String::from(r#"{"rsp_version":"0.1","hook":"on_chunk","content":"x""#);
        for index in 0..keys {
            message.push_str(&format!(",\"k{index}\":{index}"));
        }
        message.push('}');

        let started = std::time::Instant::now();
        let parsed: Result<serde_json::Value, _> = rsp_gitleaks::strictjson::from_str(&message);
        let elapsed = started.elapsed();
        assert!(parsed.is_ok(), "{keys} distinct keys is a valid message");
        elapsed
    }

    let few = spent(4_000);
    let many = spent(40_000);
    let growth = many.as_secs_f64() / few.as_secs_f64();

    assert!(
        growth < 30.0,
        "ten times the keys cost {growth:.0} times the work ({few:?} then {many:?})"
    );
}
