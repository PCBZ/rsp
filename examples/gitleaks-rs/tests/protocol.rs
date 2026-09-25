//! Which report becomes which verdict, through a stand-in binary so the
//! interesting case can be provoked: a finding that cannot be placed.

use rsp_gitleaks::gitleaks::Gitleaks;
use rsp_gitleaks::protocol::{respond, Request, REPLACEMENT};
use serde_json::{json, Value};

const KEY: &str = "AKIALALEMEL33243OLIB";

/// The report and the exit status ride in the command, not the environment:
/// tests share one process, and one test's environment is every test's.
fn fake(report: &str, exit: &str) -> Gitleaks {
    padded(report, exit, 0)
}

fn padded(report: &str, exit: &str, padding: usize) -> Gitleaks {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/fake-gitleaks.sh");
    Gitleaks::new(vec![
        script.into(),
        report.into(),
        exit.into(),
        padding.to_string(),
    ])
}

fn chunk(content: &str) -> Request {
    Request {
        hook: "on_chunk".into(),
        content: content.into(),
        ..Request::default()
    }
}

fn report(column: i64) -> String {
    json!([{"RuleID": "aws-access-token", "StartLine": 1, "EndLine": 1,
            "StartColumn": column, "EndColumn": column + 19, "Match": KEY}])
    .to_string()
}

#[test]
fn allows_a_chunk_nothing_was_found_in() {
    let got = respond(&fake("", "0"), &chunk("nothing here")).unwrap();

    assert_eq!(got, json!({"verdict": "ALLOW"}));
}

#[test]
fn redacts_what_it_can_place() {
    let content = format!("deploy with {KEY} today");
    let got = respond(&fake(&report(13), "2"), &chunk(&content)).unwrap();

    assert_eq!(got["verdict"], "REDACT");
    assert_eq!(
        got["spans"],
        json!([{"start": 12, "end": 32, "type": "aws-access-token"}])
    );
    assert_eq!(got["replacement"], REPLACEMENT);
}

#[test]
fn blocks_rather_than_redacting_only_what_it_can_place() {
    // One of two findings mislocated: reporting the good span publishes the
    // other secret, and ALLOW publishes both.
    let content = format!("deploy with {KEY} today");
    let both = format!(
        "[{},{}]",
        &report(13)[1..report(13).len() - 1],
        &report(99)[1..report(99).len() - 1]
    );
    let got = respond(&fake(&both, "2"), &chunk(&content)).unwrap();

    assert_eq!(got["verdict"], "BLOCK");
    assert!(got["reason"].is_string(), "BLOCK should say why (V4)");
}

#[test]
fn blocks_on_a_finding_with_no_position() {
    let bare = json!([{"RuleID": "aws-access-token", "Match": KEY}]).to_string();

    assert_eq!(
        respond(&fake(&bare, "2"), &chunk(KEY)).unwrap()["verdict"],
        "BLOCK"
    );
}

#[test]
fn refuses_to_answer_when_the_binary_fails() {
    // Nothing on stdout, exactly like a clean chunk (E1, D3).
    assert!(respond(&fake("", "1"), &chunk(KEY)).is_err());
}

#[test]
fn refuses_to_answer_on_a_report_that_is_not_a_report() {
    assert!(respond(&fake("not json", "2"), &chunk(KEY)).is_err());
}

#[test]
fn declares_the_wrapped_tools_version_in_its_own() {
    // D4: the adapter's version alone would outlive the ruleset it judged with.
    let request = Request {
        hook: "handshake".into(),
        ..Request::default()
    };

    let got: Value = respond(&fake("8.30.1", "0"), &request).unwrap();

    assert_eq!(got["version"], "0.1.0+8.30.1");
    assert_eq!(got["name"], "rsp-gitleaks-rs");
}

#[test]
fn survives_a_tool_that_writes_before_it_reads() {
    // The chunk and what the tool writes both exceed a pipe buffer, and the
    // writing comes first. Sending stdin from this thread would block on a
    // child already blocked on stdout, and neither side would ever move.
    let content = KEY.repeat(8000);
    let bare = json!([{"RuleID": "aws-access-token", "Match": KEY}]).to_string();

    let got = respond(&padded(&bare, "2", 200_000), &chunk(&content)).unwrap();

    assert_eq!(got["verdict"], "BLOCK");
}
