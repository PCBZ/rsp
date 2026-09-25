//! Line-and-column to byte offsets. No binary needed: a report is data.
//!
//! Every report below is transcribed from what gitleaks 8.30.1 emitted for
//! that content. Invented numbers agree with whatever the code assumes, which
//! is how the TypeScript adapter's end offset was wrong for two-line findings.

use rsp_gitleaks::gitleaks::{to_spans, Finding, Span};

const KEY: &str = "AKIALALEMEL33243OLIB";

fn pem() -> String {
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
        "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==",
        "-----END RSA PRIVATE KEY-----",
    ]
    .join("\n")
}

fn finding(rule: &str, lines: (i64, i64), columns: (i64, i64), matched: &str) -> Finding {
    Finding {
        rule_id: rule.into(),
        start_line: lines.0,
        end_line: lines.1,
        start_column: columns.0,
        end_column: columns.1,
        matched: matched.into(),
    }
}

fn aws(lines: (i64, i64), columns: (i64, i64)) -> Finding {
    finding("aws-access-token", lines, columns, KEY)
}

fn span(start: usize, end: usize, kind: &str) -> Span {
    Span {
        start,
        end,
        kind: kind.into(),
    }
}

#[test]
fn places_a_finding_on_the_first_line() {
    let content = format!("deploy with {KEY} today");
    let spans = to_spans(&[aws((1, 1), (13, 32))], &content);

    assert_eq!(spans, vec![span(12, 32, "aws-access-token")]);
    // An offset is useful exactly when it indexes the host's bytes.
    assert_eq!(&content[spans[0].start..spans[0].end], KEY);
}

#[test]
fn places_a_finding_after_multi_byte_text() {
    // 密钥 is two characters and six bytes; a character index says 3.
    let content = format!("密钥 {KEY} 在后面");
    let spans = to_spans(&[aws((1, 1), (8, 27))], &content);

    assert_eq!(spans, vec![span(7, 27, "aws-access-token")]);
    assert_eq!(&content[spans[0].start..spans[0].end], KEY);
}

#[test]
fn places_a_finding_on_a_later_line() {
    // Column 11 for a key at byte 16 of a line starting at 7: columns run
    // from the newline byte, one lower than line-relative.
    let content = format!("header\nexport K={KEY}\n");
    let spans = to_spans(&[aws((2, 2), (11, 30))], &content);

    assert_eq!(spans, vec![span(16, 36, "aws-access-token")]);
    assert_eq!(&content[spans[0].start..spans[0].end], KEY);
}

#[test]
fn places_a_finding_under_multi_byte_lines() {
    let content = format!("密钥\n说明\nK={KEY}\n");
    let spans = to_spans(&[aws((3, 3), (4, 23))], &content);

    assert_eq!(spans, vec![span(16, 36, "aws-access-token")]);
    assert_eq!(&content[spans[0].start..spans[0].end], KEY);
}

#[test]
fn places_a_finding_spanning_four_lines() {
    // Read against the start line, the end lands 141 bytes early: the key's
    // first line redacted, the rest published.
    let key = pem();
    let content = format!("cfg:\n{key}\ntrailing\n");
    let spans = to_spans(&[finding("private-key", (2, 5), (2, 30), &key)], &content);

    assert_eq!(spans, vec![span(5, 5 + key.len(), "private-key")]);
    assert_eq!(&content[spans[0].start..spans[0].end], key);
}

#[test]
fn reports_every_occurrence() {
    let content = format!("{KEY}\nfiller\n{KEY}");
    let spans = to_spans(&[aws((1, 1), (1, 20)), aws((3, 3), (2, 21))], &content);

    assert_eq!(spans.len(), 2, "S2");
    assert_eq!((spans[0].start, spans[1].start), (0, 28));
}

#[test]
fn drops_what_it_cannot_confirm() {
    let placed = format!("deploy with {KEY} today");
    // Dropping is not passing: respond turns each of these into a BLOCK.
    let cases: [(&str, &str, Finding); 3] = [
        (
            "a line the content does not have",
            "one line",
            aws((99, 99), (1, 20)),
        ),
        (
            "offsets that do not slice the match back out",
            &placed,
            aws((1, 1), (14, 32)),
        ),
        (
            "a span past the end of the content",
            "short",
            aws((1, 1), (1, 400)),
        ),
    ];

    for (name, content, finding) in cases {
        assert!(to_spans(&[finding], content).is_empty(), "{name}");
    }
}

#[test]
fn drops_a_column_that_cannot_be_added_to() {
    // A report is data, and these numbers are the largest JSON can hand a
    // 64-bit field. Unchecked they overflow, which is a panic in the debug
    // build a clone runs through `cargo run` and a wrapped span in release —
    // a plugin that dies or lies where it should have said BLOCK.
    let far = finding("aws-access-token", (1, 1), (i64::MAX, i64::MAX), KEY);
    let negative = finding("aws-access-token", (1, 1), (i64::MIN, i64::MIN), KEY);

    for case in [far, negative] {
        assert!(to_spans(&[case], KEY).is_empty());
    }
}

#[test]
fn drops_a_finding_with_no_position() {
    let bare = Finding {
        rule_id: "aws-access-token".into(),
        matched: KEY.into(),
        ..Finding::default()
    };

    assert!(to_spans(&[bare], KEY).is_empty());
}

#[test]
fn allows_an_empty_report() {
    assert!(to_spans(&[], "anything").is_empty());
}

#[test]
fn drops_spans_the_host_would_reject() {
    let content = format!("密钥 {KEY}");
    // An empty span, which the slice comparison alone would accept.
    let empty = finding("aws-access-token", (1, 1), (3, 2), "");
    // EndColumn past the content, with Match happening to be its tail.
    let past = finding("aws-access-token", (1, 1), (8, 400), KEY);
    // Offsets inside 密, with Match the bytes they actually cover. Nothing
    // here may slice: in Rust that comparison is a panic, not a mismatch.
    let inside = finding("private-key", (1, 1), (2, 3), "\u{fffd}");

    for case in [empty, past, inside] {
        assert!(to_spans(&[case], &content).is_empty());
    }
}
