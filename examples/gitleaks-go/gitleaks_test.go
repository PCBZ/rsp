// The conversion from gitleaks' line-and-column positions to the byte offsets
// S1 requires. No binary needed: the input is a report, which is data.
//
// Every report below is transcribed from what gitleaks 8.30.1 actually
// emitted for that content. Inventing the numbers is how the TypeScript
// adapter's end offset came to be wrong for anything spanning two lines — a
// fabricated report agrees with whatever the code assumes.
package main

import (
	"strings"
	"testing"
)

const key = "AKIALALEMEL33243OLIB"

var pem = strings.Join([]string{
	"-----BEGIN RSA PRIVATE KEY-----",
	"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
	"KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==",
	"-----END RSA PRIVATE KEY-----",
}, "\n")

func aws(startLine, endLine, startColumn, endColumn int) Finding {
	return Finding{
		RuleID: "aws-access-token", StartLine: startLine, EndLine: endLine,
		StartColumn: startColumn, EndColumn: endColumn, Match: key,
	}
}

func TestToSpans(t *testing.T) {
	cases := []struct {
		name    string
		content string
		finding Finding
		want    Span
	}{
		{
			name:    "on the first line",
			content: "deploy with " + key + " today",
			finding: aws(1, 1, 13, 32),
			want:    Span{Start: 12, End: 32, Type: "aws-access-token"},
		},
		{
			// 密钥 is two characters and six bytes, so a character index says 3.
			name:    "after multi-byte text on the same line",
			content: "密钥 " + key + " 在后面",
			finding: aws(1, 1, 8, 27),
			want:    Span{Start: 7, End: 27, Type: "aws-access-token"},
		},
		{
			// Column 11 for a key at byte 16 of a line starting at 7: the
			// columns run from the newline byte, so they are one lower than a
			// line-relative column would be.
			name:    "on a later line",
			content: "header\nexport K=" + key + "\n",
			finding: aws(2, 2, 11, 30),
			want:    Span{Start: 16, End: 36, Type: "aws-access-token"},
		},
		{
			name:    "on a later line with multi-byte lines above",
			content: "密钥\n说明\nK=" + key + "\n",
			finding: aws(3, 3, 4, 23),
			want:    Span{Start: 16, End: 36, Type: "aws-access-token"},
		},
		{
			// A PEM block is the ordinary case for a finding that ends on a
			// different line than it starts on. Read against the start line the
			// end lands 141 bytes early, redacting the key's first line and
			// publishing the rest.
			name:    "spanning four lines",
			content: "cfg:\n" + pem + "\ntrailing\n",
			finding: Finding{
				RuleID: "private-key", StartLine: 2, EndLine: 5,
				StartColumn: 2, EndColumn: 30, Match: pem,
			},
			want: Span{Start: 5, End: 5 + len(pem), Type: "private-key"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spans := toSpans([]Finding{c.finding}, c.content)
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if spans[0] != c.want {
				t.Errorf("got %+v, want %+v", spans[0], c.want)
			}
			// The only assertion that matters: an offset is useful exactly
			// when it indexes the bytes the host is holding.
			if sliced := c.content[spans[0].Start:spans[0].End]; sliced != c.finding.Match {
				t.Errorf("sliced %q, want %q", sliced, c.finding.Match)
			}
		})
	}
}

func TestToSpansReportsEveryOccurrence(t *testing.T) {
	content := key + "\nfiller\n" + key
	spans := toSpans([]Finding{aws(1, 1, 1, 20), aws(3, 3, 2, 21)}, content)

	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2 (S2)", len(spans))
	}
	if spans[0].Start != 0 || spans[1].Start != 28 {
		t.Errorf("got starts %d and %d, want 0 and 28", spans[0].Start, spans[1].Start)
	}
}

func TestToSpansDropsWhatItCannotConfirm(t *testing.T) {
	cases := map[string]struct {
		content string
		finding Finding
	}{
		"a line the content does not have": {"one line", aws(99, 99, 1, 20)},
		"offsets that do not slice the match back out": {
			"deploy with " + key + " today", aws(1, 1, 14, 32),
		},
		"a span past the end of the content": {"short", aws(1, 1, 1, 400)},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// Dropping is not letting it through: respond turns a finding with
			// no span into a BLOCK.
			if spans := toSpans([]Finding{c.finding}, c.content); len(spans) != 0 {
				t.Errorf("got %+v, want none", spans)
			}
		})
	}
}

func TestToSpansOnAnEmptyReport(t *testing.T) {
	if spans := toSpans(nil, "anything"); len(spans) != 0 {
		t.Errorf("got %+v, want none", spans)
	}
}
