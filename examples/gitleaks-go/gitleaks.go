// Package main wraps the gitleaks binary, through the same two interfaces as
// the TypeScript plugin: the `gitleaks stdin` command and its report's fields.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// Span is a range to mask, in byte offsets (S1). A Go string is a byte slice,
// so content[start:end] already means that: nothing converts.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
}

// Finding is the part of a gitleaks report a chunk can have.
type Finding struct {
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Match       string
}

// found separates "found something" from gitleaks failing, which shares 1.
const found = 2

func binary() string {
	if override := os.Getenv("RSP_GITLEAKS"); override != "" {
		return override
	}
	return "gitleaks"
}

// toSpans converts gitleaks' positions into byte offsets.
//
// Its columns count from the newline byte ending the previous line, not from
// the line's first byte, so only line one matches the 1-based column anyone
// assumes. EndColumn belongs to EndLine, which differs whenever a finding
// spans lines. Anything that does not slice Match back out is dropped, and the
// caller turns a dropped finding into a BLOCK.
func toSpans(findings []Finding, content string) []Span {
	origins := columnOrigins(content)
	spans := make([]Span, 0, len(findings))

	for _, f := range findings {
		from, ok := origin(origins, f.StartLine)
		to, okEnd := origin(origins, f.EndLine)
		if !ok || !okEnd {
			continue
		}
		span := Span{Start: from + f.StartColumn - 1, End: to + f.EndColumn, Type: f.RuleID}
		// End > Start, not >=: a span that masks nothing is not a span, and an
		// empty Match would otherwise satisfy the slice check below from any
		// pair of offsets, including one inside a rune.
		if span.Start < 0 || span.End > len(content) || span.End <= span.Start {
			continue
		}
		if content[span.Start:span.End] != f.Match {
			continue
		}
		spans = append(spans, span)
	}
	return spans
}

// origin is the byte gitleaks counts this line's columns from.
func origin(origins []int, line int) (int, bool) {
	if line == 1 {
		return 0, true
	}
	if line < 1 || line > len(origins) {
		return 0, false
	}
	return origins[line-1] - 1, true
}

// columnOrigins is where each line begins.
func columnOrigins(content string) []int {
	starts := []int{0}
	for at := 0; at < len(content); at++ {
		if content[at] == '\n' {
			starts = append(starts, at+1)
		}
	}
	return starts
}

// run executes the binary once. The status is why this exists: a gitleaks that
// could not run prints nothing, exactly like a clean chunk, so ignoring it
// would turn every failure into an ALLOW (E1, D3).
func run(args []string, input string) (string, error) {
	cmd := exec.Command(binary(), args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == found {
		err = nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// version is carried in the declaration so a cache key includes it (D4).
func version() (string, error) {
	return run([]string{"version"}, "")
}

// scan returns the findings for one chunk.
func scan(content string) ([]Finding, error) {
	// "-" is gitleaks' own spelling of stdout; /dev/stdout fails its writability
	// pre-check. --no-banner keeps stdout to the report alone.
	report, err := run([]string{
		"stdin", "--no-banner", "--report-format", "json",
		"--report-path", "-", "--exit-code", "2",
	}, content)
	if err != nil || report == "" {
		return nil, err
	}
	var findings []Finding
	if err := json.Unmarshal([]byte(report), &findings); err != nil {
		return nil, err
	}
	return findings, nil
}
