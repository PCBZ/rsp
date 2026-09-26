// Package main wraps gitleaks using only `gitleaks stdin` and its report.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// Span is a range to mask, in byte offsets (S1), which is what a Go string indexes.
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

// toSpans converts gitleaks' positions to byte offsets, dropping a finding it
// cannot place. The quirks it corrects are the notes in gitleaks-offsets.json.
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
		if !usable(span, content) || content[span.Start:span.End] != f.Match {
			continue
		}
		spans = append(spans, span)
	}
	return spans
}

// usable reports whether a span is in range, non-empty, and on char boundaries.
func usable(span Span, content string) bool {
	boundary := func(at int) bool { return at == len(content) || content[at]&0xC0 != 0x80 }
	return span.Start >= 0 && span.End <= len(content) && span.End > span.Start &&
		boundary(span.Start) && boundary(span.End)
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

// run executes the binary once. A failed run prints nothing, like a clean
// chunk, so only the status tells them apart (E1, D3).
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

func version() (string, error) {
	return run([]string{"version"}, "")
}

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
