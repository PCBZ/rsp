// Package main wraps the gitleaks binary. Same tool, same two public
// interfaces as the TypeScript plugin — the `gitleaks stdin` command and the
// field names of its JSON report — so the two are comparable answers to the
// same question rather than two programs that happen to detect secrets.
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// Span is a range to mask, in byte offsets into the UTF-8 encoding.
//
// A Go string is a byte slice, so content[start:end] already means what S1
// says it means. This is the language D6 was chosen for: nothing converts.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Type  string `json:"type"`
}

// Finding is the part of a gitleaks report this adapter reads. The report
// carries more — commit, author, entropy — none of which a chunk has.
type Finding struct {
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Match       string
}

// found is the exit code gitleaks is told to use for "found something", so it
// is distinct from the code it uses for its own failures.
const found = 2

func binary() string {
	if override := os.Getenv("RSP_GITLEAKS"); override != "" {
		return override
	}
	return "gitleaks"
}

// toSpans converts gitleaks' line and column numbers into byte offsets.
//
// Its columns are byte columns, counted from the newline byte that ends the
// previous line rather than from the first byte of the line: detect/location.go
// computes startColumn = start - prevNewLine + 1, and the first line, having no
// such byte, counts from zero. A finding can also end on a later line than it
// starts on, and EndColumn belongs to that line.
//
// A finding whose offsets do not slice Match back out is dropped: a wrong span
// redacts the wrong bytes, and a short one leaves part of the secret behind.
// The caller turns a dropped finding into a BLOCK.
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
		if span.Start < 0 || span.End > len(content) || span.Start > span.End {
			continue
		}
		if content[span.Start:span.End] != f.Match {
			continue
		}
		spans = append(spans, span)
	}
	return spans
}

// origin reports the byte gitleaks counts this line's columns from.
func origin(origins []int, line int) (int, bool) {
	if line == 1 {
		return 0, true
	}
	if line < 1 || line > len(origins) {
		return 0, false
	}
	return origins[line-1] - 1, true
}

// columnOrigins gives the byte offset at which each line begins.
func columnOrigins(content string) []int {
	starts := []int{0}
	for at := 0; at < len(content); at++ {
		if content[at] == '\n' {
			starts = append(starts, at+1)
		}
	}
	return starts
}

// run executes the binary once. The exit status is the reason this function
// exists: a gitleaks that cannot run writes nothing to stdout, which is what a
// clean chunk produces, so reading only the report would turn every failure
// into an ALLOW. Errors reach main, which exits without answering, and the
// host's error path blocks the chunk (E1, D3).
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

// version asks the binary what it is, so a cache key can include it (D4).
func version() (string, error) {
	return run([]string{"version"}, "")
}

// scan returns the findings for one chunk. An empty report means nothing.
func scan(content string) ([]Finding, error) {
	// --no-banner keeps stdout to the report alone; "-" is gitleaks' own
	// spelling of stdout, and /dev/stdout is not: it checks the report path is
	// writable before scanning, and opening that file fails.
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
