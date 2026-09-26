// Line-and-column to byte offsets. No binary needed: a report is data.
// Cases belong in the shared table; only what it cannot hold stays here.
package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

type Case struct {
	ID       int      `json:"tcId"`
	Comment  string   `json:"comment"`
	Flags    []string `json:"flags"`
	Content  string   `json:"content"`
	Findings []Finding
	Spans    []Span
}

type Table struct {
	Notes map[string]string
	Tests []Case
}

func table(t *testing.T) Table {
	t.Helper()
	// Outside the module, so `go test` caches past a change to it: use -count=1.
	raw, err := os.ReadFile("../gitleaks-offsets.json")
	if err != nil {
		t.Fatal(err)
	}
	var loaded Table
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	// A path that resolved to nothing would leave this test green and empty.
	if len(loaded.Tests) < 13 {
		t.Fatalf("the table lost cases: %d", len(loaded.Tests))
	}
	return loaded
}

func TestEveryCaseInTheSharedTable(t *testing.T) {
	loaded := table(t)

	for _, c := range loaded.Tests {
		t.Run(c.Comment, func(t *testing.T) {
			got := toSpans(c.Findings, c.Content)
			if len(got) == 0 && len(c.Spans) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.Spans) {
				why := make([]string, 0, len(c.Flags))
				for _, flag := range c.Flags {
					why = append(why, loaded.Notes[flag])
				}
				t.Errorf("%d: got %+v, want %+v\n%s", c.ID, got, c.Spans, strings.Join(why, "\n"))
			}
		})
	}
}

const key = "AKIALALEMEL33243OLIB"

func TestToSpansDropsASpanInsideACharacter(t *testing.T) {
	// Offsets inside 密, with Match what they cover, so only the boundary check
	// refuses them. The shared table cannot hold it: those bytes are not UTF-8.
	inside := Finding{RuleID: "private-key", StartLine: 1, EndLine: 1,
		StartColumn: 2, EndColumn: 3, Match: "\xaf\x86"}

	if spans := toSpans([]Finding{inside}, "密钥 "+key); len(spans) != 0 {
		t.Errorf("got %+v, want none", spans)
	}
}
