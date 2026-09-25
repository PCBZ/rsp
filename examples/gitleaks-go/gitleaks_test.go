// Line-and-column to byte offsets. No binary needed: a report is data.
//
// The table is examples/gitleaks-offsets.json, shared with the Rust and
// TypeScript adapters, because the numbers in it are facts about gitleaks
// rather than about any of the three. What stays here is what this language
// makes possible and the others do not.
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
	// Outside the module, so `go test` does not track it and will serve a
	// cached pass after the table changes. CI and the README pass -count=1.
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
	// Offsets inside 密, with Match the bytes they actually cover, so only the
	// boundary check can refuse them. Each adapter spells those two bytes in
	// its own way and none of the spellings is valid UTF-8, which is why this
	// case cannot live in a JSON table with the rest.
	inside := Finding{RuleID: "private-key", StartLine: 1, EndLine: 1,
		StartColumn: 2, EndColumn: 3, Match: "\xaf\x86"}

	if spans := toSpans([]Finding{inside}, "密钥 "+key); len(spans) != 0 {
		t.Errorf("got %+v, want none", spans)
	}
}
