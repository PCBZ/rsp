// Which report becomes which verdict, through a stand-in binary so the
// interesting case can be provoked: a finding that cannot be placed.
package main

import (
	"path/filepath"
	"testing"
)

func fake(t *testing.T, report string, exit string) {
	t.Helper()
	path, err := filepath.Abs("testdata/fake-gitleaks.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RSP_GITLEAKS", path)
	t.Setenv("FAKE_GITLEAKS_REPORT", report)
	t.Setenv("FAKE_GITLEAKS_EXIT", exit)
}

func verdict(t *testing.T, request Request) Response {
	t.Helper()
	answer, err := respond(request)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	response, ok := answer.(Response)
	if !ok {
		t.Fatalf("got %T, want a Response", answer)
	}
	return response
}

func TestAllowsAChunkNothingWasFoundIn(t *testing.T) {
	fake(t, "", "0")

	if got := verdict(t, Request{Hook: "on_chunk", Content: "nothing here"}); got.Verdict != "ALLOW" {
		t.Errorf("got %+v, want ALLOW", got)
	}
}

func TestRedactsWhatItCanPlace(t *testing.T) {
	content := "deploy with " + key + " today"
	fake(t, `[{"RuleID":"aws-access-token","StartLine":1,"EndLine":1,`+
		`"StartColumn":13,"EndColumn":32,"Match":"`+key+`"}]`, "2")

	got := verdict(t, Request{Hook: "on_chunk", Content: content})

	if got.Verdict != "REDACT" || len(got.Spans) != 1 {
		t.Fatalf("got %+v, want one REDACT span", got)
	}
	if got.Spans[0] != (Span{Start: 12, End: 32, Type: "aws-access-token"}) {
		t.Errorf("got %+v", got.Spans[0])
	}
	if got.Replacement != replacement {
		t.Errorf("got replacement %q", got.Replacement)
	}
}

func TestBlocksRatherThanRedactingWhatItCanPlace(t *testing.T) {
	// One of two findings mislocated: reporting the good span publishes the
	// other secret, and ALLOW publishes both.
	content := "deploy with " + key + " today"
	fake(t, `[{"RuleID":"aws-access-token","StartLine":1,"EndLine":1,`+
		`"StartColumn":13,"EndColumn":32,"Match":"`+key+`"},`+
		`{"RuleID":"aws-access-token","StartLine":1,"EndLine":1,`+
		`"StartColumn":99,"EndColumn":118,"Match":"`+key+`"}]`, "2")

	got := verdict(t, Request{Hook: "on_chunk", Content: content})

	if got.Verdict != "BLOCK" {
		t.Fatalf("got %+v, want BLOCK", got)
	}
	if got.Reason == "" {
		t.Error("BLOCK should say why (V4)")
	}
}

func TestBlocksOnAFindingWithNoPosition(t *testing.T) {
	fake(t, `[{"RuleID":"aws-access-token","Match":"`+key+`"}]`, "2")

	if got := verdict(t, Request{Hook: "on_chunk", Content: key}); got.Verdict != "BLOCK" {
		t.Errorf("got %+v, want BLOCK", got)
	}
}

func TestRefusesToAnswerWhenTheBinaryFails(t *testing.T) {
	// Nothing on stdout, exactly like a clean chunk (E1, D3).
	fake(t, "", "1")

	if _, err := respond(Request{Hook: "on_chunk", Content: key}); err == nil {
		t.Error("want an error, got a verdict")
	}
}

func TestRefusesToAnswerOnAReportThatIsNotAReport(t *testing.T) {
	fake(t, "not json", "2")

	if _, err := respond(Request{Hook: "on_chunk", Content: key}); err == nil {
		t.Error("want an error, got a verdict")
	}
}

func TestDeclaresTheWrappedToolsVersionInItsOwn(t *testing.T) {
	// D4: the adapter's version alone would outlive the ruleset it judged with.
	fake(t, "8.30.1", "0")

	answer, err := respond(Request{Hook: "handshake"})
	if err != nil {
		t.Fatal(err)
	}
	declaration, ok := answer.(Declaration)
	if !ok {
		t.Fatalf("got %T, want a Declaration", answer)
	}
	if declaration.Version != "0.1.0+8.30.1" {
		t.Errorf("got version %q", declaration.Version)
	}
}
