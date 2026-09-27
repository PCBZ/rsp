package main

import "fmt"

// Request is what a host sends. encoding/json ignores unknown fields (D8).
type Request struct {
	RSPVersion string         `json:"rsp_version"`
	Hook       string         `json:"hook"`
	Content    string         `json:"content"`
	Metadata   map[string]any `json:"metadata"`
}

// Response omits empty fields, so ALLOW carries nothing else (V2).
type Response struct {
	Verdict     string `json:"verdict"`
	Spans       []Span `json:"spans,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// Declaration is what this plugin says it is (H2).
type Declaration struct {
	RSPVersion    string   `json:"rsp_version"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Hooks         []string `json:"hooks"`
	Deterministic bool     `json:"deterministic"`
}

const replacement = "[REDACTED:secret]"

// declare carries the binary's version in its own: the tool decides verdicts (D4).
func declare() (Declaration, error) {
	tool, err := version()
	if err != nil {
		return Declaration{}, err
	}
	return Declaration{
		RSPVersion:    "0.1",
		Name:          "rsp-gitleaks-go",
		Version:       fmt.Sprintf("0.1.0+%s", tool),
		Hooks:         []string{"on_chunk", "on_retrieve"},
		Deterministic: true,
	}, nil
}

func respond(request Request) (any, error) {
	if request.Hook == "handshake" {
		return declare()
	}

	findings, err := scan(request.Content)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return Response{Verdict: "ALLOW"}, nil
	}

	spans := toSpans(findings, request.Content)
	// Redacting the rest would leave an unplaced secret in the chunk.
	if len(spans) != len(findings) {
		return Response{
			Verdict:  "BLOCK",
			Reason:   "gitleaks reported a finding whose position could not be confirmed",
			Severity: "critical",
		}, nil
	}
	return Response{
		Verdict:     "REDACT",
		Spans:       spans,
		Replacement: replacement,
		Severity:    "critical",
	}, nil
}
