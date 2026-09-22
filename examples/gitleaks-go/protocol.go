package main

import "fmt"

// Request is what a host sends. Unknown fields are ignored, which
// encoding/json does by default (D8).
type Request struct {
	RSPVersion string         `json:"rsp_version"`
	Hook       string         `json:"hook"`
	Content    string         `json:"content"`
	Metadata   map[string]any `json:"metadata"`
}

// Response is one of the verdicts this plugin returns. Fields are omitted when
// empty so that ALLOW carries nothing else (V2).
type Response struct {
	Verdict     string `json:"verdict"`
	Spans       []Span `json:"spans,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// Declaration is what this plugin tells a host about itself (H2).
type Declaration struct {
	RSPVersion    string   `json:"rsp_version"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Hooks         []string `json:"hooks"`
	Deterministic bool     `json:"deterministic"`
}

const replacement = "[REDACTED:secret]"

// declare reports the plugin's identity, carrying the binary's version in its
// own: a cache key contains the plugin version (D4), and for a wrapper it is
// the wrapped tool that decides verdicts, so gitleaks gaining a rule has to
// change this string.
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

// respond answers one request.
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
	// A finding that produced no span is a secret gitleaks found and this
	// adapter could not point at. Redacting the others would leave that one in
	// the chunk, so nothing goes downstream (V4).
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
