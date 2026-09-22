// One JSON object in, one out, then exit (T1). Diagnostics go to stderr:
// stdout is the protocol channel and a stray line on it is indistinguishable
// from a response (T2).
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if err := answer(); err != nil {
		fmt.Fprintln(os.Stderr, "rsp-gitleaks-go:", err)
		os.Exit(1)
	}
}

func answer() error {
	var request Request
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	response, err := respond(request)
	if err != nil {
		return err
	}
	// SetEscapeHTML(false): the default turns < and & into escapes, which is
	// valid JSON a host would decode back, but the wire should carry what the
	// plugin meant.
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
