// One JSON object in, one out, then exit (T1); diagnostics to stderr (T2).
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
	// A host would decode \u003c back, but the wire should say what was meant.
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
