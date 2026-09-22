// One JSON object in, one out, then exit (T1). Diagnostics go to stderr: a
// stray line on stdout is indistinguishable from a response (T2).
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
	// The default escapes < and &, which a host decodes back, but the wire
	// should carry what the plugin meant.
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
