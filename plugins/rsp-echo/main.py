#!/usr/bin/env python3
"""Plugin call site — issue #2. The counterpart to rsp/guards.py.

guards.py defines what the runtime must offer a host. This defines what the
runtime must send a plugin, and what it gets back. SPEC.md's wire format is
reverse-engineered from the two together (#3).

Stdlib only, and deliberately so: a plugin is a process that reads JSON on
stdin and writes JSON on stdout. There is no SDK to install and no language
requirement — this one is Python because the runtime is, not because a plugin
has to be.

It is also the runtime's test instrument. Content markers select each verdict,
so a fixture can drive all four deterministically:

    RSP-BLOCK   -> BLOCK
    RSP-FLAG    -> FLAG
    secret      -> REDACT (spans over every occurrence)
    otherwise   -> ALLOW

Run it by hand:

    echo '{"rsp_version":"0.1","hook":"on_chunk","content":"a secret here"}' \
        | python3 plugins/rsp-echo/main.py
"""

import json
import sys

RSP_VERSION = "0.1"
REDACT_MARKER = "secret"
REPLACEMENT = "[REDACTED:echo-test]"

# One request object in, one response object out, then exit. Spawn-per-call is
# the v0.1 model (Q6), which is why the handshake is its own invocation rather
# than a first message on a long-lived stream.
HANDSHAKE = {
    "rsp_version": RSP_VERSION,
    "name": "rsp-echo",
    "version": "0.1.0",
    "hooks": ["on_chunk", "on_retrieve", "on_response"],
    "deterministic": True,
    "max_inline_bytes": 1_048_576,
}


def spans_for(content: str) -> list[dict]:
    """Byte offsets into the UTF-8 encoding of content, half-open (D6).

    Computed on the encoded bytes, not the str, so that a plugin in any
    language produces the same numbers for the same input.
    """
    data = content.encode("utf-8")
    needle = REDACT_MARKER.encode("utf-8")
    spans, start = [], data.find(needle)
    while start != -1:
        spans.append({"start": start, "end": start + len(needle), "type": "echo-test"})
        start = data.find(needle, start + len(needle))
    return spans


def evaluate(request: dict) -> dict:
    """Unrecognized request fields are ignored, never an error (D8)."""
    if request.get("hook") == "handshake":
        return HANDSHAKE

    content = request.get("content", "")
    if "RSP-BLOCK" in content:
        return {"verdict": "BLOCK", "reason": "marker RSP-BLOCK", "severity": "critical"}
    if "RSP-FLAG" in content:
        return {"verdict": "FLAG", "reason": "marker RSP-FLAG", "severity": "low"}
    spans = spans_for(content)
    if spans:
        return {
            "verdict": "REDACT",
            "spans": spans,
            "replacement": REPLACEMENT,
            "severity": "medium",
        }
    return {"verdict": "ALLOW"}


def main() -> None:
    # stdout is the protocol channel; diagnostics go to stderr (T2).
    print("rsp-echo: reading request", file=sys.stderr)
    request = json.load(sys.stdin)
    json.dump(evaluate(request), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
