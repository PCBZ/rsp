#!/usr/bin/env python3
"""The reference plugin, and the runtime's test instrument.

Stdlib only, deliberately: a plugin is a process that reads JSON on stdin and
writes JSON on stdout. No SDK, no language requirement — this one is Python
because the runtime is.

Content markers select the verdict, so fixtures can drive all four:

    RSP-BLOCK -> BLOCK    RSP-FLAG -> FLAG    secret -> REDACT    else ALLOW

    echo '{"rsp_version":"0.1","hook":"on_chunk","content":"a secret here"}' \
        | python3 plugins/rsp-echo/main.py
"""

import json
import sys

RSP_VERSION = "0.1"
REDACT_MARKER = "secret"
REPLACEMENT = "[REDACTED:echo-test]"

# The handshake is its own invocation, not a first message on a stream:
# one call is one process in v0.1 (Q6).
HANDSHAKE = {
    "rsp_version": RSP_VERSION,
    "name": "rsp-echo",
    "version": "0.1.0",
    "hooks": ["on_chunk", "on_retrieve", "on_response"],
    "deterministic": True,
}


def spans_for(content: str) -> list[dict]:
    """Byte offsets into the UTF-8 encoding, half-open (D6).

    Computed on bytes, not the str, so any language produces the same numbers.
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
    # The wire is UTF-8 (M1), whatever locale the host was started in. Python
    # picks the locale's encoding for stdin and stdout otherwise, which makes
    # a plugin that works on one machine fail on another over content it never
    # looked at.
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")

    # stdout is the protocol channel; diagnostics go to stderr (T2).
    print("rsp-echo: reading request", file=sys.stderr)
    request = json.load(sys.stdin)
    json.dump(evaluate(request), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
