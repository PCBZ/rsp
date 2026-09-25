#!/usr/bin/env python3
"""A plugin that does what a host case tells it to, including badly.

Host cases need a plugin whose behaviour is an input rather than a fixture: a
crash for E1, a hang for E4, a span outside the content for S3. Real plugins
are not obliging enough to fail on request, so this one reads its script from
the file named by `RSP_REPLAY` and follows it.

Stdlib only, like the reference plugin, and no detection of any kind — what it
answers is whatever the case wrote down.
"""

import json
import os
import pathlib
import sys
import time

DECLARATION = {
    "rsp_version": "0.1",
    "name": "rsp-replay",
    "version": "0.1.0",
    # Not on_response: the spec reserves it, and a plugin declaring a hook no
    # host implements would be modelling something nobody can do.
    "hooks": ["on_chunk", "on_retrieve"],
    "deterministic": True,
}

# Long enough to outlast any bound a case configures, short enough that a
# leaked process is a nuisance rather than an hour of one.
FOREVER = 30


def script() -> dict:
    """The case, named by argument so one host case can run several of these."""
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ["RSP_REPLAY"]
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main() -> None:
    # The wire is UTF-8 (M1), not the locale's idea of it.
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")

    plan = script()
    request = json.loads(sys.stdin.read() or "{}")

    # A hook this plugin should never have been asked about leaves no other
    # trace: the case asserting a verdict cannot tell "not called" from
    # "called and ignored".
    if witness := os.environ.get("RSP_REPLAY_CALLS"):
        with pathlib.Path(witness).open("a", encoding="utf-8") as log:
            log.write(f"{request.get('hook')}\n")

    if request.get("hook") == "handshake":
        print(json.dumps(plan.get("declaration", DECLARATION)))
        return

    match plan.get("behaviour"):
        case "crash":
            sys.exit(3)
        case "hang":
            time.sleep(FOREVER)
        case "garbage":
            print("this is not JSON")
        case "chatty":
            # Two objects where the protocol allows one (T1, T2).
            print(json.dumps({"verdict": "ALLOW"}))
            print(json.dumps({"verdict": "ALLOW"}))
        case "silent":
            pass
        case "raw":
            # Verbatim, so a case can send what json.dumps would not: a
            # repeated key, an integer no parser agrees on, a lone surrogate.
            sys.stdout.write(plan["raw"] + "\n")
        case "noisy":
            # A valid answer and a flood of diagnostics. Only the answer is
            # the protocol's (E3).
            print("x" * 100_000, file=sys.stderr)
            print(json.dumps(plan["reply"]))
        case None:
            print(json.dumps(plan["reply"]))
        case unknown:
            # Falling through to `reply` would exit non-zero on a missing key,
            # which a host reads as a crash — so a typo in a case file would
            # pass every case about crashing.
            raise SystemExit(f"rsp-replay: no such behaviour: {unknown!r}")


if __name__ == "__main__":
    main()
