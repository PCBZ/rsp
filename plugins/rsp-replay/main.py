#!/usr/bin/env python3
"""A plugin that does what a host case tells it to, including badly.

Host cases need misbehaviour on request — a crash for E1, a hang for E4, a bad
span for S3 — so this reads a script from the file named by its argument or by
`RSP_REPLAY`, and answers what the case wrote down. Stdlib only, no detection.
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
    "hooks": ["on_chunk", "on_retrieve"],  # not on_response, which §4 reserves
    "deterministic": True,
}

FOREVER = 30  # outlasts any bound a case sets, without leaking a process for long


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

    # The hook and content as received: a scripted answer cannot show what it was asked (H3, S5).
    if witness := os.environ.get("RSP_REPLAY_CALLS"):
        with pathlib.Path(witness).open("a", encoding="utf-8") as log:
            log.write(
                json.dumps({"hook": request.get("hook"), "content": request.get("content")}) + "\n"
            )

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
        case "flood":
            # More stdout than a host keeps (E1).
            sys.stdout.write("x" * 100_000 + "\n")
        case "raw":
            # Verbatim, so a case can send what json.dumps would not.
            sys.stdout.write(plan["raw"] + "\n")
        case "noisy":
            # A valid answer under a flood of diagnostics, which are not the protocol's (E3).
            print("x" * 100_000, file=sys.stderr)
            print(json.dumps(plan["reply"]))
        case None:
            print(json.dumps(plan["reply"]))
        case unknown:
            # Named, so a typo is not mistaken for the crash a case asked for.
            raise SystemExit(f"rsp-replay: no such behaviour: {unknown!r}")


if __name__ == "__main__":
    main()
