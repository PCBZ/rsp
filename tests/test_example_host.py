"""The one-file host in examples/host, run as a reader runs it.

Its README shows a transcript; an example whose output nobody checks is
prose. This runs the program and reads what it printed.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

from plugins import ROOT

HOST = ROOT / "examples" / "host"
TRANSCRIPT = re.compile(r"```console\n\$ [^\n]+\n(.*?)```", re.DOTALL)


def run(where: pathlib.Path) -> str:
    done = subprocess.run(
        [sys.executable, str(HOST / "main.py")],
        cwd=where,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return done.stdout


def test_the_example_blocks_redacts_and_keeps() -> None:
    """One document refused, one rewritten, one clean: a guard that flags everything proves nothing."""
    printed = run(ROOT)

    assert "2 chunks indexed, 1 refused" in printed, printed
    assert "blocked  runbook-incident.md: BLOCK" in printed, printed
    assert "redact   deploy-notes.md" in printed, printed


def test_the_retrieve_guard_drops_what_the_index_already_held() -> None:
    """The second seam, and the reason it is not redundant with the first."""
    printed = run(ROOT)

    assert "retrieved 3, answered with 2" in printed, printed
    assert "(no source)" not in printed, "the node the store already held survived retrieval"


def test_it_runs_from_any_directory(tmp_path: pathlib.Path) -> None:
    """Its config names the plugin beside itself, so where a reader stands cannot matter."""
    assert "2 chunks indexed, 1 refused" in run(tmp_path)


def test_the_readme_transcript_is_what_it_prints() -> None:
    """A transcript nobody reruns is the output of a version that is gone."""
    shown = TRANSCRIPT.search((HOST / "README.md").read_text(encoding="utf-8"))
    assert shown, "examples/host/README.md no longer shows a console transcript"

    printed = run(ROOT)
    for line in (one for one in shown.group(1).splitlines() if one.strip()):
        assert line in printed, f"the README shows a line the program does not print: {line!r}"


def test_nothing_it_prints_quotes_the_content() -> None:
    """A report that repeats what was found is another copy of it."""
    printed = run(ROOT)

    for document in sorted((HOST / "docs").glob("*.md")):
        for line in document.read_text(encoding="utf-8").splitlines():
            if len(line.split()) > 4:
                assert line not in printed, f"{document.name} reached stdout"
