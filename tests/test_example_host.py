"""The one-file host in examples/host, run as a reader runs it.

Its README shows two transcripts, with and without the Go toolchain; an
example whose output nobody checks is prose. These run the program and read
what it printed.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

from plugins import REQUIRED, ROOT

HOST = ROOT / "examples" / "host"
# Both transcripts: the second is the same program with the Go half absent.
TRANSCRIPTS = re.compile(r"```console\n\$ [^\n]+\n(.*?)```", re.DOTALL)
GO_TOOLS = ("go", "gitleaks")


def run(where: pathlib.Path = ROOT, *, path: str | None = None) -> str:
    """`path` narrows PATH, which is how a reader without a Go toolchain runs it."""
    done = subprocess.run(
        [sys.executable, str(HOST / "main.py")],
        cwd=where,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=dict(os.environ) | ({"PATH": path} if path else {}),
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return done.stdout


def both() -> str:
    """The run with two plugins, or why this machine cannot do it."""
    if absent := [tool for tool in GO_TOOLS if shutil.which(tool) is None]:
        why = f"not installed: {', '.join(absent)}"
        pytest.fail(why) if REQUIRED else pytest.skip(why)
    return run()


def test_each_language_catches_what_the_other_does_not() -> None:
    """The claim the example exists to make: same pipeline, two implementations."""
    printed = both()

    assert "plugins: echo, gitleaks-go" in printed, printed
    assert "redact   deploy-notes.md          echo-test" in printed, printed
    assert "redact   mirror-credentials.md    aws-access-token" in printed, printed


def test_the_python_plugin_alone_still_runs_and_says_what_it_lost() -> None:
    """A host is as strict as the plugins it can start, and should say which it could not."""
    printed = run(path="/usr/bin:/bin")

    assert "skipping gitleaks-go: no go, gitleaks" in printed, printed
    assert "plugins: echo " in printed, printed
    assert "echo-test" in printed, printed
    assert "aws-access-token" not in printed, "the Go plugin cannot have found anything"


def test_the_ingest_guard_refuses_one_and_keeps_the_rest() -> None:
    """One refused, two rewritten, one clean: a guard that flags everything proves nothing."""
    printed = both()

    assert "3 chunks indexed, 1 refused" in printed, printed
    assert "blocked  runbook-incident.md      echo: marker RSP-BLOCK" in printed, printed


def test_the_retrieve_guard_drops_what_the_index_already_held() -> None:
    """The second seam, and the reason it is not redundant with the first."""
    printed = both()

    assert "retrieved 4, answered with 3" in printed, printed
    assert "(no source)" not in printed, "the node the store already held survived retrieval"


def test_it_runs_from_any_directory(tmp_path: pathlib.Path) -> None:
    """Its config names both plugins beside itself, so where a reader stands cannot matter."""
    if [tool for tool in GO_TOOLS if shutil.which(tool) is None]:
        pytest.skip("needs both plugins to be worth asserting")

    assert "plugins: echo, gitleaks-go" in run(tmp_path)


def test_both_readme_transcripts_are_what_it_prints() -> None:
    """A transcript nobody reruns is the output of a version that is gone."""
    shown = TRANSCRIPTS.findall((HOST / "README.md").read_text(encoding="utf-8"))
    assert len(shown) == 2, "the README no longer shows a run with and without the Go half"

    printed = (both(), run(path="/usr/bin:/bin"))
    for transcript, output in zip(shown, printed, strict=True):
        for line in (one for one in transcript.splitlines() if one.strip()):
            assert line in output, f"the README shows a line the program does not print: {line!r}"


def test_nothing_it_prints_quotes_the_content() -> None:
    """A report that repeats what was found is another copy of it."""
    printed = both()

    for document in sorted((HOST / "docs").glob("*.md")):
        for line in document.read_text(encoding="utf-8").splitlines():
            if len(line.split()) > 4:
                assert line not in printed, f"{document.name} reached stdout"
