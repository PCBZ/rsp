"""The kit, run the way somebody who does not have this repository would.

`conformance/` plus a plugin, in a directory with no `rsp/` in it and nothing
installed. That is the condition the kit exists to meet: a plugin author
checks their plugin against the protocol, not against our implementation of
it, and cannot be asked to install the thing whose behaviour is not under
test.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).parent.parent


@pytest.fixture
def elsewhere(tmp_path: pathlib.Path) -> pathlib.Path:
    """A copy of the kit and the reference plugin, and nothing else."""
    shutil.copytree(ROOT / "conformance", tmp_path / "conformance")
    shutil.copytree(ROOT / "plugins", tmp_path / "plugins")
    assert not (tmp_path / "rsp").exists(), "the runtime is the thing that must be absent"
    return tmp_path


def run(where: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "conformance/run.py", *arguments],
        cwd=where,
        capture_output=True,
        text=True,
        check=False,
        # PYTHONPATH unset: an import of `rsp` would have to find it, and it
        # is not there to find.
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(where)},
    )


def test_the_kit_runs_with_the_runtime_source_absent(elsewhere: pathlib.Path) -> None:
    done = run(elsewhere, "--role", "echo", "--", sys.executable, "plugins/rsp-echo/main.py")

    assert done.returncode == 0, done.stdout + done.stderr
    assert "10/10 cases" in done.stderr, done.stderr
    assert "clauses settled" in done.stderr


def test_a_plugin_that_fails_a_case_is_reported_and_exits_non_zero(
    elsewhere: pathlib.Path,
) -> None:
    """The kit is only useful if it can say no."""
    lying = elsewhere / "plugins" / "lying.py"
    lying.write_text(
        'import json, sys\njson.load(sys.stdin)\nprint(json.dumps({"verdict": "ALLOW"}))\n',
        encoding="utf-8",
    )

    done = run(elsewhere, "--role", "echo", "--", sys.executable, "plugins/lying.py")

    assert done.returncode == 1
    assert "FAIL" in done.stdout
    assert "10/10" not in done.stderr


def test_an_unknown_role_is_refused(elsewhere: pathlib.Path) -> None:
    done = run(elsewhere, "--role", "nonesuch", "--", sys.executable, "plugins/rsp-echo/main.py")

    assert done.returncode == 2
    assert "no cases for role" in done.stderr
