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
        # An ASCII locale, with the coercion that would quietly undo it
        # switched off (PEP 538): the cases carry 密钥, and a harness that let
        # the locale choose would fail to encode the request at all.
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(where),
            "LC_ALL": "C",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONUTF8": "0",
        },
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


def test_an_unknown_role_is_refused_and_names_the_real_ones(elsewhere: pathlib.Path) -> None:
    done = run(elsewhere, "--role", "nonesuch", "--", sys.executable, "plugins/rsp-echo/main.py")

    assert done.returncode == 2
    assert "no cases for role" in done.stderr
    assert "echo" in done.stderr and "gitleaks" in done.stderr, "say what was available"


def test_the_roles_can_be_listed_without_a_plugin(elsewhere: pathlib.Path) -> None:
    """The first question is which cases apply, and answering it should not
    require guessing the answer first."""
    done = run(elsewhere, "--list-roles")

    assert done.returncode == 0
    assert "echo" in done.stdout and "gitleaks" in done.stdout


def test_without_a_role_every_role_is_tried(elsewhere: pathlib.Path) -> None:
    """A plugin conforms to a role rather than in general. Asked without one,
    the kit reports each — the reference plugin answers markers, so it passes
    the echo cases and fails the ones written for a gitleaks wrapper, which is
    how its author learns which it is."""
    done = run(elsewhere, "--", sys.executable, "plugins/rsp-echo/main.py")

    assert done.returncode == 0, "passing one role in full is conformance to that role"
    assert "10/10 cases for echo" in done.stderr
    assert "cases for gitleaks" in done.stderr


MISBEHAVING = {
    "output that is not UTF-8": (
        "import sys\nsys.stdin.read()\nsys.stdout.buffer.write(b'\\xff\\xfe not text\\n')\n",
        "not UTF-8",
    ),
    "valid JSON that is not an object": (
        "import sys\nsys.stdin.read()\nprint('null')\n",
        "expected a JSON object",
    ),
}


@pytest.mark.parametrize(("source", "expected"), MISBEHAVING.values(), ids=list(MISBEHAVING))
def test_a_plugin_cannot_stop_the_run(elsewhere: pathlib.Path, source: str, expected: str) -> None:
    """The kit exists to test plugins that misbehave, so misbehaviour has to
    fail a case rather than end the run — an exception out of the harness
    takes the remaining cases with it."""
    (elsewhere / "plugins" / "rude.py").write_text(source, encoding="utf-8")

    done = run(elsewhere, "--role", "echo", "--", sys.executable, "plugins/rude.py")

    assert done.returncode == 1
    assert expected in done.stdout, done.stdout + done.stderr
    assert "10 cases" in done.stderr, "every case ran, not just the first"


def test_the_plugin_keeps_its_own_separator(elsewhere: pathlib.Path) -> None:
    """Only the leading `--` is the runner's. A command that needs its own
    would otherwise be run as a different command."""
    (elsewhere / "plugins" / "needs.py").write_text(
        "import json, sys\n"
        "assert sys.argv[1:] == ['--', 'inner'], sys.argv\n"
        "json.load(sys.stdin)\n"
        'print(json.dumps({"verdict": "ALLOW"}))\n',
        encoding="utf-8",
    )

    done = run(elsewhere, "--role", "echo", "--", sys.executable, "plugins/needs.py", "--", "inner")

    # It answers ALLOW to everything, so it fails cases — but on the verdict,
    # which means it was started with the arguments it asked for.
    assert "exited 1" not in done.stdout, done.stdout
