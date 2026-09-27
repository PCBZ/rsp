"""The adapters, against the corpus gitleaks tests itself with.

Tests the translation, not detection, which is gitleaks' claim; upstream's files
are shapes nobody here chose. Differential: gitleaks answers directly as the
oracle and again through a plugin and the host. The oracle's command is spelled
out, not imported, so an adapter's change of invocation shows as a disagreement.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from typing import NamedTuple

import pytest

from plugins import REQUIRED, Implementation, for_role
from rsp.runtime import Plugin, Result, Runtime, Verdict

IMPLEMENTATIONS = for_role("gitleaks")

# From the binary's own release, or the two disagree for reasons that are nobody's bug.
CORPUS = os.environ.get("RSP_GITLEAKS_CORPUS")
GITLEAKS = os.environ.get("RSP_GITLEAKS") or "gitleaks"

# Archive scanning is gitleaks' feature, not the plugin's: the protocol carries text (M1).
BINARY = (".7z", ".tar", ".zip", ".zst", ".xz", ".gz", ".png", ".jpg", ".pdf")
# Too long for a coincidence, short enough that leaving this much behind is a leak.
WINDOW = 16
FLOOR = 5


def _corpus() -> list[pathlib.Path]:
    if CORPUS is None:
        return []
    root = pathlib.Path(CORPUS)
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not path.name.endswith(BINARY) and path.stat().st_size > 0
    )


CASES = _corpus()


def _text(path: pathlib.Path) -> str | None:
    """None if not UTF-8: a chunk is text by the time a plugin sees it."""
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return None


def _oracle(content: str) -> list[dict]:
    """What gitleaks says, asked directly."""
    proc = subprocess.run(
        [
            GITLEAKS,
            "stdin",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--exit-code",
            "2",
        ],
        input=content.encode("utf-8"),
        capture_output=True,
        check=False,
        timeout=30,
    )
    if proc.returncode not in (0, 2):
        pytest.fail(f"gitleaks exited {proc.returncode}: {proc.stderr.decode()[:400]}")
    report = proc.stdout.decode("utf-8").strip()
    return json.loads(report) if report else []


def _windows(secret: str) -> list[str]:
    """Every window, one character apart: a coarser stride leaves gaps a survivor sits in."""
    if len(secret) <= WINDOW:
        return [secret]
    return [secret[at : at + WINDOW] for at in range(len(secret) - WINDOW + 1)]


class Answer(NamedTuple):
    content: str
    findings: list[dict]
    result: Result


_ANSWERS: dict[tuple[pathlib.Path, str], Answer] = {}
_RUNTIMES: dict[str, Runtime] = {}


def runtime_for(implementation: Implementation) -> Runtime:
    """One handshake per implementation, not per file."""
    if implementation.name not in _RUNTIMES:
        _RUNTIMES[implementation.name] = Runtime(
            [Plugin(name=implementation.name, command=list(implementation.command))]
        )
    return _RUNTIMES[implementation.name]


def answer(path: pathlib.Path, implementation: Implementation) -> Answer:
    """Both answers for one file and plugin, cached because four tests read each pair."""
    key = (path, implementation.name)
    if key not in _ANSWERS:
        content = _text(path)
        if content is None:
            pytest.skip("not UTF-8")
        result = runtime_for(implementation).evaluate("on_chunk", content)
        _ANSWERS[key] = Answer(content, _oracle(content), result)
    return _ANSWERS[key]


@pytest.fixture(autouse=True)
def _guard_the_environment(request: pytest.FixtureRequest) -> None:
    """Skip or fail up front; no clause column, as fidelity to gitleaks is not a SPEC.md clause."""
    # The oracle runs the binary directly, with or without an implementation.
    if shutil.which(GITLEAKS) is None:
        message = f"not installed: {GITLEAKS}"
        pytest.fail(message) if REQUIRED else pytest.skip(message)

    callspec = getattr(request.node, "callspec", None)
    implementation = callspec.params.get("implementation") if callspec else None
    if implementation is not None:
        request.getfixturevalue("record_property")("plugin", implementation.name)
        if not implementation.installed:
            message = f"not installed: {implementation.missing}"
            pytest.fail(message) if REQUIRED else pytest.skip(message)
    if CORPUS is None:
        pytest.fail("no corpus") if REQUIRED else pytest.skip("no corpus")


def _ids(value: object) -> str:
    if isinstance(value, Implementation):
        return value.name
    if isinstance(value, pathlib.Path) and CORPUS:
        return value.relative_to(pathlib.Path(CORPUS)).as_posix()
    return str(value)


pytestmark = pytest.mark.skipif(
    not CASES and not REQUIRED, reason="set RSP_GITLEAKS_CORPUS to run the corpus"
)


def test_the_corpus_reaches_the_adapter_at_all() -> None:
    """The tests below check nothing when gitleaks reports nothing; the floor catches zero."""
    found = 0
    for path in CASES:
        if (text := _text(path)) and _oracle(text):
            found += 1
            if found == FLOOR:
                return
    pytest.fail(
        f"only {found} of {len(CASES)} corpus files produced a finding; "
        "the corpus or the binary is not what this suite assumes"
    )


@pytest.mark.parametrize("implementation", IMPLEMENTATIONS, ids=_ids)
@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_content_with_a_finding_is_not_allowed(
    path: pathlib.Path, implementation: Implementation
) -> None:
    """REDACT, not just "not ALLOW": BLOCK means a finding could not be placed."""
    _, findings, result = answer(path, implementation)

    if not findings:
        assert result.verdict is Verdict.ALLOW, f"allowed nothing, got {result.reasons}"
        return
    assert result.verdict is Verdict.REDACT, (
        f"gitleaks reported {len(findings)} finding(s) and the host said "
        f"{result.verdict.value}: {result.reasons}"
    )


@pytest.mark.parametrize("implementation", IMPLEMENTATIONS, ids=_ids)
@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_no_reported_secret_survives_redaction(
    path: pathlib.Path, implementation: Implementation
) -> None:
    """Windows, not the whole string: redacting a key's first bytes leaves the rest readable."""
    _, findings, result = answer(path, implementation)
    if not findings:
        pytest.skip("nothing reported")
    if result.verdict is Verdict.BLOCK:
        pytest.skip("blocked, so nothing is handed on")

    for finding in findings:
        for field in ("Secret", "Match"):
            value = finding.get(field)
            if not value:
                continue
            for window in _windows(value):
                assert window not in result.content, (
                    f"{finding['RuleID']}: {len(window)} bytes of {field} survived "
                    f"redaction at line {finding['StartLine']}: {window[:24]!r}"
                )


@pytest.mark.parametrize("implementation", IMPLEMENTATIONS, ids=_ids)
@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_lines_without_findings_come_back_unchanged(
    path: pathlib.Path, implementation: Implementation
) -> None:
    """Redacting the whole chunk passes the test above; this is the other half.

    A subsequence, not line numbers: a multi-line finding becomes one replacement.
    """
    content, findings, result = answer(path, implementation)
    if not findings:
        pytest.skip("nothing reported")
    if result.verdict is Verdict.BLOCK:
        pytest.skip("blocked, so nothing is handed on")

    touched = {
        line for finding in findings for line in range(finding["StartLine"], finding["EndLine"] + 1)
    }
    kept = iter(result.content.splitlines())
    for number, line in enumerate(content.splitlines(), start=1):
        if number in touched:
            continue
        assert line in kept, (
            f"line {number} had no finding and did not come back, in order and unaltered: {line!r}"
        )


@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_every_implementation_of_the_role_answers_identically(path: pathlib.Path) -> None:
    """A protocol whose implementations disagree is a suggestion."""
    installed = [one for one in IMPLEMENTATIONS if one.installed]
    if len(installed) < 2:
        pytest.skip("needs two implementations of the role")

    answers = {one.name: answer(path, one) for one in installed}
    verdicts = {name: found.result.verdict for name, found in answers.items()}
    contents = {name: found.result.content for name, found in answers.items()}

    assert len(set(verdicts.values())) == 1, f"verdicts disagree: {verdicts}"
    assert len(set(contents.values())) == 1, (
        f"the same content came back differently: {sorted(contents)}"
    )
