"""The adapters, against the corpus gitleaks tests itself with.

Not a detection benchmark: precision and recall would measure gitleaks, which
these plugins wrap unmodified so that detection quality is never RSP's claim.
What is ours is the translation, and upstream's files are shapes nobody here
chose — the hand-written fixtures are, and two position bugs got past them.

Differential: the same binary answers twice, once directly as the oracle and
once through a plugin and the host. The oracle's command is spelled out rather
than imported, so a change in how an adapter invokes gitleaks shows up as a
disagreement instead of being mirrored into the expectation.
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

ROOT = pathlib.Path(__file__).parent.parent
IMPLEMENTATIONS = for_role("gitleaks")

# Fetched by the plugins workflow, from the same release as the binary: a
# corpus from a different one disagrees for reasons that are nobody's bug.
CORPUS = os.environ.get("RSP_GITLEAKS_CORPUS")
GITLEAKS = os.environ.get("RSP_GITLEAKS") or "gitleaks"

# Archives are gitleaks' own feature, not the plugin's: the protocol carries
# text (M1), and a host that unpacks archives does it before any chunk exists.
BINARY = (".7z", ".tar", ".zip", ".zst", ".xz", ".gz", ".png", ".jpg", ".pdf")


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
    """The file as content, or None: a chunk is text by the time a plugin sees
    it, so a file that is not valid UTF-8 is not this plugin's problem."""
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


# Long enough that a coincidence is not plausible, short enough that leaving
# this much of a credential behind is still a leak.
WINDOW = 16


def _windows(secret: str) -> list[str]:
    """Every window, one character apart: sampling at intervals leaves gaps a
    survivor sits in. At stride eight, sixteen characters surviving from offset
    four are missed by the window at zero and the one at eight."""
    if len(secret) <= WINDOW:
        return [secret]
    return [secret[at : at + WINDOW] for at in range(len(secret) - WINDOW + 1)]


class Answer(NamedTuple):
    content: str
    findings: list[dict]
    result: Result


_ANSWERS: dict[tuple[pathlib.Path, str], Answer] = {}
_RUNTIMES: dict[str, Runtime] = {}


def answer(path: pathlib.Path, implementation: Implementation) -> Answer:
    """Both answers for one file and one plugin, asked once: four properties
    read the same pair, at two gitleaks runs apiece."""
    key = (path, implementation.name)
    if key not in _ANSWERS:
        content = _text(path)
        if content is None:
            pytest.skip("not UTF-8")
        result = runtime_for(implementation).evaluate("on_chunk", content)
        _ANSWERS[key] = Answer(content, _oracle(content), result)
    return _ANSWERS[key]


def runtime_for(implementation: Implementation) -> Runtime:
    """One handshake per implementation, not per file."""
    if implementation.name not in _RUNTIMES:
        _RUNTIMES[implementation.name] = Runtime(
            [Plugin(name=implementation.name, command=list(implementation.command))]
        )
    return _RUNTIMES[implementation.name]


@pytest.fixture(autouse=True)
def _guard_the_environment(request: pytest.FixtureRequest) -> None:
    """Skip or fail before a test asks anything, and label the report row. No
    clause: fidelity to the wrapped tool is what an adapter owes it, not
    something SPEC.md requires."""
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


FLOOR = 5


def test_the_corpus_reaches_the_adapter_at_all() -> None:
    """Every property below is conditional on gitleaks reporting something, so
    one that reports nothing turns this file green while checking nothing.
    Stops at the floor: the point is to catch zero."""
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
    """An adapter that placed no span and a gitleaks that never ran both look
    like clean content. REDACT rather than "not ALLOW": BLOCK here means a
    finding could not be placed, and the placement rate has to be one."""
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
    """Checked in windows, not whole: a span covering a private key's first
    thirty bytes destroys the exact string while leaving the key readable, so
    asking whether `Secret` is still a substring passes a redaction that leaked
    nearly all of it."""
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
    """The other half of a misplaced span: destroying what nobody objected to,
    which redacting the whole chunk would hide from the test above.

    A subsequence rather than line numbers, because a four-line finding becomes
    one replacement string and shifts every number after it.
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
    """The claim a second implementation exists to test: two adapters over one
    binary must return the same verdict and leave the host the same bytes. A
    protocol whose implementations disagree is a suggestion."""
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
