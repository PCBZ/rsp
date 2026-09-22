"""The adapter, against the corpus its own tool is tested with.

Not a detection benchmark. Precision and recall belong to gitleaks, which the
plugin wraps unmodified precisely so that detection quality is never RSP's
claim — an F1 here would be a number nobody in this repository can act on.

What is ours is the translation: gitleaks reports a line and a column, S1 wants
a byte offset, and every file below is a chance for that arithmetic to be
wrong. The five hand-written span fixtures are shapes somebody chose, and two
position bugs got past them; upstream's test files are shapes nobody chose,
which is the point.

The check is differential. The same binary answers twice — once directly, as
the oracle, and once through the plugin and the host — and the oracle's command
is spelled out here rather than imported, so that a change in how the adapter
invokes gitleaks shows up as a disagreement instead of being mirrored into the
expectation.

Three properties, none of them a curve:

* content gitleaks finds something in is never allowed through
* no secret it reported survives in what the host hands on
* lines it said nothing about come back byte for byte
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from collections.abc import Callable
from typing import NamedTuple

import pytest

from rsp.runtime import Plugin, Result, Runtime, Verdict

ROOT = pathlib.Path(__file__).parent.parent
PLUGIN = ["node", "examples/gitleaks-ts/src/main.ts"]

# Fetched by the plugins workflow, from the same release as the binary: a
# corpus from a different one disagrees for reasons that are nobody's bug.
CORPUS = os.environ.get("RSP_GITLEAKS_CORPUS")
GITLEAKS = os.environ.get("RSP_GITLEAKS") or "gitleaks"
REQUIRED = os.environ.get("RSP_REQUIRE_ALL_PLUGINS") == "1"

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
    """Every window of a secret, or the whole thing when it is shorter than
    one.

    One character at a time, not one window at a time: sampling at intervals
    leaves gaps a survivor can sit in. With a stride of eight, sixteen
    characters surviving from offset four are missed by the window at zero,
    which needs the first four, and by the window at eight, which needs four
    past the end.
    """
    if len(secret) <= WINDOW:
        return [secret]
    return [secret[at : at + WINDOW] for at in range(len(secret) - WINDOW + 1)]


class Answer(NamedTuple):
    content: str
    findings: list[dict]
    result: Result


_ANSWERS: dict[pathlib.Path, Answer] = {}


def answer(path: pathlib.Path, runtime: Runtime) -> Answer:
    """Both answers for one file, asked once. Three properties read the same
    pair, and each process this avoids is a gitleaks run."""
    if path not in _ANSWERS:
        content = _text(path)
        if content is None:
            pytest.skip("not UTF-8")
        _ANSWERS[path] = Answer(content, _oracle(content), runtime.evaluate("on_chunk", content))
    return _ANSWERS[path]


@pytest.fixture(autouse=True)
def _label(record_property: Callable[[str, object], None]) -> None:
    """Which implementation these rows are about. No clause: fidelity to the
    wrapped tool is not something SPEC.md requires of anyone — it is what this
    adapter owes the tool it wraps."""
    record_property("plugin", "rsp-gitleaks-ts")


@pytest.fixture(scope="module")
def runtime() -> Runtime:
    """One handshake for the whole corpus. Also the first test anywhere that
    drives this plugin through the host rather than as a bare subprocess."""
    missing = [tool for tool in ("node", GITLEAKS) if shutil.which(tool) is None]
    if missing or CORPUS is None:
        why = f"not installed: {', '.join(missing)}" if missing else "no corpus"
        pytest.fail(why) if REQUIRED else pytest.skip(why)
    return Runtime([Plugin(name="gitleaks", command=PLUGIN)])


def _ids(path: pathlib.Path) -> str:
    return path.relative_to(pathlib.Path(CORPUS)).as_posix() if CORPUS else str(path)


pytestmark = pytest.mark.skipif(
    not CASES and not REQUIRED, reason="set RSP_GITLEAKS_CORPUS to run the corpus"
)


FLOOR = 5


def test_the_corpus_reaches_the_adapter_at_all() -> None:
    """Every property below is conditional on gitleaks reporting something, so
    a gitleaks that reports nothing — wrong flags, a broken download, a corpus
    of the wrong directory — turns this file green while checking nothing.

    Stops at the floor rather than counting the corpus: the point is to catch
    zero, not to pin a number upstream is free to change."""
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


@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_content_with_a_finding_is_not_allowed(path: pathlib.Path, runtime: Runtime) -> None:
    """The failure this catches is the quiet one: an adapter that reports no
    span for a finding, or a gitleaks that never ran, both look like clean
    content. REDACT rather than merely "not ALLOW", because BLOCK here means
    the adapter could not place a finding it was given — the placement rate
    this corpus measures, which has to be one."""
    _, findings, result = answer(path, runtime)

    if not findings:
        assert result.verdict is Verdict.ALLOW, f"allowed nothing, got {result.reasons}"
        return
    assert result.verdict is Verdict.REDACT, (
        f"gitleaks reported {len(findings)} finding(s) and the host said "
        f"{result.verdict.value}: {result.reasons}"
    )


@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_no_reported_secret_survives_redaction(path: pathlib.Path, runtime: Runtime) -> None:
    """The security property, and the reason it is checked in windows rather
    than whole: a span that covers the first thirty bytes of a private key
    destroys the exact string while leaving the key readable, so asking whether
    `Secret` is still a substring passes for a redaction that leaked almost all
    of it. Every window has to be gone."""
    _, findings, result = answer(path, runtime)
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


@pytest.mark.parametrize("path", CASES, ids=_ids)
def test_lines_without_findings_come_back_unchanged(path: pathlib.Path, runtime: Runtime) -> None:
    """The other half of a misplaced span: it destroys content nobody objected
    to. Redacting a whole chunk would pass the survival test above.

    Checked as a subsequence, in order, one line at a time. Comparing line
    numbers would be stronger and is not available: a finding spanning four
    lines becomes one replacement string, so every number after it shifts. A
    subsequence still catches a line that was altered, dropped, duplicated or
    moved, which is everything a span can do to a line it should not have
    touched.
    """
    content, findings, result = answer(path, runtime)
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
