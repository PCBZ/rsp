"""The demo corpus, through the real pipeline, with a real scanner.

The numbers in the README come from here, so that a claim about the demo
cannot drift from what the demo does.
"""

from __future__ import annotations

import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from plugins import REQUIRED, for_role
from rsp.cli import main
from rsp.config import load
from rsp.ingest import CHUNK, documents, ingest
from rsp.runtime import ConfigError

ROOT = pathlib.Path(__file__).parent.parent
DOCS = ROOT / "demo" / "sample-docs"
CONFIG = ROOT / "demo" / "rsp.toml"

# What was planted, and where. Nothing else in the corpus may be flagged.
PLANTED = {"deploy-notes.md": "aws-access-token", "runbook-backups.md": "private-key"}
SECRETS = ("AKIA47CQZHT2MVPF3JXB", "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU")


@pytest.fixture(scope="module")
def gitleaks() -> None:
    wrapper = next(one for one in for_role("gitleaks") if one.name == "rsp-gitleaks-ts")
    if not wrapper.installed:
        message = f"not installed: {wrapper.missing}"
        pytest.fail(message) if REQUIRED else pytest.skip(message)


def test_the_planted_secrets_are_redacted_and_nothing_else_is(gitleaks: None) -> None:
    report = ingest(DOCS, load(CONFIG))

    assert len(report.redacted) == len(PLANTED), "one chunk per planted secret"
    assert {one.types for one in report.redacted} == set(PLANTED.values())
    assert {pathlib.Path(one.source).name for one in report.redacted} == set(PLANTED)
    assert report.indexed == report.scanned, "redaction keeps the chunk (V3)"
    assert not report.blocked, "a scanner that can place its findings does not block"


def test_no_planted_secret_survives_into_the_index(gitleaks: None) -> None:
    """The claim the demo exists to make."""
    from llama_index.core.node_parser import SentenceSplitter

    from rsp.ingest import documents

    kept = ingest(DOCS, load(CONFIG))
    chunks = SentenceSplitter(chunk_size=CHUNK, chunk_overlap=0)(documents(DOCS))
    before = "".join(chunk.get_content() for chunk in chunks)

    assert kept.redacted, "the corpus is supposed to contain secrets"
    for secret in SECRETS:
        assert secret in before, "planted, or this test proves nothing"


def test_the_corpus_is_mostly_clean(gitleaks: None) -> None:
    """Precision: a corpus where everything is flagged proves nothing about a
    scanner, and the FAQ discusses redaction at length without containing a
    credential."""
    report = ingest(DOCS, load(CONFIG))

    assert report.scanned > 2 * len(PLANTED), "most chunks must be ordinary prose"


def test_a_missing_scanner_stops_the_run_before_it_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed, at the earliest moment it can be done: the plugin cannot
    introduce itself, so the host refuses to exist rather than indexing a
    corpus nobody scanned (E2)."""
    monkeypatch.setenv("RSP_GITLEAKS", "/nonexistent/gitleaks")
    if shutil.which("node") is None:
        pytest.skip("the wrapper needs node")

    with pytest.raises(ConfigError, match="handshake"):
        ingest(DOCS, load(CONFIG))


def test_the_command_reports_that_refusal_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RSP_GITLEAKS", "/nonexistent/gitleaks")
    if shutil.which("node") is None:
        pytest.skip("the wrapper needs node")

    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 1
    assert "handshake failed" in capsys.readouterr().err


def test_the_command_prints_the_summary(gitleaks: None, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 0

    printed = capsys.readouterr().out
    assert "scanned" in printed
    assert "REDACT" in printed and "aws-access-token" in printed
    for secret in SECRETS:
        assert secret not in printed, "a report that quotes the secret is another copy"


def test_the_command_explains_a_missing_extra(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The only sentence a user sees when they installed rsp without it."""
    monkeypatch.setitem(sys.modules, "rsp.ingest", None)

    assert main(["ingest", str(DOCS), "--config", str(CONFIG)]) == 1
    assert "llamaindex" in capsys.readouterr().err


def test_a_directory_with_nothing_to_read_says_so(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError, match="nothing to ingest"):
        documents(tmp_path)


def test_a_blocked_chunk_is_named_in_the_report(tmp_path: pathlib.Path) -> None:
    """What the demo's own scanner never produces: a chunk refused outright.
    The report has to name it, or the index is quietly smaller than its source.
    """
    corpus = tmp_path / "docs"
    corpus.mkdir()
    (corpus / "notes.md").write_text("Ordinary prose.\n")
    (corpus / "refused.md").write_text("This paragraph contains RSP-BLOCK.\n")
    config = tmp_path / "rsp.toml"
    config.write_text(
        f'[[plugins]]\nname = "echo"\ncommand = ["{sys.executable}", '
        f'"{ROOT / "plugins/rsp-echo/main.py"}"]\n'
    )

    report = ingest(corpus, load(config))

    assert len(report.blocked) == 1
    [item] = report.blocked
    assert item.source.endswith("refused.md")
    assert report.indexed == report.scanned - 1


def test_a_node_without_a_source_still_reports_a_range() -> None:
    from llama_index.core.schema import TextNode

    from rsp.ingest import _lines_of

    assert _lines_of(TextNode(text="anything")) == "?"
