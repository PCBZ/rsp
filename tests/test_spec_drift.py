"""The spec, the cases and the coverage table have to agree."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from plugins import ROOT

SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CLAUSES = dict(
    re.findall(r"\*\*([A-Z]+\d+)\.\*\*(.*?)(?=\n\*\*[A-Z]+\d+\.\*\*|\n---|\n## )", SPEC, re.DOTALL)
)
CASE_ROOT = ROOT / "conformance" / "cases"
HOST_ROOT = ROOT / "conformance" / "host"
# Host cases count too: a clause is covered when any case settles it. rglob,
# because plugin cases live in per-plugin subdirectories.
ALL_CASES = [
    (p.relative_to(p.parent.parent).as_posix(), json.loads(p.read_text(encoding="utf-8")))
    for p in sorted(CASE_ROOT.rglob("*.json")) + sorted(HOST_ROOT.glob("*.json"))
]
# By stem, for SPEC.md's fixture references; coverage counts `ALL_CASES`, which keeps repeats.
CASES = {pathlib.Path(name).stem: case for name, case in ALL_CASES}
OPEN_QUESTIONS = set(re.findall(r"\| (Q\d) \|", SPEC[SPEC.find("## 9. Open questions") :]))

# R1 is proved by rsp-echo existing at all, not by a case file.
COVERED_WITHOUT_A_CASE = {"R1"}
ISSUE_REFERENCE = re.compile(r"(?<!\]\()#\d+")
DURABLE_TEXT = (
    sorted((ROOT / "rsp").glob("*.py"))
    + sorted((ROOT / "plugins").rglob("*.py"))
    + [ROOT / "SPEC.md", ROOT / "conformance" / "cases" / "README.md", ROOT / "pyproject.toml"]
)
WORDS = {23: "twenty-three", 24: "twenty-four", 28: "twenty-eight"}


def clauses_in(field: str) -> set[str]:
    return {c.strip() for c in field.split(",")}


@pytest.mark.parametrize("clause", CLAUSES)
def test_every_clause_carries_a_rationale(clause: str) -> None:
    assert "*Rationale:" in CLAUSES[clause]


@pytest.mark.parametrize("clause", CLAUSES)
def test_fixture_references_point_at_real_cases(clause: str) -> None:
    # Up to the blank line or next clause, so a list that wraps is still one list.
    for line in re.findall(r"Fixtures?: (.+?)(?=\n\n|\n\*|\Z)", CLAUSES[clause], re.DOTALL):
        for name in (n.strip().strip("`") for n in line.split(",")):
            assert name, f"{clause}: a fixture reference is empty"
            assert name in CASES, f"{clause} references {name!r}, which does not exist"


def test_case_names_are_unique_across_directories() -> None:
    """SPEC.md names a fixture, not a path, so a shared name is resolved by sort order."""
    seen: dict[str, str] = {}
    for name, _ in ALL_CASES:
        stem = pathlib.Path(name).stem
        assert stem not in seen, f"{name} and {seen[stem]} share the name {stem!r}"
        seen[stem] = name


@pytest.mark.parametrize("clause", CLAUSES)
def test_no_clause_cites_a_settled_question(clause: str) -> None:
    """A citation outlives its question silently."""
    for ref in set(re.findall(r"\bQ\d\b", CLAUSES[clause])):
        assert ref in OPEN_QUESTIONS, f"{clause} cites {ref}, which is no longer open"


@pytest.mark.parametrize(
    "source",
    sorted((ROOT / "rsp").glob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")),
    ids=lambda p: p.name,
)
def test_no_comment_cites_a_settled_question(source: pathlib.Path) -> None:
    for ref in set(re.findall(r"\bQ\d\b", source.read_text(encoding="utf-8"))):
        assert ref in OPEN_QUESTIONS, f"{source.name} cites {ref}, which is no longer open"


@pytest.mark.parametrize(("name", "case"), ALL_CASES, ids=[name for name, _ in ALL_CASES])
def test_every_case_names_a_clause_the_spec_defines(name: str, case: dict) -> None:
    for clause in clauses_in(case["clause"]):
        assert clause in CLAUSES, f"case {name} claims a clause the spec does not define"


@pytest.mark.parametrize("path", DURABLE_TEXT, ids=lambda p: p.name)
def test_no_issue_numbers_in_durable_text(path: pathlib.Path) -> None:
    """An issue number resolves only against a live tracker; a clause ID, inside a clone."""
    found = ISSUE_REFERENCE.findall(path.read_text(encoding="utf-8"))
    assert not found, f"{path.name} points at {found} instead of stating the reason"


def test_the_default_timeout_matches_the_spec() -> None:
    """E4 states a number, and so does the code."""
    from rsp.process import DEFAULT_TIMEOUT

    stated = re.search(r"defaults to\s+\*\*(\d+)\s+seconds\*\*", CLAUSES["E4"])
    assert stated, "E4 no longer states a default in the form the code can check"
    assert float(stated.group(1)) == DEFAULT_TIMEOUT


def test_the_on_error_values_match_the_spec() -> None:
    """E5 enumerates them; so does the enum."""
    from rsp.runtime import OnError

    stated = set(re.findall(r"`(block|allow|skip)`", CLAUSES["E5"]))
    assert {member.value for member in OnError} == stated


def test_coverage_table_matches_the_cases_on_disk() -> None:
    claimed = clauses_in(re.search(r"\| Covered \| (.+?) \|", SPEC).group(1))
    actual = {c for _, case in ALL_CASES for c in clauses_in(case["clause"])}
    assert actual - claimed == set(), "cases cover clauses §10 still lists as uncovered"
    assert claimed - actual - COVERED_WITHOUT_A_CASE == set(), "§10 claims coverage with no case"


def test_the_counts_in_prose_match_the_clauses() -> None:
    """§10 states the counts in words and again as a list."""
    covered = clauses_in(re.search(r"\| Covered \| (.+?) \|", SPEC).group(1))
    total = len(CLAUSES)

    stated = re.search(r"(\w+(?:-\w+)?) of the (\w+(?:-\w+)?) normative clauses", SPEC)
    assert stated, "section 10 no longer states the counts in the form the code can check"
    assert stated.group(1).lower() == WORDS[len(covered)], f"{len(covered)} clauses are covered"
    assert stated.group(2).lower() == WORDS[total], f"there are {total} clauses"


def test_the_readme_agrees_with_the_spec() -> None:
    """A third copy of the counts; the README's excludes R1, which no case settles."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    covered = clauses_in(re.search(r"\| Covered \| (.+?) \|", SPEC).group(1))

    stated = re.search(
        r"(\w+(?:-\w+)?) clauses, .*?(\w+(?:-\w+)?) of them settled", readme, re.DOTALL
    )
    assert stated, "the README no longer states the counts in the form the code can check"
    assert stated.group(1).lower() == WORDS[len(CLAUSES)]
    assert stated.group(2).lower() == WORDS[len(covered - COVERED_WITHOUT_A_CASE)]


def test_the_readme_example_span_is_valid() -> None:
    """The example teaches S1 and S3, so it has to obey them."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    content = re.search(r'"content":"([^"]+)"', readme).group(1)
    start, end = (int(n) for n in re.search(r'"start":(\d+),"end":(\d+)', readme).groups())

    assert 0 <= start < end <= len(content.encode("utf-8")), f"{start}-{end} in {content!r}"
    assert content.encode("utf-8")[start:end].decode("utf-8").startswith("AKIA")
