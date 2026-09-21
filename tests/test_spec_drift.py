"""The spec, the cases and the coverage table have to agree.

Every check here exists because the drift it catches was found by hand first.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
SPEC = (ROOT / "SPEC.md").read_text()
CLAUSES = dict(
    re.findall(r"\*\*([A-Z]+\d+)\.\*\*(.*?)(?=\n\*\*[A-Z]+\d+\.\*\*|\n---|\n## )", SPEC, re.DOTALL)
)
CASES = {
    p.stem: json.loads(p.read_text())
    for p in sorted((ROOT / "conformance" / "cases").glob("*.json"))
}
OPEN_QUESTIONS = set(re.findall(r"\| (Q\d) \|", SPEC[SPEC.find("## 9. Open questions") :]))

# R1 is proved by rsp-echo existing at all, not by a case file.
COVERED_WITHOUT_A_CASE = {"R1"}


def clauses_in(field: str) -> set[str]:
    return {c.strip() for c in field.split(",")}


@pytest.mark.parametrize("clause", CLAUSES)
def test_every_clause_carries_a_rationale(clause: str) -> None:
    assert "*Rationale:" in CLAUSES[clause]


@pytest.mark.parametrize("clause", CLAUSES)
def test_fixture_references_point_at_real_cases(clause: str) -> None:
    for line in re.findall(r"Fixtures?: (.+)", CLAUSES[clause]):
        for name in (n.strip().strip("`") for n in line.split(",")):
            assert name in CASES, f"{clause} references a case that does not exist"


@pytest.mark.parametrize("clause", CLAUSES)
def test_no_clause_cites_a_settled_question(clause: str) -> None:
    """A citation outlives its question silently — V4 kept pointing at Q1 in
    the same PR that answered it."""
    for ref in set(re.findall(r"\bQ\d\b", CLAUSES[clause])):
        assert ref in OPEN_QUESTIONS, f"{clause} cites {ref}, which is no longer open"


@pytest.mark.parametrize(
    "source",
    sorted((ROOT / "rsp").glob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")),
    ids=lambda p: p.name,
)
def test_no_comment_cites_a_settled_question(source: pathlib.Path) -> None:
    for ref in set(re.findall(r"\bQ\d\b", source.read_text())):
        assert ref in OPEN_QUESTIONS, f"{source.name} cites {ref}, which is no longer open"


@pytest.mark.parametrize("name", CASES)
def test_every_case_names_a_clause_the_spec_defines(name: str) -> None:
    for clause in clauses_in(CASES[name]["clause"]):
        assert clause in CLAUSES, f"case {name} claims a clause the spec does not define"


ISSUE_REFERENCE = re.compile(r"(?<!\]\()#\d+")

DURABLE_TEXT = (
    sorted((ROOT / "rsp").glob("*.py"))
    + sorted((ROOT / "plugins").rglob("*.py"))
    + [ROOT / "SPEC.md", ROOT / "conformance" / "cases" / "README.md"]
)


@pytest.mark.parametrize("path", DURABLE_TEXT, ids=lambda p: p.name)
def test_no_issue_numbers_in_durable_text(path: pathlib.Path) -> None:
    """An issue number resolves only against a live GitHub, and only while that
    issue keeps its number. Clause IDs — D6, S1, Q6 — resolve inside a clone,
    and SPEC.md must be readable by someone who has never seen the tracker.
    Say the reason, or cite the clause."""
    found = ISSUE_REFERENCE.findall(path.read_text())
    assert not found, f"{path.name} points at {found} instead of stating the reason"


def test_the_default_timeout_matches_the_spec() -> None:
    """E4 states a number, and so does the code. A number stated twice is a
    number that will disagree with itself."""
    from rsp.process import DEFAULT_TIMEOUT

    stated = re.search(r"defaults to \*\*(\d+) seconds\*\*", SPEC)
    assert stated, "E4 no longer states a default in the form the code can check"
    assert DEFAULT_TIMEOUT == float(stated.group(1))


def test_the_on_error_values_match_the_spec() -> None:
    """E5 enumerates them; so does the enum."""
    from rsp.runtime import OnError

    stated = set(re.findall(r"`(block|allow|skip)`", SPEC))
    assert {member.value for member in OnError} == stated


def test_coverage_table_matches_the_cases_on_disk() -> None:
    claimed = clauses_in(re.search(r"\| Covered \| (.+?) \|", SPEC).group(1))
    actual = {c for case in CASES.values() for c in clauses_in(case["clause"])}
    assert actual - claimed == set(), "cases cover clauses §10 still lists as uncovered"
    assert claimed - actual - COVERED_WITHOUT_A_CASE == set(), "§10 claims coverage with no case"
