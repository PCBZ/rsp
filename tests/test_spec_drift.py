"""The spec, the cases and the coverage table have to agree.

Every check here exists because the drift it catches was found by hand first.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
SPEC = (ROOT / "SPEC.md").read_text(encoding="utf-8")
CLAUSES = dict(
    re.findall(r"\*\*([A-Z]+\d+)\.\*\*(.*?)(?=\n\*\*[A-Z]+\d+\.\*\*|\n---|\n## )", SPEC, re.DOTALL)
)
# rglob, not glob: cases live in subdirectories once a second plugin has its
# own set, and a guard that cannot see them reports green while the coverage
# table goes stale.
CASE_ROOT = ROOT / "conformance" / "cases"
HOST_ROOT = ROOT / "conformance" / "host"
# Both kinds count toward coverage: a clause is covered when some case settles
# it, and the seventeen §10 listed were uncovered precisely because only one
# kind existed.
ALL_CASES = [
    (p.relative_to(p.parent.parent).as_posix(), json.loads(p.read_text(encoding="utf-8")))
    for p in sorted(CASE_ROOT.rglob("*.json")) + sorted(HOST_ROOT.glob("*.json"))
]
# Keyed by stem for the fixture references in SPEC.md, which name a case rather
# than a path. Coverage is counted from ALL_CASES instead, because a dict drops
# a repeated name — which is what the uniqueness test below exists to prevent.
CASES = {pathlib.Path(name).stem: case for name, case in ALL_CASES}
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


def test_case_names_are_unique_across_directories() -> None:
    """SPEC.md names a fixture, not a path, so two cases with one name make a
    reference ambiguous — and a dict keyed on the name resolves it by sort
    order, which is not a decision anybody made. Two plugins each had a case
    called `handshake`, and H1's fixture reference was validating whichever of
    them sorted last."""
    seen: dict[str, str] = {}
    for name, _ in ALL_CASES:
        stem = pathlib.Path(name).stem
        assert stem not in seen, f"{name} and {seen[stem]} share the name {stem!r}"
        seen[stem] = name


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
    for ref in set(re.findall(r"\bQ\d\b", source.read_text(encoding="utf-8"))):
        assert ref in OPEN_QUESTIONS, f"{source.name} cites {ref}, which is no longer open"


@pytest.mark.parametrize(("name", "case"), ALL_CASES, ids=[name for name, _ in ALL_CASES])
def test_every_case_names_a_clause_the_spec_defines(name: str, case: dict) -> None:
    for clause in clauses_in(case["clause"]):
        assert clause in CLAUSES, f"case {name} claims a clause the spec does not define"


ISSUE_REFERENCE = re.compile(r"(?<!\]\()#\d+")

DURABLE_TEXT = (
    sorted((ROOT / "rsp").glob("*.py"))
    + sorted((ROOT / "plugins").rglob("*.py"))
    # pyproject.toml was outside this list, and carried two issue numbers in a
    # comment explaining a plan that had already been abandoned. A guard with a
    # hole in it reads exactly like a guard.
    + [ROOT / "SPEC.md", ROOT / "conformance" / "cases" / "README.md", ROOT / "pyproject.toml"]
)


@pytest.mark.parametrize("path", DURABLE_TEXT, ids=lambda p: p.name)
def test_no_issue_numbers_in_durable_text(path: pathlib.Path) -> None:
    """An issue number resolves only against a live GitHub, and only while that
    issue keeps its number. Clause IDs — D6, S1, Q6 — resolve inside a clone,
    and SPEC.md must be readable by someone who has never seen the tracker.
    Say the reason, or cite the clause."""
    found = ISSUE_REFERENCE.findall(path.read_text(encoding="utf-8"))
    assert not found, f"{path.name} points at {found} instead of stating the reason"


def test_the_default_timeout_matches_the_spec() -> None:
    """E4 states a number, and so does the code. A number stated twice is a
    number that will disagree with itself."""
    from rsp.process import DEFAULT_TIMEOUT

    stated = re.search(r"defaults to\s+\*\*(\d+)\s+seconds\*\*", CLAUSES["E4"])
    assert stated, "E4 no longer states a default in the form the code can check"
    assert DEFAULT_TIMEOUT == float(stated.group(1))


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
