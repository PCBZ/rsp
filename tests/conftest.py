"""Two extra report columns, clause and plugin: the matrix SPEC.md §10 keeps by hand.

Tests supply the values with `record_property`, so nothing parses a case file
twice and JUnit XML gets them too. pytest-html is pinned below 5 because these
hooks took plain strings only from 4 onward, and two silently empty columns
look like a pass.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

# The kit ships standalone, not as a package, so `harness` is imported as a sibling.
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "conformance"))

COLUMNS = ("clause", "plugin")


def pytest_html_results_table_header(cells: list[str]) -> None:
    # Inserted before the last column, which pytest-html keeps for links.
    for name in COLUMNS:
        cells.insert(-1, f"<th>{name.title()}</th>")


def pytest_html_results_table_row(report: pytest.TestReport, cells: list[str]) -> None:
    recorded = dict(getattr(report, "user_properties", []))
    for name in COLUMNS:
        cells.insert(-1, f"<td>{recorded.get(name, '')}</td>")
