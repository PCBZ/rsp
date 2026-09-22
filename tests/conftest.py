"""Two extra columns in the HTML report: which clause, which implementation.

A list of test names is what the green tick already says. What a protocol
publishes is a matrix — clause against implementation — which is the same thing
SPEC.md §10 maintains by hand and drifts from reality between commits.

The tests supply the values with `record_property`, so nothing here parses a
case file a second time and the same values land in JUnit XML for whatever
reads that instead. pytest-html is pinned below 5 because these two hooks took
plain strings only from 4 onward, and a report with two silently empty columns
looks exactly like a passing one.
"""

from __future__ import annotations

import pytest

COLUMNS = ("clause", "plugin")


def pytest_html_results_table_header(cells: list[str]) -> None:
    # Inserted before the last column, which pytest-html keeps for links.
    for name in COLUMNS:
        cells.insert(-1, f"<th>{name.title()}</th>")


def pytest_html_results_table_row(report: pytest.TestReport, cells: list[str]) -> None:
    recorded = dict(getattr(report, "user_properties", []))
    for name in COLUMNS:
        cells.insert(-1, f"<td>{recorded.get(name, '')}</td>")
