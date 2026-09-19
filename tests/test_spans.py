"""Span coalescing and redaction — #21, settling Q1 and Q2.

The table mirrors the shape a host conformance case will take (#31): content
and spans in, resulting content out. Lifting these into data should be
mechanical once the kit can drive a host.
"""

from __future__ import annotations

import pytest

from rsp.runtime import Span, merge_spans, redact, valid_span

TEXT = "0123456789"


def span(
    start: int,
    end: int,
    *,
    sev: str = "low",
    rep: str = "[R]",
    order: int = 0,
    type_: str | None = None,
) -> Span:
    return Span(start=start, end=end, type=type_, severity=sev, replacement=rep, order=order)


@pytest.mark.parametrize(
    ("name", "spans", "expected"),
    [
        ("disjoint", [span(0, 2, rep="[A]"), span(5, 7, rep="[B]")], "[A]234[B]789"),
        ("exact overlap", [span(0, 3, rep="[A]"), span(0, 3, sev="high", rep="[B]")], "[B]3456789"),
        ("partial overlap", [span(0, 4, rep="[A]"), span(2, 6, sev="high", rep="[B]")], "[B]6789"),
        ("adjacent", [span(0, 3, rep="[A]"), span(3, 6, rep="[B]")], "[A]6789"),
        ("contained", [span(0, 6, rep="[A]"), span(2, 4, sev="critical", rep="[B]")], "[B]6789"),
        (
            "equal severity, earlier plugin wins",
            [span(0, 3, rep="[A]", order=0), span(1, 4, rep="[B]", order=1)],
            "[A]456789",
        ),
        ("nothing to do", [], TEXT),
    ],
)
def test_coalescing(name: str, spans: list[Span], expected: str) -> None:
    content, rejected = redact(TEXT, spans)
    assert content == expected, name
    assert rejected == []


def test_a_coalesced_span_records_every_contributing_type() -> None:
    merged = merge_spans([span(0, 4, type_="aws-key"), span(2, 6, type_="generic")])
    assert len(merged) == 1
    assert merged[0].type == "aws-key+generic"


def test_a_later_merge_can_take_the_replacement_back() -> None:
    """Three spans, two merges. The first merge hands the replacement to the
    high-severity span from plugin 2; the second brings in an equally severe
    span from plugin 1, which S6 says wins the tie. The merged span must
    therefore carry the current winner's order, not the earliest contributor's,
    or plugin 2 keeps a replacement that plugin 1 should have taken."""
    a = span(0, 4, sev="low", rep="[A]", order=0)
    b = span(2, 7, sev="high", rep="[B]", order=2)
    c = span(6, 9, sev="high", rep="[C]", order=1)
    merged = merge_spans([a, b, c])
    assert len(merged) == 1
    assert merged[0].replacement == "[C]"


def test_order_of_arrival_does_not_change_the_result() -> None:
    """Composition must not depend on which plugin happened to answer first."""
    a, b = span(0, 4, rep="[A]"), span(2, 6, sev="high", rep="[B]")
    assert redact(TEXT, [a, b]) == redact(TEXT, [b, a])

    # and with the three-span case, where the winner changes mid-merge
    trio = [
        span(0, 4, sev="low", rep="[A]", order=0),
        span(2, 7, sev="high", rep="[B]", order=2),
        span(6, 9, sev="high", rep="[C]", order=1),
    ]
    assert redact(TEXT, trio) == redact(TEXT, list(reversed(trio)))


def test_every_plugin_addresses_the_original_content() -> None:
    """Q2: offsets from two plugins are both computed against the same bytes,
    so a replacement of a different length cannot shift the other's range."""
    content, _ = redact(TEXT, [span(0, 2, rep="[a very long replacement]"), span(8, 10, rep="[B]")])
    assert content == "[a very long replacement]234567[B]"


def test_utf8_offsets_are_bytes_not_characters() -> None:
    content, rejected = redact("密钥 secret", [span(7, 13, rep="[S]")])
    assert content == "密钥 [S]"
    assert rejected == []


@pytest.mark.parametrize(
    ("bad", "why"),
    [
        (span(1, 2), "starts inside a multi-byte character"),
        (span(0, 1), "ends inside a multi-byte character"),
        (span(0, 99), "past the end"),
        (span(-1, 3), "negative"),
        (span(5, 2), "start after end"),
    ],
)
def test_invalid_spans_are_rejected_not_applied(bad: Span, why: str) -> None:
    """S3: a span is a claim from untrusted code until it is checked. Applying
    one that cuts a character raises on decode — a plugin choosing when the
    host falls over."""
    text = "密钥 secret"
    content, rejected = redact(text, [bad])
    assert content == text, why
    assert rejected == [bad]


def test_a_valid_span_survives_alongside_an_invalid_one() -> None:
    text = "密钥 secret"
    content, rejected = redact(text, [span(1, 2, rep="[BAD]"), span(7, 13, rep="[OK]")])
    assert content == "密钥 [OK]"
    assert len(rejected) == 1


def test_boundaries_of_the_content_are_valid_positions() -> None:
    data = "密钥".encode()
    assert valid_span(span(0, len(data)), data)
