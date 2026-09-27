"""Spans and redaction: what a chunk looks like after every plugin has spoken.

Knows byte offsets and severities; knows no verdicts and no plugins.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass


class Severity(enum.IntEnum):
    """The scale S6 compares.

    A rank only: the wire value stays a string on the Span, so an unknown
    "catastrophic" ranks lowest without the operator losing the word.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def of(cls, wire: str | None) -> Severity:
        """Rank a declared severity. Unknown is lowest, never an error (S7, D8).

        Case-sensitive, so this host takes nothing a stricter one refuses.
        """
        try:
            return cls[wire.upper()] if wire and wire.islower() else cls.LOW
        except KeyError:
            return cls.LOW


@dataclass(frozen=True)
class Span:
    """A range one plugin wants masked, plus what merging it needs.

    `replacement` and `severity` come from its response (V3, V4); `order` is the
    plugin's configured position, which breaks ties in S6.
    """

    start: int
    end: int
    type: str | None = None
    severity: str = "low"
    replacement: str = "[REDACTED]"
    order: int = 0

    @property
    def rank(self) -> Severity:
        return Severity.of(self.severity)


def valid_span(span: Span, content: bytes) -> bool:
    """Whether a span is in range, ordered, and on a character boundary (S3)."""
    if span.start < 0 or span.end > len(content) or span.start > span.end:
        return False
    # A UTF-8 continuation byte is 0b10xxxxxx; a boundary is anything else.
    return all(
        i in (0, len(content)) or (content[i] & 0xC0) != 0x80 for i in (span.start, span.end)
    )


def merge_spans(spans: Iterable[Span]) -> list[Span]:
    """Coalesce overlapping and adjacent ranges into one (S6).

    Adjacent too, or `[REDACTED][REDACTED]` shows where the boundary fell. The
    highest-severity replacement survives, ties to the earlier plugin, so the
    result cannot depend on who answered first.
    """
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[Span] = []
    for span in ordered:
        if merged and span.start <= merged[-1].end:
            current = merged[-1]
            winner = max((current, span), key=lambda s: (s.rank, -s.order))
            types = {t for t in (current.type, span.type) if t}
            merged[-1] = Span(
                start=current.start,
                end=max(current.end, span.end),
                type="+".join(sorted(types)) or None,
                severity=winner.severity,
                replacement=winner.replacement,
                order=winner.order,  # the next tie is against whoever holds the replacement
            )
        else:
            merged.append(span)
    return merged


def redact(content: str, spans: Iterable[Span]) -> tuple[str, list[Span]]:
    """Apply every plugin's spans to the original content, once (S5).

    All offsets address the bytes passed in, so a replacement of another length
    cannot shift a later range. Invalid spans are returned, not applied, so the
    caller can treat them as a plugin error (S3, E1).
    """
    data = content.encode("utf-8")
    usable, rejected = [], []
    for span in spans:
        (usable if valid_span(span, data) else rejected).append(span)

    out, cursor = bytearray(), 0
    for span in merge_spans(usable):
        out += data[cursor : span.start]
        out += span.replacement.encode("utf-8")
        cursor = span.end
    out += data[cursor:]
    return out.decode("utf-8"), rejected
