"""Spans and redaction — issue #21.

What a chunk looks like after every plugin has spoken. Knows about byte offsets
and severities; knows nothing about verdicts or plugins.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass


class Severity(enum.IntEnum):
    """The scale S6 compares. IntEnum because the comparison is the point.

    Only a rank. The wire value stays a string on the Span: a plugin that
    declares "catastrophic" ranks lowest (S7) but the operator should still see
    the word it used, and normalising it away would hide a plugin that thinks
    it is being more severe than the scale allows.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def of(cls, wire: str | None) -> Severity:
        """Rank a declared severity. Unknown is lowest, never an error (S7, D8).

        Exact match: "CRITICAL" is not "critical". Accepting case variants would
        be this host taking something a stricter one rejects, which is the
        leniency tracked in #29.
        """
        try:
            return cls[wire.upper()] if wire and wire.islower() else cls.LOW
        except KeyError:
            return cls.LOW


@dataclass(frozen=True)
class Span:
    """A range one plugin wants masked, carried with what it takes to merge.

    `replacement` and `severity` come from the response the span arrived in
    (V3, V4); `order` is the plugin's position in the configured list, which is
    what settles a tie without asking the clock.
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
    """S3. Plugins are untrusted, so a span is a claim until it is checked.

    An unchecked span is a host crash waiting to happen: a range past the end
    slices short in Python and raises elsewhere, and one that cuts a multi-byte
    character raises on decode. Either way a plugin chose when the host fell
    over.
    """
    if span.start < 0 or span.end > len(content) or span.start > span.end:
        return False
    # A continuation byte is 0b10xxxxxx; a boundary is anything else.
    return all(
        i in (0, len(content)) or (content[i] & 0xC0) != 0x80 for i in (span.start, span.end)
    )


def merge_spans(spans: Iterable[Span]) -> list[Span]:
    """Coalesce overlapping and adjacent ranges into one (S6).

    Adjacent ranges merge too: two plugins finding neighbouring secrets should
    produce one mask, not `[REDACTED][REDACTED]`, which tells a reader exactly
    how the boundary fell.

    The surviving replacement is the highest-severity contributor's, ties going
    to the earlier plugin. Any rule other than a total order would make the
    output depend on which plugin happened to answer first.
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
                # The winner's order, not the earliest contributor's: this
                # field exists to break the next tie, and the next tie is
                # against whoever currently holds the replacement. Carrying the
                # earliest order instead lets a later plugin keep a replacement
                # that an earlier one should have taken.
                order=winner.order,
            )
        else:
            merged.append(span)
    return merged


def redact(content: str, spans: Iterable[Span]) -> tuple[str, list[Span]]:
    """Apply every plugin's spans to the original content, once (S5).

    Every plugin on a hook sees the same bytes, and masking happens after the
    last one has answered. The alternative — handing plugin N+1 what plugin N
    redacted — means each plugin reports offsets into a different string, and
    the host has to map them back. One coordinate system costs duplicate
    findings on the same bytes, which is what merging is for.

    Invalid spans are dropped and returned, so the caller can treat the
    response as a plugin error (S3, E1) rather than silently masking the wrong
    bytes.
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
