"""Verdict composition: the deciding layer.

The layers below report how a plugin ended, what it said, and where its spans
fall. Only this one decides what happens as a result.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rsp.codec import RSP_VERSION, call
from rsp.handshake import Handshake, handshake
from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT
from rsp.spans import Severity, Span, redact, valid_span


class Verdict(enum.StrEnum):
    """The four outcomes a plugin may return (V1).

    Ranked by `_STRICTNESS`, not by value, so strictest-wins (D9) reads as a table.
    """

    ALLOW = "ALLOW"
    FLAG = "FLAG"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


_STRICTNESS = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.REDACT: 2, Verdict.BLOCK: 3}


class OnError(enum.StrEnum):
    """What a plugin's failure means. BLOCK unless configured otherwise (D3)."""

    BLOCK = "block"
    ALLOW = "allow"
    SKIP = "skip"


class ConfigError(Exception):
    """Raised at construction, never during evaluation.

    An unguarded index looks exactly like a guarded one, so a misconfiguration
    stops the run while someone is watching.
    """


@dataclass(frozen=True)
class Plugin:
    name: str
    command: Sequence[str]
    on_error: OnError = OnError.BLOCK
    timeout: float = DEFAULT_TIMEOUT
    max_output: int = DEFAULT_MAX_OUTPUT


@dataclass(frozen=True)
class Result:
    """What the host acts on.

    `content` is already redacted, so the host never sees a span (S4). `reasons`
    stay out of `provenance`, which is stored on the node, because a plugin's
    free text can quote what it matched (Q8).
    """

    verdict: Verdict
    content: str
    provenance: dict[str, Any]
    reasons: list[str]

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


def _verdict_of(payload: Mapping[str, Any]) -> Verdict | None:
    """The declared verdict, or None if it is not one (V1)."""
    declared = payload.get("verdict")
    if not isinstance(declared, str):
        return None
    try:
        return Verdict(declared)
    except ValueError:
        return None


def _spans_of(payload: Mapping[str, Any], order: int, content: bytes) -> list[Span] | None:
    """Every span in a REDACT response, or None if any of it is unusable (S3, V3).

    Checked per response, so a bad span is charged to the plugin that sent it and
    routed through its on_error.
    """
    raw_spans = payload.get("spans")
    replacement = payload.get("replacement")
    severity = payload.get("severity", "low")
    if not isinstance(raw_spans, list) or not raw_spans:
        return None
    if not isinstance(replacement, str) or not isinstance(severity, str):
        return None
    try:
        replacement.encode("utf-8")  # a lone surrogate is a str, and not UTF-8
    except UnicodeEncodeError:
        return None

    spans = []
    for raw in raw_spans:
        if not isinstance(raw, Mapping):
            return None
        start, end, kind = raw.get("start"), raw.get("end"), raw.get("type")
        # bool is an int in Python, and `true` is not an offset.
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (start, end)):
            return None
        if kind is not None and not isinstance(kind, str):
            return None
        span = Span(start, end, kind, severity, replacement, order)
        if not valid_span(span, content):
            return None  # S3
        spans.append(span)
    return spans


class Runtime:
    """Dispatches a hook across plugins and composes one verdict.

    Handshakes at construction, so a plugin that cannot introduce itself fails
    before ingest starts rather than in the middle.
    """

    def __init__(self, plugins: Sequence[Plugin]) -> None:
        self.plugins = list(plugins)
        self.declarations: dict[str, Handshake] = {}
        for plugin in self.plugins:
            if plugin.name in self.declarations:
                # Names key the declarations: a duplicate would take another's hooks.
                raise ConfigError(f"{plugin.name}: configured twice")
            outcome, declaration = handshake(
                plugin.command, timeout=plugin.timeout, max_output=plugin.max_output
            )
            if declaration is None:
                raise ConfigError(f"{plugin.name}: handshake failed ({outcome})")
            self.declarations[plugin.name] = declaration

    def for_hook(self, hook: str) -> list[Plugin]:
        """The plugins that declared this hook, and only those (H3)."""
        return [p for p in self.plugins if self.declarations[p.name].supports(hook)]

    def evaluate(
        self, hook: str, content: str, metadata: Mapping[str, Any] | None = None
    ) -> Result:
        """One verdict on `content` from every plugin that declared `hook`.

        Never raises (E2): a failure is BLOCK unless that plugin's on_error says
        otherwise (E1).
        """
        request: dict[str, Any] = {"rsp_version": RSP_VERSION, "hook": hook, "content": content}
        if metadata:
            request["metadata"] = dict(metadata)

        try:
            data = content.encode("utf-8")
        except UnicodeEncodeError:
            # A lone surrogate cannot go on the wire, so no plugin can judge it (E3).
            return Result(
                Verdict.BLOCK,
                content,
                {"rsp.verdict": Verdict.BLOCK.value},
                ["content is not encodable as UTF-8"],
            )

        verdict, spans, reasons = Verdict.ALLOW, [], []
        types: set[str] = set()
        severities: set[str] = set()
        contributors: list[str] = []

        for order, plugin in enumerate(self.for_hook(hook)):
            reply = call(
                plugin.command, request, timeout=plugin.timeout, max_output=plugin.max_output
            )

            if not reply.ok:
                if self._failed(plugin, str(reply.outcome), reasons):
                    return self._blocked(content, types, severities, contributors, reasons)
                continue

            said = _verdict_of(reply.payload)
            if said is None:
                # Guessing at "ALLOOW" is how a typo becomes a silent allow.
                if self._failed(plugin, f"verdict {reply.payload.get('verdict')!r}", reasons):
                    return self._blocked(content, types, severities, contributors, reasons)
                continue

            contributors.append(plugin.name)
            if isinstance(reason := reply.payload.get("reason"), str):
                reasons.append(f"{plugin.name}: {reason}")
            if isinstance(severity := reply.payload.get("severity"), str):
                severities.add(severity)

            if said is Verdict.BLOCK:
                # Short-circuit: later verdicts about rejected content go unused (D9).
                reasons.append(f"{plugin.name}: BLOCK")
                return self._blocked(content, types, severities, contributors, reasons)

            if said is Verdict.REDACT:
                declared = _spans_of(reply.payload, order, data)
                if declared is None:
                    # Void the whole response (S3, V3): no telling which spans are sound.
                    contributors.pop()
                    if self._failed(plugin, "unusable spans", reasons):
                        return self._blocked(content, types, severities, contributors, reasons)
                    continue
                spans.extend(declared)
                types.update(span.type for span in declared if span.type)

            if _STRICTNESS[said] > _STRICTNESS[verdict]:
                verdict = said

        redacted, _ = redact(content, spans)  # every span was validated on arrival
        return Result(
            verdict, redacted, self._provenance(verdict, types, severities, contributors), reasons
        )

    @staticmethod
    def _failed(plugin: Plugin, detail: str, reasons: list[str]) -> bool:
        """Record a plugin failure and say whether it blocks the chunk.

        on_error covers an unusable response as much as a crash. ALLOW and SKIP
        behave alike today, and stay apart because the intent differs.
        """
        suffix = "" if plugin.on_error is OnError.BLOCK else f" (on_error={plugin.on_error})"
        reasons.append(f"{plugin.name}: {detail}{suffix}")
        return plugin.on_error is OnError.BLOCK

    def _blocked(
        self,
        content: str,
        types: set[str],
        severities: set[str],
        contributors: list[str],
        reasons: list[str],
    ) -> Result:
        """Blocked content comes back as is: nothing stores it, and redacting it loses evidence."""
        return Result(
            Verdict.BLOCK,
            content,
            self._provenance(Verdict.BLOCK, types, severities, contributors),
            reasons,
        )

    @staticmethod
    def _provenance(
        verdict: Verdict, types: set[str], severities: set[str], contributors: list[str]
    ) -> dict[str, Any]:
        """Types and severities, never matched bytes or offsets (Q8)."""
        provenance: dict[str, Any] = {"rsp.verdict": verdict.value}
        if types:
            provenance["rsp.types"] = sorted(types)
        if severities:
            provenance["rsp.severity"] = max(severities, key=Severity.of)
        if contributors:
            provenance["rsp.plugins"] = contributors
        return provenance
