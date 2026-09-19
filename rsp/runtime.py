"""Verdict composition — issue #7.

The deciding layer. rsp.process knows how a process ended, rsp.codec knows what
it said, rsp.spans knows what to do with offsets — and none of them knows what
should happen as a result. This does.
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

    A StrEnum, not an IntEnum: these values go on the wire, and the ordering
    below is a policy (D9, strictest wins) rather than a property of the words.
    Keeping the rank in a table means the policy can be read — and argued with —
    instead of being implied by which number someone assigned.
    """

    ALLOW = "ALLOW"
    FLAG = "FLAG"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


STRICTNESS = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.REDACT: 2, Verdict.BLOCK: 3}


class OnError(enum.StrEnum):
    """What a plugin's failure means. BLOCK unless configured otherwise (D3)."""

    BLOCK = "block"
    ALLOW = "allow"
    SKIP = "skip"


class ConfigError(Exception):
    """Raised at construction, never during evaluation.

    A misconfiguration should stop the run while someone is watching. The
    alternative — degrading quietly into an index nobody is guarding — looks
    exactly like success (thread on #24).
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

    `content` is already redacted (S4): the host never sees a span. `reasons`
    are for the operator's log and deliberately not in `provenance`, which is
    written onto a stored node — a plugin's free text could quote the very
    bytes it matched, and Q8 keeps matched content out of the index.
    """

    verdict: Verdict
    content: str
    provenance: dict[str, Any]
    reasons: list[str]

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


def _verdict_of(payload: Mapping[str, Any]) -> Verdict | None:
    """The declared verdict, or None if it is not one (V1).

    isinstance before lookup: a plugin may return any JSON, and `["BLOCK"] in
    set(Verdict)` raises rather than answering. Everything a plugin sends is a
    claim about its own output, checked before it is used.
    """
    declared = payload.get("verdict")
    if not isinstance(declared, str):
        return None
    try:
        return Verdict(declared)
    except ValueError:
        return None


def _spans_of(payload: Mapping[str, Any], order: int, content: bytes) -> list[Span] | None:
    """Every span in a REDACT response, or None if any of it is unusable.

    Validation is per response rather than at redaction time so the failure can
    be attributed: the host knows which plugin sent it and can apply that
    plugin's on_error. It also enforces V3 — a REDACT with no spans or no
    replacement is not a REDACT.
    """
    raw_spans = payload.get("spans")
    replacement = payload.get("replacement")
    severity = payload.get("severity", "low")
    if not isinstance(raw_spans, list) or not raw_spans:
        return None
    if not isinstance(replacement, str) or not isinstance(severity, str):
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
            return None  # S3: out of range, inverted, or cutting a character
        spans.append(span)
    return spans


class Runtime:
    """Dispatches a hook across plugins and composes one verdict (#7).

    Handshakes eagerly: a plugin that cannot introduce itself is a
    configuration problem, and those are raised while someone is watching
    rather than turned into a silently unguarded index.
    """

    def __init__(self, plugins: Sequence[Plugin]) -> None:
        self.plugins = list(plugins)
        self.declarations: dict[str, Handshake] = {}
        for plugin in self.plugins:
            if plugin.name in self.declarations:
                # Names key the declarations, so a duplicate silently gives one
                # plugin another's capabilities — and a guard that never runs
                # looks exactly like a guard that found nothing.
                raise ConfigError(f"{plugin.name}: configured twice")
            outcome, declaration = handshake(
                plugin.command, timeout=plugin.timeout, max_output=plugin.max_output
            )
            if declaration is None:
                raise ConfigError(f"{plugin.name}: handshake failed ({outcome})")
            self.declarations[plugin.name] = declaration

    def for_hook(self, hook: str) -> list[Plugin]:
        """Only plugins that declared this hook (H3).

        A plugin handed a hook it never declared cannot refuse it, so whatever
        verdict it returns is about a situation it was not written for.
        """
        return [p for p in self.plugins if self.declarations[p.name].supports(hook)]

    def evaluate(
        self, hook: str, content: str, metadata: Mapping[str, Any] | None = None
    ) -> Result:
        """Never raises (E2). Every failure becomes a verdict, and by E1 that
        verdict is BLOCK unless that plugin's on_error says otherwise."""
        request: dict[str, Any] = {"rsp_version": RSP_VERSION, "hook": hook, "content": content}
        if metadata:
            request["metadata"] = dict(metadata)
        data = content.encode("utf-8")

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
                # Short-circuits: later verdicts about rejected content are
                # unused, and running them invites a plugin to expect a call it
                # never receives (D9).
                reasons.append(f"{plugin.name}: BLOCK")
                return self._blocked(content, types, severities, contributors, reasons)

            if said is Verdict.REDACT:
                declared = _spans_of(reply.payload, order, data)
                if declared is None:
                    # A response the host cannot use is a plugin error (S3, V3).
                    # Applying this plugin's other spans would let it report
                    # nothing by reporting garbage, and the host cannot tell
                    # which of its claims were sound.
                    contributors.pop()
                    if self._failed(plugin, "unusable spans", reasons):
                        return self._blocked(content, types, severities, contributors, reasons)
                    continue
                spans.extend(declared)
                types.update(span.type for span in declared if span.type)

            if STRICTNESS[said] > STRICTNESS[verdict]:
                verdict = said

        redacted, _ = redact(content, spans)  # every span was validated on arrival
        return Result(
            verdict, redacted, self._provenance(verdict, types, severities, contributors), reasons
        )

    @staticmethod
    def _failed(plugin: Plugin, detail: str, reasons: list[str]) -> bool:
        """Record a plugin failure and say whether it blocks the chunk.

        on_error covers every failure of that plugin, not only the ones that
        happen to the process: a plugin that returns an unusable response has
        failed as surely as one that crashed, and an operator who set
        on_error=allow for a metrics collector meant both.

        ALLOW and SKIP have the same effect on composition today — neither
        contributes a verdict. They are kept apart because the intent differs,
        and because provenance may come to distinguish them.
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
        """Blocked content is returned unchanged: it is not being stored, and
        redacting something nobody will see costs work and loses evidence."""
        return Result(
            Verdict.BLOCK,
            content,
            self._provenance(Verdict.BLOCK, types, severities, contributors),
            reasons,
        )

    @staticmethod
    def _provenance(verdict, types, severities, contributors) -> dict[str, Any]:
        """Types and severities, never matched bytes or offsets (Q8)."""
        provenance: dict[str, Any] = {"rsp.verdict": verdict.value}
        if types:
            provenance["rsp.types"] = sorted(types)
        if severities:
            provenance["rsp.severity"] = max(severities, key=lambda s: Severity.of(s))
        if contributors:
            provenance["rsp.plugins"] = contributors
        return provenance
