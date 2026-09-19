"""Handshake — issue #5.

Who a plugin says it is, validated (H1, H2). One invocation of its own rather
than the opening message of a stream, because one call is one process (Q6).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rsp.codec import RSP_VERSION, call
from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Outcome

REQUIRED_DECLARATION_FIELDS = ("rsp_version", "name", "version", "hooks")


@dataclass(frozen=True)
class Handshake:
    """What a plugin says it is (H2).

    Only what the host acts on. `hooks` decides what it is called with (H3),
    `version` is part of a cache key (D4), `deterministic` decides whether
    caching is legal at all, and `max_inline_bytes` is the plugin's own limit
    on how much content it will take inline (D5).
    """

    rsp_version: str
    name: str
    version: str
    hooks: frozenset[str]
    deterministic: bool = False
    max_inline_bytes: int | None = None

    def supports(self, hook: str) -> bool:
        return hook in self.hooks

    def inline_limit(self, host_limit: int) -> int:
        """The smaller of what the plugin accepts and what the host offers.

        Declarations lower the limit; they never raise it. A plugin asking for
        more than the host allows would otherwise choose how much memory the
        host spends on it — the same attack the output limit in E1 exists to
        stop, arriving through the front door instead.
        """
        return (
            host_limit if self.max_inline_bytes is None else min(self.max_inline_bytes, host_limit)
        )


def _declaration(payload: Mapping[str, Any]) -> Handshake | None:
    """Validate a declaration. Unknown fields are ignored, never an error (D8)."""
    if any(field not in payload for field in REQUIRED_DECLARATION_FIELDS):
        return None

    hooks = payload["hooks"]
    if not isinstance(hooks, list) or not all(isinstance(hook, str) for hook in hooks):
        return None
    if not all(isinstance(payload[f], str) for f in ("rsp_version", "name", "version")):
        return None

    # Defaulting rather than guessing: a plugin that did not say it is
    # deterministic is not treated as one, because the cost of guessing wrong is
    # a cached verdict from a plugin whose answer depends on when you asked.
    deterministic = payload.get("deterministic", False)
    if not isinstance(deterministic, bool):
        return None

    max_inline = payload.get("max_inline_bytes")
    if max_inline is not None and (
        not isinstance(max_inline, int) or isinstance(max_inline, bool) or max_inline <= 0
    ):
        return None

    return Handshake(
        rsp_version=payload["rsp_version"],
        name=payload["name"],
        version=payload["version"],
        hooks=frozenset(hooks),
        deterministic=deterministic,
        max_inline_bytes=max_inline,
    )


def handshake(
    command: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> tuple[Outcome, Handshake | None]:
    """Ask a plugin who it is, before sending it any content (H1).

    Its own invocation rather than the first message of a stream, because one
    call is one process in v0.1 (Q6). The cost is an extra spawn per plugin per
    run, which caching cannot remove: the cache key contains the plugin version,
    and the version is what the handshake is for (#13).
    """
    reply = call(
        command,
        {"rsp_version": RSP_VERSION, "hook": "handshake"},
        timeout=timeout,
        max_output=max_output,
    )
    if not reply.ok:
        return reply.outcome, None

    declaration = _declaration(reply.payload)
    if declaration is None:
        return Outcome.MALFORMED, None
    return Outcome.OK, declaration
