"""Handshake.

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
    """What a plugin says it is (H2). Only fields the host acts on: `hooks`
    gates dispatch (H3), `version` keys the cache (D4), `deterministic` decides
    whether caching is legal.
    """

    rsp_version: str
    name: str
    version: str
    hooks: frozenset[str]
    deterministic: bool = False

    def supports(self, hook: str) -> bool:
        return hook in self.hooks


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

    return Handshake(
        rsp_version=payload["rsp_version"],
        name=payload["name"],
        version=payload["version"],
        hooks=frozenset(hooks),
        deterministic=deterministic,
    )


def handshake(
    command: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> tuple[Outcome, Handshake | None]:
    """Ask a plugin who it is, before sending it any content (H1).

    Its own invocation, since one call is one process (Q6). Costs a spawn per
    plugin per run that caching cannot remove — the cache key needs the version
    this call exists to fetch.
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
