"""Handshake: who a plugin says it is, validated (H1, H2)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rsp.codec import RSP_VERSION, call
from rsp.process import DEFAULT_MAX_OUTPUT, DEFAULT_TIMEOUT, Outcome

_REQUIRED_FIELDS = ("rsp_version", "name", "version", "hooks")


@dataclass(frozen=True)
class Handshake:
    """What a plugin says it is (H2).

    Only the fields the host acts on: `hooks` gates dispatch (H3); `version` keys
    the cache and `deterministic` decides whether caching is legal (D4).
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
    if any(field not in payload for field in _REQUIRED_FIELDS):
        return None

    hooks = payload["hooks"]
    if not isinstance(hooks, list) or not all(isinstance(hook, str) for hook in hooks):
        return None
    if not all(isinstance(payload[f], str) for f in ("rsp_version", "name", "version")):
        return None

    # Absent means false: a wrong guess caches an answer that depends on when it was asked.
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

    Its own spawn, since one call is one process (Q6). Caching cannot remove it:
    the cache key needs the version this call fetches.
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
