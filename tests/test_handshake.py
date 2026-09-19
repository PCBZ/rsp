"""Handshake tests — H1, H2, H3, H4, D8."""

from __future__ import annotations

import json
import sys

import pytest

from rsp.handshake import Handshake, Outcome, _declaration, handshake

ECHO = [sys.executable, "plugins/rsp-echo/main.py"]

VALID = {
    "rsp_version": "0.1",
    "name": "rsp-echo",
    "version": "0.1.0",
    "hooks": ["on_chunk", "on_retrieve"],
}


def declaring(payload: dict) -> list[str]:
    """A plugin that answers the handshake with exactly this payload."""
    return [sys.executable, "-c", f"import sys; sys.stdin.read(); print({json.dumps(payload)!r})"]


def test_reference_plugin_declares_itself() -> None:
    outcome, declaration = handshake(ECHO)
    assert outcome is Outcome.OK
    assert declaration.name == "rsp-echo"
    assert declaration.deterministic is True
    assert declaration.hooks == frozenset({"on_chunk", "on_retrieve", "on_response"})


def test_declared_hooks_decide_what_may_be_called() -> None:
    """H3: a plugin that declared only on_chunk must not see a retrieval hit."""
    declaration = _declaration({**VALID, "hooks": ["on_chunk"]})
    assert declaration.supports("on_chunk")
    assert not declaration.supports("on_retrieve")


@pytest.mark.parametrize("missing", ["rsp_version", "name", "version", "hooks"])
def test_a_declaration_missing_a_required_field_is_rejected(missing: str) -> None:
    payload = {k: v for k, v in VALID.items() if k != missing}
    assert _declaration(payload) is None


@pytest.mark.parametrize(
    "payload",
    [
        {**VALID, "hooks": "on_chunk"},  # a string, not a list
        {**VALID, "hooks": [1, 2]},  # not strings
        {**VALID, "version": 1.0},  # not a string
        {**VALID, "deterministic": "yes"},  # not a bool
        {**VALID, "max_inline_bytes": 0},
        {**VALID, "max_inline_bytes": -1},
        {**VALID, "max_inline_bytes": "1MiB"},
        {**VALID, "max_inline_bytes": True},  # a bool is not a size
    ],
)
def test_wrong_types_are_rejected(payload: dict) -> None:
    assert _declaration(payload) is None


def test_unknown_fields_are_ignored() -> None:
    """D8: a field from a future version must not break an older host."""
    declaration = _declaration({**VALID, "supports_streaming": True, "vendor": {"x": 1}})
    assert isinstance(declaration, Handshake)
    assert declaration.name == "rsp-echo"


def test_undeclared_determinism_means_uncacheable() -> None:
    """Guessing wrong caches a plugin whose answer depends on when you asked."""
    assert _declaration(VALID).deterministic is False


def test_a_plugin_cannot_raise_the_hosts_inline_limit() -> None:
    greedy = _declaration({**VALID, "max_inline_bytes": 8 << 20})
    assert greedy.inline_limit(1 << 20) == 1 << 20  # host wins
    modest = _declaration({**VALID, "max_inline_bytes": 4096})
    assert modest.inline_limit(1 << 20) == 4096  # plugin may lower it
    assert _declaration(VALID).inline_limit(1 << 20) == 1 << 20  # silence means the host's


def test_a_plugin_that_answers_with_a_verdict_is_malformed() -> None:
    confused = declaring({"verdict": "ALLOW"})
    outcome, declaration = handshake(confused)
    assert outcome is Outcome.MALFORMED
    assert declaration is None


def test_process_failures_surface_unchanged() -> None:
    outcome, declaration = handshake([sys.executable, "-c", "import sys; sys.exit(2)"])
    assert outcome is Outcome.CRASHED
    assert declaration is None
