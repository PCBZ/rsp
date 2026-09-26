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


def test_a_plugin_that_answers_with_a_verdict_is_malformed() -> None:
    confused = declaring({"verdict": "ALLOW"})
    outcome, declaration = handshake(confused)
    assert outcome is Outcome.MALFORMED
    assert declaration is None


def test_process_failures_surface_unchanged() -> None:
    outcome, declaration = handshake([sys.executable, "-c", "import sys; sys.exit(2)"])
    assert outcome is Outcome.CRASHED
    assert declaration is None


def test_a_declaration_missing_a_field_is_refused_without_raising() -> None:
    """Absent and wrongly typed are one property, checked once: a lookup that
    assumes presence turns a malformed declaration into a crash in the host."""
    for missing in ("rsp_version", "name", "version", "hooks"):
        declaration = {
            "rsp_version": "0.1",
            "name": "p",
            "version": "1",
            "hooks": ["on_chunk"],
        }
        del declaration[missing]

        assert _declaration(declaration) is None, missing
