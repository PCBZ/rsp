"""What a config file may say, and what happens when it says something else.

Each rejection is a way to switch a guard off while the file still reads as if it works.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

from rsp.cli import main
from rsp.config import load, plugins_from
from rsp.runtime import ConfigError, OnError, Runtime

ECHO = [sys.executable, str(pathlib.Path(__file__).parent.parent / "plugins/rsp-echo/main.py")]
REJECTED = {
    "a misspelled field": ({"name": "x", "command": ["true"], "on_eror": "allow"}, "on_eror"),
    "an unknown on_error": ({"name": "x", "command": ["true"], "on_error": "ignore"}, "block"),
    "a command as a string": ({"name": "x", "command": "gitleaks stdin"}, "not a string"),
    "an empty command": ({"name": "x", "command": []}, "non-empty list"),
    "a non-string argument": ({"name": "x", "command": ["true", 7]}, r"command\[1\]"),
    "no name": ({"command": ["true"]}, "missing name"),
    "an empty name": ({"name": "", "command": ["true"]}, "non-empty string"),
    "a zero timeout": ({"name": "x", "command": ["true"], "timeout": 0}, "positive"),
    "a negative timeout": ({"name": "x", "command": ["true"], "timeout": -1}, "positive"),
    "a boolean timeout": ({"name": "x", "command": ["true"], "timeout": True}, "positive"),
    # TOML spells both, and `nan <= 0` is false, so a positivity check lets NaN through.
    "a NaN timeout": ({"name": "x", "command": ["true"], "timeout": float("nan")}, "finite"),
    "an infinite timeout": ({"name": "x", "command": ["true"], "timeout": float("inf")}, "finite"),
    "a fractional size": ({"name": "x", "command": ["true"], "max_output": 2048.7}, "whole number"),
    "a zero size": ({"name": "x", "command": ["true"], "max_output": 0}, "positive"),
    "a plugin that is not a table": ("gitleaks", "expected a table"),
}


def test_a_minimal_entry_gets_the_documented_defaults() -> None:
    [plugin] = plugins_from({"plugins": [{"name": "x", "command": ["true"]}]})

    assert plugin.on_error is OnError.BLOCK, "an unconfigured failure blocks (D3)"
    assert plugin.timeout == 5.0, "E4's default"


def test_every_field_survives_the_round_trip() -> None:
    [plugin] = plugins_from(
        {
            "plugins": [
                {
                    "name": "gitleaks",
                    "command": ["node", "main.ts"],
                    "on_error": "skip",
                    "timeout": 1.5,
                    "max_output": 2048,
                }
            ]
        }
    )

    assert plugin.name == "gitleaks"
    assert plugin.command == ["node", "main.ts"]
    assert plugin.on_error is OnError.SKIP
    assert plugin.timeout == 1.5
    assert plugin.max_output == 2048


def test_the_order_of_the_file_is_the_order_of_the_plugins() -> None:
    """Composition is order-sensitive: `order` breaks span ties (D9)."""
    plugins = plugins_from(
        {
            "plugins": [
                {"name": "first", "command": ["true"]},
                {"name": "second", "command": ["true"]},
            ]
        }
    )

    assert [plugin.name for plugin in plugins] == ["first", "second"]


@pytest.mark.parametrize(("entry", "expected"), REJECTED.values(), ids=list(REJECTED))
def test_a_bad_entry_is_refused_and_says_why(entry: object, expected: str) -> None:
    with pytest.raises(ConfigError, match=expected):
        plugins_from({"plugins": [entry]})


def test_two_plugins_may_not_share_a_name() -> None:
    """Refused here too, so `rsp validate`, which starts nothing, can report it."""
    entry = {"name": "gitleaks", "command": ["true"]}

    with pytest.raises(ConfigError, match="configured twice"):
        plugins_from({"plugins": [entry, dict(entry)]})


def test_a_file_that_is_not_utf8_is_refused(tmp_path: pathlib.Path) -> None:
    """Not a crash: validate has a diagnostic and an exit code for this."""
    config = tmp_path / "latin.toml"
    config.write_bytes(b'[[plugins]]\nname = "caf\xe9"\ncommand = ["true"]\n')

    with pytest.raises(ConfigError, match=r"latin.toml"):
        load(config)


def test_an_unknown_top_level_key_is_refused() -> None:
    """`plugin = [...]` is one letter from working and would configure nothing."""
    with pytest.raises(ConfigError, match="unknown key"):
        plugins_from({"plugin": [{"name": "x", "command": ["true"]}]})


def test_a_file_with_no_plugins_is_refused() -> None:
    """A host with no guards is a thing to say out loud."""
    with pytest.raises(ConfigError, match="no plugins"):
        plugins_from({"plugins": []})


def test_a_document_that_is_not_a_table_is_refused() -> None:
    with pytest.raises(ConfigError, match="expected a table"):
        plugins_from(["gitleaks"])


def test_a_missing_file_names_itself(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ConfigError, match=r"absent.toml"):
        load(tmp_path / "absent.toml")


def test_malformed_toml_names_itself(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "broken.toml"
    config.write_text("[[plugins]\nname = 'x'\n")

    with pytest.raises(ConfigError, match=r"broken.toml"):
        load(config)


def test_a_config_file_produces_a_runtime_that_works(tmp_path: pathlib.Path) -> None:
    config = tmp_path / "rsp.toml"
    config.write_text(f'[[plugins]]\nname = "echo"\ncommand = {ECHO!r}\n'.replace("'", '"'))

    result = Runtime(load(config)).evaluate("on_chunk", "a secret here")

    assert result.content == "a [REDACTED:echo-test] here"


def test_validate_prints_each_plugin_and_succeeds(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "rsp.toml"
    config.write_text('[[plugins]]\nname = "gitleaks"\ncommand = ["node", "main.ts"]\n')

    assert main(["validate", str(config)]) == 0
    printed = capsys.readouterr()
    assert "gitleaks: node main.ts" in printed.out
    assert "on_error=block" in printed.out, "the default worth seeing in the output"
    assert "not started" in printed.err, "validate makes no claim about the binary"


def test_validate_reports_the_problem_and_fails(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit code, because a config check belongs in a pipeline."""
    config = tmp_path / "rsp.toml"
    config.write_text('[[plugins]]\nname = "x"\ncommand = "gitleaks stdin"\n')

    assert main(["validate", str(config)]) == 1
    assert "not a string" in capsys.readouterr().err


def test_validate_needs_a_config_path() -> None:
    with pytest.raises(SystemExit):
        main([])


def test_plugins_must_be_a_list() -> None:
    """`[plugins]` instead of `[[plugins]]` is the TOML mistake to expect."""
    with pytest.raises(ConfigError, match="list of tables"):
        plugins_from({"plugins": {"name": "x", "command": ["true"]}})
