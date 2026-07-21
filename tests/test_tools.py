"""Tests for tool catalog, detection, and command building."""

from __future__ import annotations

import pytest

from securityops.core.tools import (
    CATALOG,
    CATALOG_BY_KEY,
    MissingParameterError,
    ToolRegistry,
)


def test_catalog_keys_unique() -> None:
    keys = [spec.key for spec in CATALOG]
    assert len(keys) == len(set(keys))


def test_registry_detects_all_catalog_entries() -> None:
    registry = ToolRegistry()
    detected = registry.all()
    assert len(detected) == len(CATALOG)
    # every catalog key is represented
    assert {d.spec.key for d in detected} == set(CATALOG_BY_KEY)


def test_build_command_simple_target() -> None:
    registry = ToolRegistry()
    command = registry.build_command("nmap", "10.0.0.5")
    assert "10.0.0.5" in command
    assert command.startswith("nmap") or "/nmap" in command


def test_build_command_missing_param_raises() -> None:
    registry = ToolRegistry()
    # gobuster template needs {wordlist}
    with pytest.raises(MissingParameterError):
        registry.build_command("gobuster", "http://example.com")


def test_build_command_with_params() -> None:
    registry = ToolRegistry()
    command = registry.build_command(
        "gobuster", "http://example.com", {"wordlist": "/tmp/wl.txt"}
    )
    assert "/tmp/wl.txt" in command
    assert "http://example.com" in command


def test_unknown_tool_raises_keyerror() -> None:
    registry = ToolRegistry()
    with pytest.raises(KeyError):
        registry.build_command("does-not-exist", "target")


def test_split_command_no_shell() -> None:
    argv = ToolRegistry.split_command('nmap -sV "10.0.0.5"')
    assert argv == ["nmap", "-sV", "10.0.0.5"]
