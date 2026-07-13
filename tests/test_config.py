"""Tests for layered configuration loading."""

from __future__ import annotations

from pathlib import Path

from securityops.core.config import Config, load_config


def test_defaults_load() -> None:
    cfg = load_config()
    assert cfg.get("application.name")
    assert cfg.get("logging.level") in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def test_dotted_access_and_default() -> None:
    cfg = Config({"a": {"b": {"c": 42}}})
    assert cfg.get("a.b.c") == 42
    assert cfg.get("a.b.missing", "fallback") == "fallback"
    assert cfg.get("nope") is None


def test_user_override_deep_merges(tmp_path: Path) -> None:
    user_file = tmp_path / "config.yaml"
    user_file.write_text("ui:\n  theme: light\n", encoding="utf-8")
    cfg = load_config(user_file=user_file)
    # overridden value
    assert cfg.get("ui.theme") == "light"
    # untouched default still present
    assert cfg.get("application.name")


def test_section_returns_copy() -> None:
    cfg = Config({"logging": {"level": "DEBUG"}})
    section = cfg.section("logging")
    section["level"] = "INFO"
    assert cfg.get("logging.level") == "DEBUG"  # original unchanged
