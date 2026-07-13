"""Layered configuration loading.

Precedence (highest first):
    1. File pointed to by ``$SECURITYOPS_CONFIG``
    2. ``~/.config/securityops/config.yaml``
    3. Packaged ``config/default_config.yaml``

User values are deep-merged over the defaults so a partial user file only needs
to specify the keys it wants to change.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from . import paths


class ConfigError(RuntimeError):
    """Raised when configuration cannot be loaded or parsed."""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Failed to load config from {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Config root must be a mapping in {path}")
    return data


class Config:
    """Immutable-ish view over merged configuration with dotted-key access."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Return the value at ``"a.b.c"`` or *default* if any segment is missing."""
        node: Any = self._data
        for part in dotted_key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def section(self, name: str) -> dict[str, Any]:
        """Return a copy of a top-level section (or an empty dict)."""
        value = self._data.get(name, {})
        return copy.deepcopy(value) if isinstance(value, dict) else {}

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Config(keys={list(self._data)})"


def load_config(user_file: Path | None = None) -> Config:
    """Load and merge configuration from defaults and user overrides.

    Parameters
    ----------
    user_file:
        Optional explicit path. If omitted, ``$SECURITYOPS_CONFIG`` then the
        standard user config location are used.
    """
    defaults = _load_yaml(paths.packaged_default_config())

    candidate = user_file
    if candidate is None:
        env_path = os.environ.get("SECURITYOPS_CONFIG")
        candidate = Path(env_path) if env_path else paths.user_config_file()

    merged = defaults
    if candidate and candidate.exists():
        merged = _deep_merge(defaults, _load_yaml(candidate))

    return Config(merged)


def write_default_user_config() -> Path:
    """Write the packaged defaults to the user config path if it does not exist.

    Returns the path to the user config file.
    """
    target = paths.user_config_file()
    if not target.exists():
        source = paths.packaged_default_config().read_text(encoding="utf-8")
        target.write_text(source, encoding="utf-8")
    return target
