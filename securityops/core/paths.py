"""Cross-platform resolution of application directories.

Follows the XDG Base Directory spec on Linux and falls back to sensible
locations on macOS/Windows so the app can at least run for development. All
functions ensure the returned directory exists.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_APP_DIRNAME = "securityops"


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _ensure(path: Path) -> Path:
    """Create *path* (and parents) if needed and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_dir() -> Path:
    """Directory holding the user's ``config.yaml``."""
    if sys.platform.startswith("linux"):
        base = os.environ.get("XDG_CONFIG_HOME") or (_home() / ".config")
    elif sys.platform == "darwin":
        base = _home() / "Library" / "Application Support"
    else:  # Windows / other
        base = os.environ.get("APPDATA") or (_home() / "AppData" / "Roaming")
    return _ensure(Path(base) / _APP_DIRNAME)


def data_dir() -> Path:
    """Directory holding the database, evidence, and other persistent data."""
    if sys.platform.startswith("linux"):
        base = os.environ.get("XDG_DATA_HOME") or (_home() / ".local" / "share")
    elif sys.platform == "darwin":
        base = _home() / "Library" / "Application Support"
    else:  # Windows / other
        base = os.environ.get("LOCALAPPDATA") or (_home() / "AppData" / "Local")
    return _ensure(Path(base) / _APP_DIRNAME)


def log_dir() -> Path:
    """Directory holding rotating log files."""
    if sys.platform.startswith("linux"):
        base = os.environ.get("XDG_STATE_HOME") or (_home() / ".local" / "state")
        return _ensure(Path(base) / _APP_DIRNAME / "logs")
    return _ensure(data_dir() / "logs")


def evidence_dir() -> Path:
    """Directory holding collected evidence (screenshots, files)."""
    return _ensure(data_dir() / "evidence")


def reports_dir() -> Path:
    """Default directory for generated reports."""
    return _ensure(data_dir() / "reports")


def downloads_dir() -> Path:
    """The user's Downloads folder (for one-click report downloads).

    Honors the XDG user-dirs ``XDG_DOWNLOAD_DIR`` on Linux when set, otherwise
    falls back to ``~/Downloads``. Created if it does not yet exist.
    """
    env = os.environ.get("XDG_DOWNLOAD_DIR")
    if env:
        return _ensure(Path(os.path.expandvars(env)))
    return _ensure(_home() / "Downloads")


def user_config_file() -> Path:
    """Path to the user's config file (may not yet exist)."""
    return config_dir() / "config.yaml"


def packaged_default_config() -> Path:
    """Path to the shipped default configuration file."""
    return Path(__file__).resolve().parent.parent / "config" / "default_config.yaml"
