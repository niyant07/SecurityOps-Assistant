"""Core services: configuration, logging, persistence, threading, plugins, tools.

Nothing in this package imports from :mod:`securityops.gui`, so the core can be
exercised headlessly in unit tests.
"""

from __future__ import annotations

__all__ = [
    "paths",
    "config",
    "logging_config",
    "database",
    "tasks",
    "tools",
    "plugins",
]
