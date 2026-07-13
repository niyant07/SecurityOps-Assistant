"""Central logging configuration.

Provides a rotating file handler plus an optional console handler. All modules
obtain loggers via :func:`logging.getLogger(__name__)`; this module only wires
up the root ``securityops`` logger once.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from . import paths

_LOGGER_NAME = "securityops"
_CONFIGURED = False

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(settings: dict[str, Any] | None = None) -> logging.Logger:
    """Configure and return the root application logger.

    Idempotent: repeated calls do not add duplicate handlers.

    Parameters
    ----------
    settings:
        The ``logging`` section of the configuration. Recognized keys:
        ``level``, ``console``, ``file``, ``max_bytes``, ``backup_count``.
    """
    global _CONFIGURED
    settings = settings or {}

    logger = logging.getLogger(_LOGGER_NAME)
    level_name = str(settings.get("level", "INFO")).upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    if _CONFIGURED:
        return logger

    formatter = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    if settings.get("console", True):
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    if settings.get("file", True):
        log_path: Path = paths.log_dir() / "securityops.log"
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=int(settings.get("max_bytes", 5 * 1024 * 1024)),
            backupCount=int(settings.get("backup_count", 5)),
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    _CONFIGURED = True
    logger.debug("Logging configured (level=%s)", level_name)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the ``securityops`` namespace."""
    if not name:
        return logging.getLogger(_LOGGER_NAME)
    return logging.getLogger(f"{_LOGGER_NAME}.{name}")
