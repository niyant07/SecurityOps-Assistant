"""Typed domain models used across the application.

These are plain dataclasses with no persistence logic of their own; the
:mod:`securityops.core.database` layer maps them to/from SQLite rows. Keeping
them framework-free makes them trivial to unit test.
"""

from __future__ import annotations

from .enums import AssetType, ScanStatus, ScopeState, Severity
from .records import Asset, Evidence, Finding, Project, Scan

__all__ = [
    "AssetType",
    "ScanStatus",
    "ScopeState",
    "Severity",
    "Asset",
    "Evidence",
    "Finding",
    "Project",
    "Scan",
]
