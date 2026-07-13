"""Dataclass records for persisted entities.

Each record carries an optional integer ``id`` (``None`` until inserted). Times
are timezone-aware UTC ``datetime`` objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .enums import AssetType, ScanStatus, ScopeState, Severity


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


@dataclass
class Project:
    """A security engagement / assessment project."""

    name: str
    client: str = ""
    description: str = ""
    scope_notes: str = ""
    authorized: bool = False
    id: int | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)


@dataclass
class Asset:
    """An inventoried target within a project."""

    project_id: int
    identifier: str                     # hostname, IP, URL, CIDR, ...
    asset_type: AssetType = AssetType.HOST
    scope: ScopeState = ScopeState.PENDING
    label: str = ""
    notes: str = ""
    id: int | None = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class Scan:
    """A recorded tool execution against the project/assets."""

    project_id: int
    tool: str
    command: str
    status: ScanStatus = ScanStatus.QUEUED
    target: str = ""
    output: str = ""
    exit_code: int | None = None
    id: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class Finding:
    """A vulnerability/observation discovered during the assessment."""

    project_id: int
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    affected_asset: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    remediation: str = ""
    references: str = ""                 # newline-separated URLs/notes
    id: int | None = None
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)


@dataclass
class Evidence:
    """A file/screenshot/note attached to a finding."""

    project_id: int
    finding_id: int | None
    kind: str                            # "screenshot", "file", "note"
    path: str = ""                       # relative path under evidence dir
    caption: str = ""
    id: int | None = None
    created_at: datetime = field(default_factory=utcnow)
