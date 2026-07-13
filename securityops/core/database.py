"""SQLite persistence layer.

A single :class:`Database` owns one connection guarded by a lock so it can be
shared safely across worker threads. Entity access is exposed through small
repository objects (``db.projects``, ``db.assets`` ...) that map dataclass
records to/from rows.

The schema is created on first use and versioned via ``PRAGMA user_version`` so
future migrations have a hook.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..models import (
    Asset,
    AssetType,
    Evidence,
    Finding,
    Project,
    Scan,
    ScanStatus,
    ScopeState,
    Severity,
)
from .logging_config import get_logger

_LOG = get_logger("database")

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    client       TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    scope_notes  TEXT NOT NULL DEFAULT '',
    authorized   INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    identifier   TEXT NOT NULL,
    asset_type   TEXT NOT NULL,
    scope        TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tool         TEXT NOT NULL,
    command      TEXT NOT NULL,
    status       TEXT NOT NULL,
    target       TEXT NOT NULL DEFAULT '',
    output       TEXT NOT NULL DEFAULT '',
    exit_code    INTEGER,
    started_at   TEXT,
    finished_at  TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    cvss_score    REAL,
    cvss_vector   TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    references_   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id   INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,
    path         TEXT NOT NULL DEFAULT '',
    caption      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_project   ON assets(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_project    ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project_id);
"""


# --------------------------------------------------------------------------- #
# datetime (de)serialization helpers
# --------------------------------------------------------------------------- #
def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# --------------------------------------------------------------------------- #
# Repositories
# --------------------------------------------------------------------------- #
class _BaseRepo:
    def __init__(self, db: "Database") -> None:
        self._db = db


class ProjectRepo(_BaseRepo):
    @staticmethod
    def _row(r: sqlite3.Row) -> Project:
        return Project(
            id=r["id"],
            name=r["name"],
            client=r["client"],
            description=r["description"],
            scope_notes=r["scope_notes"],
            authorized=bool(r["authorized"]),
            created_at=_parse(r["created_at"]),  # type: ignore[arg-type]
            updated_at=_parse(r["updated_at"]),  # type: ignore[arg-type]
        )

    def create(self, project: Project) -> Project:
        cur = self._db.execute(
            "INSERT INTO projects (name, client, description, scope_notes, authorized, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                project.name,
                project.client,
                project.description,
                project.scope_notes,
                int(project.authorized),
                _iso(project.created_at),
                _iso(project.updated_at),
            ),
        )
        project.id = int(cur.lastrowid)
        _LOG.info("Created project id=%s name=%r", project.id, project.name)
        return project

    def update(self, project: Project) -> None:
        if project.id is None:
            raise ValueError("Cannot update a project without an id")
        project.updated_at = datetime.now(timezone.utc)
        self._db.execute(
            "UPDATE projects SET name=?, client=?, description=?, scope_notes=?, "
            "authorized=?, updated_at=? WHERE id=?",
            (
                project.name,
                project.client,
                project.description,
                project.scope_notes,
                int(project.authorized),
                _iso(project.updated_at),
                project.id,
            ),
        )

    def get(self, project_id: int) -> Project | None:
        row = self._db.query_one("SELECT * FROM projects WHERE id=?", (project_id,))
        return self._row(row) if row else None

    def list(self) -> list[Project]:
        rows = self._db.query_all("SELECT * FROM projects ORDER BY updated_at DESC")
        return [self._row(r) for r in rows]

    def delete(self, project_id: int) -> None:
        self._db.execute("DELETE FROM projects WHERE id=?", (project_id,))
        _LOG.info("Deleted project id=%s", project_id)


class AssetRepo(_BaseRepo):
    @staticmethod
    def _row(r: sqlite3.Row) -> Asset:
        return Asset(
            id=r["id"],
            project_id=r["project_id"],
            identifier=r["identifier"],
            asset_type=AssetType(r["asset_type"]),
            scope=ScopeState(r["scope"]),
            label=r["label"],
            notes=r["notes"],
            created_at=_parse(r["created_at"]),  # type: ignore[arg-type]
        )

    def create(self, asset: Asset) -> Asset:
        cur = self._db.execute(
            "INSERT INTO assets (project_id, identifier, asset_type, scope, label, "
            "notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                asset.project_id,
                asset.identifier,
                asset.asset_type.value,
                asset.scope.value,
                asset.label,
                asset.notes,
                _iso(asset.created_at),
            ),
        )
        asset.id = int(cur.lastrowid)
        return asset

    def update(self, asset: Asset) -> None:
        if asset.id is None:
            raise ValueError("Cannot update an asset without an id")
        self._db.execute(
            "UPDATE assets SET identifier=?, asset_type=?, scope=?, label=?, notes=? "
            "WHERE id=?",
            (
                asset.identifier,
                asset.asset_type.value,
                asset.scope.value,
                asset.label,
                asset.notes,
                asset.id,
            ),
        )

    def list_for_project(self, project_id: int) -> list[Asset]:
        rows = self._db.query_all(
            "SELECT * FROM assets WHERE project_id=? ORDER BY identifier", (project_id,)
        )
        return [self._row(r) for r in rows]

    def delete(self, asset_id: int) -> None:
        self._db.execute("DELETE FROM assets WHERE id=?", (asset_id,))


class ScanRepo(_BaseRepo):
    @staticmethod
    def _row(r: sqlite3.Row) -> Scan:
        return Scan(
            id=r["id"],
            project_id=r["project_id"],
            tool=r["tool"],
            command=r["command"],
            status=ScanStatus(r["status"]),
            target=r["target"],
            output=r["output"],
            exit_code=r["exit_code"],
            started_at=_parse(r["started_at"]),
            finished_at=_parse(r["finished_at"]),
            created_at=_parse(r["created_at"]),  # type: ignore[arg-type]
        )

    def create(self, scan: Scan) -> Scan:
        cur = self._db.execute(
            "INSERT INTO scans (project_id, tool, command, status, target, output, "
            "exit_code, started_at, finished_at, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan.project_id,
                scan.tool,
                scan.command,
                scan.status.value,
                scan.target,
                scan.output,
                scan.exit_code,
                _iso(scan.started_at),
                _iso(scan.finished_at),
                _iso(scan.created_at),
            ),
        )
        scan.id = int(cur.lastrowid)
        return scan

    def update(self, scan: Scan) -> None:
        if scan.id is None:
            raise ValueError("Cannot update a scan without an id")
        self._db.execute(
            "UPDATE scans SET status=?, output=?, exit_code=?, started_at=?, "
            "finished_at=? WHERE id=?",
            (
                scan.status.value,
                scan.output,
                scan.exit_code,
                _iso(scan.started_at),
                _iso(scan.finished_at),
                scan.id,
            ),
        )

    def list_for_project(self, project_id: int) -> list[Scan]:
        rows = self._db.query_all(
            "SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC",
            (project_id,),
        )
        return [self._row(r) for r in rows]


class FindingRepo(_BaseRepo):
    @staticmethod
    def _row(r: sqlite3.Row) -> Finding:
        return Finding(
            id=r["id"],
            project_id=r["project_id"],
            title=r["title"],
            severity=Severity(r["severity"]),
            description=r["description"],
            affected_asset=r["affected_asset"],
            cvss_score=r["cvss_score"],
            cvss_vector=r["cvss_vector"],
            remediation=r["remediation"],
            references=r["references_"],
            created_at=_parse(r["created_at"]),  # type: ignore[arg-type]
            updated_at=_parse(r["updated_at"]),  # type: ignore[arg-type]
        )

    def create(self, finding: Finding) -> Finding:
        cur = self._db.execute(
            "INSERT INTO findings (project_id, title, severity, description, "
            "affected_asset, cvss_score, cvss_vector, remediation, references_, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.project_id,
                finding.title,
                finding.severity.value,
                finding.description,
                finding.affected_asset,
                finding.cvss_score,
                finding.cvss_vector,
                finding.remediation,
                finding.references,
                _iso(finding.created_at),
                _iso(finding.updated_at),
            ),
        )
        finding.id = int(cur.lastrowid)
        return finding

    def update(self, finding: Finding) -> None:
        if finding.id is None:
            raise ValueError("Cannot update a finding without an id")
        finding.updated_at = datetime.now(timezone.utc)
        self._db.execute(
            "UPDATE findings SET title=?, severity=?, description=?, affected_asset=?, "
            "cvss_score=?, cvss_vector=?, remediation=?, references_=?, updated_at=? "
            "WHERE id=?",
            (
                finding.title,
                finding.severity.value,
                finding.description,
                finding.affected_asset,
                finding.cvss_score,
                finding.cvss_vector,
                finding.remediation,
                finding.references,
                _iso(finding.updated_at),
                finding.id,
            ),
        )

    def list_for_project(self, project_id: int) -> list[Finding]:
        rows = self._db.query_all(
            "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC",
            (project_id,),
        )
        findings = [self._row(r) for r in rows]
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings

    def delete(self, finding_id: int) -> None:
        self._db.execute("DELETE FROM findings WHERE id=?", (finding_id,))


class EvidenceRepo(_BaseRepo):
    @staticmethod
    def _row(r: sqlite3.Row) -> Evidence:
        return Evidence(
            id=r["id"],
            project_id=r["project_id"],
            finding_id=r["finding_id"],
            kind=r["kind"],
            path=r["path"],
            caption=r["caption"],
            created_at=_parse(r["created_at"]),  # type: ignore[arg-type]
        )

    def create(self, evidence: Evidence) -> Evidence:
        cur = self._db.execute(
            "INSERT INTO evidence (project_id, finding_id, kind, path, caption, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                evidence.project_id,
                evidence.finding_id,
                evidence.kind,
                evidence.path,
                evidence.caption,
                _iso(evidence.created_at),
            ),
        )
        evidence.id = int(cur.lastrowid)
        return evidence

    def list_for_project(self, project_id: int) -> list[Evidence]:
        rows = self._db.query_all(
            "SELECT * FROM evidence WHERE project_id=? ORDER BY created_at DESC",
            (project_id,),
        )
        return [self._row(r) for r in rows]

    def list_for_finding(self, finding_id: int) -> list[Evidence]:
        rows = self._db.query_all(
            "SELECT * FROM evidence WHERE finding_id=? ORDER BY created_at DESC",
            (finding_id,),
        )
        return [self._row(r) for r in rows]

    def delete(self, evidence_id: int) -> None:
        self._db.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))


# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
class Database:
    """Thread-safe SQLite wrapper exposing entity repositories."""

    def __init__(self, db_path: str | Path) -> None:
        self._path = str(db_path)
        self._lock = threading.RLock()
        # check_same_thread=False + our own lock lets worker threads share this.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

        self.projects = ProjectRepo(self)
        self.assets = AssetRepo(self)
        self.scans = ScanRepo(self)
        self.findings = FindingRepo(self)
        self.evidence = EvidenceRepo(self)
        _LOG.info("Database ready at %s", self._path)

    # -- schema ----------------------------------------------------------- #
    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            (version,) = self._conn.execute("PRAGMA user_version").fetchone()
            if version < SCHEMA_VERSION:
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.commit()

    # -- low-level helpers ------------------------------------------------ #
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        """Execute a writing statement and commit."""
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def query_all(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
        _LOG.debug("Database connection closed")

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
