"""Tests for persisted dashboard aggregation."""

from __future__ import annotations

from securityops.core.database import Database
from securityops.dashboard import DashboardService
from securityops.models import (
    Asset,
    Confidence,
    Finding,
    Project,
    Scan,
    ScanStatus,
    ScopeState,
    Severity,
)


def test_snapshot_aggregates_records_across_projects(db: Database) -> None:
    first = db.projects.create(Project(name="First"))
    second = db.projects.create(Project(name="Second"))
    assert first.id is not None
    assert second.id is not None

    db.assets.create(Asset(project_id=first.id, identifier="app.example.test",
                           scope=ScopeState.IN_SCOPE))
    db.findings.create(Finding(
        project_id=first.id, title="Critical issue", severity=Severity.CRITICAL,
        confidence=Confidence.TENTATIVE,
    ))
    db.findings.create(Finding(
        project_id=second.id, title="Low issue", severity=Severity.LOW,
    ))
    db.scans.create(Scan(
        project_id=first.id, tool="nmap", command="nmap example.test",
        target="example.test", status=ScanStatus.FAILED,
    ))
    db.scans.create(Scan(
        project_id=second.id, tool="nmap", command="nmap example.test",
        target="example.test", status=ScanStatus.RUNNING,
    ))

    snapshot = DashboardService(db, 2, 24).snapshot()

    assert snapshot.project_count == 2
    assert snapshot.asset_count == 1
    assert snapshot.finding_count == 2
    assert snapshot.critical_high_count == 1
    assert snapshot.awaiting_verification_count == 1
    assert snapshot.active_assessment_count == 1
    assert snapshot.failed_scan_count == 1
    assert snapshot.installed_tool_count == 2
    assert snapshot.catalog_tool_count == 24
    assert len(snapshot.recent_scans) == 2


def test_snapshot_handles_empty_database(db: Database) -> None:
    snapshot = DashboardService(db, 0, 24).snapshot()

    assert snapshot.project_count == 0
    assert snapshot.asset_count == 0
    assert snapshot.finding_count == 0
    assert snapshot.recent_scans == ()
