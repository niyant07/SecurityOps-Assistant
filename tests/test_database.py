"""Tests for the SQLite persistence layer."""

from __future__ import annotations

from securityops.core.database import Database
from securityops.models import (
    Asset,
    AssetType,
    Evidence,
    Finding,
    Scan,
    ScanStatus,
    ScopeState,
    Severity,
)


def test_project_crud(db: Database) -> None:
    from securityops.models import Project

    created = db.projects.create(Project(name="Acme Pentest", client="Acme", authorized=True))
    assert created.id is not None

    fetched = db.projects.get(created.id)
    assert fetched is not None
    assert fetched.name == "Acme Pentest"
    assert fetched.authorized is True

    fetched.name = "Acme Pentest 2024"
    db.projects.update(fetched)
    assert db.projects.get(created.id).name == "Acme Pentest 2024"

    assert len(db.projects.list()) == 1
    db.projects.delete(created.id)
    assert db.projects.get(created.id) is None


def test_asset_scope_roundtrip(db: Database, project_id: int) -> None:
    asset = db.assets.create(Asset(
        project_id=project_id, identifier="10.0.0.5",
        asset_type=AssetType.HOST, scope=ScopeState.IN_SCOPE,
    ))
    assets = db.assets.list_for_project(project_id)
    assert len(assets) == 1
    assert assets[0].asset_type is AssetType.HOST
    assert assets[0].scope is ScopeState.IN_SCOPE
    assert asset.id is not None


def test_findings_sorted_by_severity(db: Database, project_id: int) -> None:
    db.findings.create(Finding(project_id=project_id, title="Low", severity=Severity.LOW))
    db.findings.create(Finding(project_id=project_id, title="Crit", severity=Severity.CRITICAL))
    db.findings.create(Finding(project_id=project_id, title="Med", severity=Severity.MEDIUM))

    findings = db.findings.list_for_project(project_id)
    severities = [f.severity for f in findings]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_scan_lifecycle(db: Database, project_id: int) -> None:
    scan = db.scans.create(Scan(
        project_id=project_id, tool="nmap", command="nmap -sV 10.0.0.5",
        target="10.0.0.5", status=ScanStatus.RUNNING,
    ))
    scan.status = ScanStatus.COMPLETED
    scan.exit_code = 0
    scan.output = "22/tcp open ssh"
    db.scans.update(scan)

    stored = db.scans.list_for_project(project_id)[0]
    assert stored.status is ScanStatus.COMPLETED
    assert stored.exit_code == 0
    assert "ssh" in stored.output


def test_evidence_links_to_finding(db: Database, project_id: int) -> None:
    finding = db.findings.create(Finding(project_id=project_id, title="XSS"))
    assert finding.id is not None
    db.evidence.create(Evidence(
        project_id=project_id, finding_id=finding.id,
        kind="screenshot", path="1/shot.png", caption="popup",
    ))
    linked = db.evidence.list_for_finding(finding.id)
    assert len(linked) == 1
    assert linked[0].caption == "popup"


def test_cascade_delete_removes_children(db: Database, project_id: int) -> None:
    db.assets.create(Asset(project_id=project_id, identifier="host"))
    db.findings.create(Finding(project_id=project_id, title="f"))
    db.projects.delete(project_id)
    assert db.assets.list_for_project(project_id) == []
    assert db.findings.list_for_project(project_id) == []
