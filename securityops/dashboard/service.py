"""Read-only aggregation of persisted application activity for the dashboard."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.database import Database
from ..models import Confidence, Scan, ScanStatus, Severity


@dataclass(frozen=True)
class DashboardSnapshot:
    """A point-in-time summary derived from persisted application records."""

    project_count: int
    asset_count: int
    finding_count: int
    critical_high_count: int
    awaiting_verification_count: int
    active_assessment_count: int
    failed_scan_count: int
    installed_tool_count: int
    catalog_tool_count: int
    recent_scans: tuple[Scan, ...]


class DashboardService:
    """Collect dashboard metrics using the existing database repositories."""

    def __init__(self, database: Database, installed_tool_count: int,
                 catalog_tool_count: int) -> None:
        self._database = database
        self._installed_tool_count = installed_tool_count
        self._catalog_tool_count = catalog_tool_count

    def snapshot(self) -> DashboardSnapshot:
        """Return aggregate metrics and the five most recent persisted scans."""
        projects = self._database.projects.list()
        assets = []
        findings = []
        scans: list[Scan] = []
        for project in projects:
            if project.id is None:
                continue
            assets.extend(self._database.assets.list_for_project(project.id))
            findings.extend(self._database.findings.list_for_project(project.id))
            scans.extend(self._database.scans.list_for_project(project.id))

        scans.sort(key=lambda scan: scan.created_at, reverse=True)
        return DashboardSnapshot(
            project_count=len(projects),
            asset_count=len(assets),
            finding_count=len(findings),
            critical_high_count=sum(
                finding.severity in (Severity.CRITICAL, Severity.HIGH)
                for finding in findings
            ),
            awaiting_verification_count=sum(
                finding.confidence is Confidence.TENTATIVE for finding in findings
            ),
            active_assessment_count=sum(
                scan.status is ScanStatus.RUNNING for scan in scans
            ),
            failed_scan_count=sum(
                scan.status is ScanStatus.FAILED for scan in scans
            ),
            installed_tool_count=self._installed_tool_count,
            catalog_tool_count=self._catalog_tool_count,
            recent_scans=tuple(scans[:5]),
        )
