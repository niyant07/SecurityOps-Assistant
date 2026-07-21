"""Tests for HTML and Markdown report generation."""

from __future__ import annotations

from securityops.models import Asset, AssetType, Finding, ScopeState, Severity
from securityops.reporting import ReportBundle, ReportFormat, ReportGenerator


def _bundle() -> ReportBundle:
    from securityops.models import Project

    project = Project(name="Acme Assessment", client="Acme", scope_notes="example.com")
    findings = [
        Finding(project_id=1, id=1, title="SQL Injection", severity=Severity.HIGH,
                description="Injectable id parameter.", affected_asset="example.com",
                cvss_score=8.6, remediation="Use parameterized queries."),
        Finding(project_id=1, id=2, title="Info leak", severity=Severity.LOW,
                description="Version banner exposed."),
    ]
    assets = [Asset(project_id=1, identifier="example.com",
                    asset_type=AssetType.DOMAIN, scope=ScopeState.IN_SCOPE)]
    return ReportBundle(project=project, findings=findings, assets=assets,
                        scans=[], evidence=[])


def test_render_html_contains_findings() -> None:
    html = ReportGenerator().render_html(_bundle())
    assert "Acme Assessment" in html
    assert "SQL Injection" in html
    assert "Executive Summary" in html
    assert "8.6" in html


def test_render_markdown_structure() -> None:
    md = ReportGenerator().render_markdown(_bundle())
    assert md.startswith("# Acme Assessment")
    assert "## Findings" in md
    assert "SQL Injection" in md
    assert "Use parameterized queries." in md


def test_export_writes_file(tmp_path) -> None:
    out = tmp_path / "report.md"
    written = ReportGenerator().export(_bundle(), out, ReportFormat.MARKDOWN)
    assert written.exists()
    assert "Acme Assessment" in written.read_text(encoding="utf-8")


def test_auto_summary_when_blank() -> None:
    html = ReportGenerator().render_html(_bundle())
    # auto summary mentions the finding count and max severity
    assert "identified 2 finding" in html
    assert "High" in html
