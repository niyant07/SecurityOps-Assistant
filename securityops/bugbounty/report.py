"""Bug bounty report generation.

Extends the shared :class:`ReportGenerator` with a bug-bounty template that adds
Scope, Methodology, and per-finding Reproduction sections, while reusing the same
evidence embedding, severity counting, and PDF/Markdown machinery.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..models import Asset, Evidence, Finding, Project, Scan
from ..reporting.generator import ReportFormat, ReportGenerator
from .methodology import methodology_summary
from .scope import Scope


@dataclass
class BugBountyReportBundle:
    """All data required to render a bug bounty report."""

    project: Project
    scope: Scope
    findings: list[Finding]
    assets: list[Asset]
    scans: list[Scan]
    evidence: list[Evidence]
    executive_summary: str = ""


class BugBountyReportGenerator(ReportGenerator):
    """Render bug bounty reports to HTML / PDF / Markdown."""

    def render_html(self, bundle: BugBountyReportBundle,  # type: ignore[override]
                    evidence_root: Path | None = None) -> str:
        template = self._env.get_template("bugbounty_report.html")
        return template.render(
            project=bundle.project,
            scope=bundle.scope,
            findings=bundle.findings,
            assets=bundle.assets,
            scans=bundle.scans,
            evidence_by_finding=self._group_evidence(bundle.evidence, evidence_root),
            methodology=methodology_summary(bundle.scope.target_type),
            executive_summary=bundle.executive_summary or self._auto_summary(bundle.findings),
            author=self._author,
            company=self._company,
            classification=self._classification,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

    def render_markdown(self, bundle: BugBountyReportBundle) -> str:  # type: ignore[override]
        s = bundle.scope
        out: list[str] = [
            f"# {s.program or bundle.project.name} — Bug Bounty Assessment",
            "",
            f"*{s.platform + ' · ' if s.platform else ''}{s.target_type.value} · "
            f"{datetime.now(timezone.utc):%Y-%m-%d}*",
            "",
            f"**Classification:** {self._classification}",
            "",
            "## Executive Summary",
            "",
            bundle.executive_summary or self._auto_summary(bundle.findings),
            "",
            "## Scope",
            "",
            "**In scope:**",
        ]
        out += [f"- {t}" for t in s.in_scope] or ["- (none specified)"]
        out += ["", "**Out of scope:**"]
        out += [f"- {t}" for t in s.out_of_scope] or ["- (none specified)"]
        if s.rules:
            out += ["", "**Engagement rules:**", "", s.rules]
        out += ["", "## Methodology", "", "```", methodology_summary(s.target_type), "```", ""]

        out += ["## Findings", ""]
        if not bundle.findings:
            out += ["_No findings recorded._", ""]
        for i, f in enumerate(bundle.findings, 1):
            out += [f"### {i}. {f.title} — {f.severity.value}", ""]
            out.append(f"- **Affected:** {f.affected_asset or '—'}")
            if f.cvss_score is not None:
                vec = f" ({f.cvss_vector})" if f.cvss_vector else ""
                out.append(f"- **CVSS:** {f.cvss_score:.1f}{vec}")
            out += ["", f"**Description.** {f.description}", ""]
            if f.reproduction:
                out += ["**Steps to reproduce.**", "", "```", f.reproduction, "```", ""]
            if f.remediation:
                out += [f"**Remediation.** {f.remediation}", ""]
            if f.references:
                out += ["**References.**", "", f.references, ""]
        return "\n".join(out)

    def export(self, bundle: BugBountyReportBundle,  # type: ignore[override]
               output_path: Path, fmt: ReportFormat,
               evidence_root: Path | None = None) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt is ReportFormat.MARKDOWN:
            output_path.write_text(self.render_markdown(bundle), encoding="utf-8")
        elif fmt is ReportFormat.HTML:
            output_path.write_text(self.render_html(bundle, evidence_root), encoding="utf-8")
        elif fmt is ReportFormat.PDF:
            self._write_pdf(self.render_html(bundle, evidence_root), output_path)
        else:  # pragma: no cover
            raise ValueError(f"Unsupported format: {fmt}")
        return output_path
