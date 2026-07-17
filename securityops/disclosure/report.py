"""Responsible-disclosure report generation.

Extends the shared :class:`ReportGenerator` with a disclosure template that adds
Business Impact and a Timeline of Assessment, and surfaces each finding's
confidence level. Reuses the platform's evidence embedding and PDF/Markdown
machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..models import Asset, Evidence, Finding, Project, Scan
from ..reporting.generator import ReportFormat, ReportGenerator
from .curate import CuratedFindings, curate_findings


@dataclass
class DisclosureReportBundle:
    """All data required to render a disclosure report."""

    project: Project
    target: str
    findings: list[Finding]
    assets: list[Asset] = field(default_factory=list)
    scans: list[Scan] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    organization: str = ""
    methodology: str = ""
    executive_summary: str = ""
    report_version: str = "v1"


class DisclosureReportGenerator(ReportGenerator):
    """Render responsible-disclosure reports to HTML / PDF / Markdown."""

    def _context(self, bundle: DisclosureReportBundle, evidence_root: Path | None):
        curated = curate_findings(bundle.findings)
        return {
            "curated": curated,
            "target": bundle.target,
            "organization": bundle.organization,
            "findings": curated.ranked,
            "evidence_by_finding": self._group_evidence(bundle.evidence, evidence_root),
            "severity_counts": [(s.value, n) for s, n in
                                sorted(curated.severity_counts.items(),
                                       key=lambda kv: kv[0].rank, reverse=True)],
            "needs_verification": len(curated.needs_verification),
            "scope": self._scope_text(bundle),
            "methodology": bundle.methodology or _DEFAULT_METHODOLOGY,
            "timeline": self._timeline(bundle),
            "executive_summary": bundle.executive_summary or self._auto_summary(curated.ranked),
            "report_version": bundle.report_version,
            "author": self._author,
            "company": self._company,
            "classification": self._classification,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }

    def render_html(self, bundle: DisclosureReportBundle,  # type: ignore[override]
                    evidence_root: Path | None = None) -> str:
        template = self._env.get_template("disclosure_report.html")
        return template.render(**self._context(bundle, evidence_root))

    def render_markdown(self, bundle: DisclosureReportBundle) -> str:  # type: ignore[override]
        curated = curate_findings(bundle.findings)
        out: list[str] = [
            f"# Vulnerability Disclosure Report — {bundle.target}",
            "",
            f"*Prepared by {self._author}"
            + (f", {self._company}" if self._company else "")
            + f" · Report {bundle.report_version} · {datetime.now(timezone.utc):%Y-%m-%d}*",
            "",
            f"**Classification:** {self._classification}",
            "",
            "## Executive Summary",
            "",
            bundle.executive_summary or self._auto_summary(curated.ranked),
            "",
        ]
        if curated.severity_counts:
            out += ["| Severity | Count |", "|----------|-------|"]
            out += [f"| {s.value} | {n} |" for s, n in
                    sorted(curated.severity_counts.items(), key=lambda kv: kv[0].rank, reverse=True)]
            out.append("")
        if curated.needs_verification:
            out += [f"> {len(curated.needs_verification)} finding(s) require additional "
                    f"manual verification (marked Tentative).", ""]

        out += ["## Scope", "", self._scope_text(bundle), "",
                "## Assessment Methodology", "", "```",
                bundle.methodology or _DEFAULT_METHODOLOGY, "```", "",
                "## Technical Findings", ""]
        if not curated.ranked:
            out += ["_No verified findings recorded._", ""]
        for i, f in enumerate(curated.ranked, 1):
            flag = "  ⚑ verify" if f.confidence.needs_verification else ""
            out += [f"### {i}. {f.title} — {f.severity.value} (Confidence: {f.confidence.value}){flag}", ""]
            out.append(f"- **Affected:** {f.affected_asset or '—'}")
            if f.cvss_score is not None:
                vec = f" ({f.cvss_vector})" if f.cvss_vector else ""
                out.append(f"- **CVSS:** {f.cvss_score:.1f}{vec}")
            out += ["", f"**Description.** {f.description}", ""]
            if f.business_impact:
                out += [f"**Business impact.** {f.business_impact}", ""]
            if f.reproduction:
                out += ["**Steps to reproduce.**", "", "```", f.reproduction, "```", ""]
            if f.remediation:
                out += [f"**Suggested remediation.** {f.remediation}", ""]
            if f.references:
                out += ["**References.**", "", f.references, ""]

        out += ["## Timeline of Assessment", "", "| Date | Event |", "|------|-------|"]
        out += [f"| {w} | {e} |" for w, e in self._timeline(bundle)]
        out.append("")
        return "\n".join(out)

    def export(self, bundle: DisclosureReportBundle,  # type: ignore[override]
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

    # ------------------------------------------------------------------ #
    @staticmethod
    def _scope_text(bundle: DisclosureReportBundle) -> str:
        in_scope = [a.identifier for a in bundle.assets
                    if a.scope.value == "In Scope"]
        base = f"This report concerns the authorized assessment of {bundle.target}."
        if in_scope:
            base += " In-scope assets: " + ", ".join(in_scope) + "."
        if bundle.project.scope_notes:
            base += "\n\n" + bundle.project.scope_notes
        return base

    @staticmethod
    def _timeline(bundle: DisclosureReportBundle) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        scans = [s for s in bundle.scans if s.created_at]
        if bundle.project.created_at:
            events.append((bundle.project.created_at.strftime("%Y-%m-%d"),
                           "Engagement initiated"))
        if scans:
            starts = [s.started_at or s.created_at for s in scans]
            ends = [s.finished_at or s.created_at for s in scans]
            first = min(starts)
            last = max(ends)
            events.append((first.strftime("%Y-%m-%d %H:%M"), "Assessment / testing began"))
            events.append((last.strftime("%Y-%m-%d %H:%M"),
                           f"Testing completed ({len(scans)} tool run(s))"))
        events.append((datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                       f"Disclosure report {bundle.report_version} prepared"))
        # De-duplicate consecutive identical (date,event)
        seen: set[tuple[str, str]] = set()
        unique = []
        for e in events:
            if e not in seen:
                seen.add(e)
                unique.append(e)
        return unique


_DEFAULT_METHODOLOGY = (
    "The assessment followed a structured methodology: reconnaissance to map the "
    "attack surface, enumeration of live services and technologies, and "
    "vulnerability assessment of the in-scope assets using industry-standard "
    "tooling. All testing was non-destructive and limited to authorized, in-scope "
    "targets. Each finding was recorded with supporting evidence and a confidence "
    "level; tentative items are flagged for further verification."
)
