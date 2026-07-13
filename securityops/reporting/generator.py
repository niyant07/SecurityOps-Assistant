"""Assessment report generator.

Assembles project data into an HTML document via Jinja2, then optionally exports
to PDF (WeasyPrint) or Markdown. Screenshots are embedded as base64 data URIs so
HTML/PDF reports are self-contained.
"""

from __future__ import annotations

import base64
import mimetypes
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.logging_config import get_logger
from ..models import Asset, Evidence, Finding, Project, Scan, Severity

_LOG = get_logger("reporting")

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class ReportFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "md"


@dataclass
class ReportBundle:
    """All data required to render a report."""

    project: Project
    findings: list[Finding]
    assets: list[Asset]
    scans: list[Scan]
    evidence: list[Evidence]
    executive_summary: str = ""


class ReportGenerator:
    """Render :class:`ReportBundle` objects to HTML/PDF/Markdown."""

    def __init__(self, config_section: dict[str, object] | None = None) -> None:
        cfg = config_section or {}
        self._author = str(cfg.get("author", "Security Analyst"))
        self._company = str(cfg.get("company", ""))
        self._classification = str(cfg.get("classification", "CONFIDENTIAL"))
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def render_html(self, bundle: ReportBundle, evidence_root: Path | None = None) -> str:
        """Render the report to a self-contained HTML string."""
        template = self._env.get_template("report.html")
        counts = self._severity_counts(bundle.findings)
        evidence_by_finding = self._group_evidence(bundle.evidence, evidence_root)
        return template.render(
            project=bundle.project,
            findings=bundle.findings,
            assets=[a for a in bundle.assets],
            scans=bundle.scans,
            evidence_by_finding=evidence_by_finding,
            severity_counts=counts,
            executive_summary=bundle.executive_summary or self._auto_summary(bundle.findings),
            author=self._author,
            company=self._company,
            classification=self._classification,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

    def render_markdown(self, bundle: ReportBundle) -> str:
        """Render the report to Markdown."""
        p = bundle.project
        out: list[str] = [
            f"# {p.name} — Security Assessment Report",
            "",
            f"*Prepared by {self._author}"
            + (f", {self._company}" if self._company else "")
            + f" · {datetime.now(timezone.utc):%Y-%m-%d}*",
            "",
            f"**Classification:** {self._classification}",
            "",
            "## Executive Summary",
            "",
            bundle.executive_summary or self._auto_summary(bundle.findings),
            "",
        ]

        counts = self._severity_counts(bundle.findings)
        if counts:
            out += ["| Severity | Count |", "|----------|-------|"]
            out += [f"| {sev} | {n} |" for sev, n in counts]
            out.append("")

        if p.scope_notes:
            out += ["## Scope", "", p.scope_notes, ""]

        if bundle.assets:
            out += ["### In-scope assets", "", "| Identifier | Type | Scope |",
                    "|------------|------|-------|"]
            out += [f"| {a.identifier} | {a.asset_type.value} | {a.scope.value} |"
                    for a in bundle.assets]
            out.append("")

        out += ["## Findings", ""]
        if not bundle.findings:
            out += ["_No findings recorded._", ""]
        for i, f in enumerate(bundle.findings, 1):
            out += [
                f"### {i}. {f.title} — {f.severity.value}",
                "",
                f"- **Affected:** {f.affected_asset or '—'}",
            ]
            if f.cvss_score is not None:
                vec = f" ({f.cvss_vector})" if f.cvss_vector else ""
                out.append(f"- **CVSS:** {f.cvss_score:.1f}{vec}")
            out += ["", f"**Description.** {f.description}", ""]
            if f.remediation:
                out += [f"**Remediation.** {f.remediation}", ""]
            if f.references:
                out += ["**References.**", "", f.references, ""]

        return "\n".join(out)

    def export(
        self,
        bundle: ReportBundle,
        output_path: Path,
        fmt: ReportFormat,
        evidence_root: Path | None = None,
    ) -> Path:
        """Render and write a report to *output_path*; returns the path written."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt is ReportFormat.MARKDOWN:
            output_path.write_text(self.render_markdown(bundle), encoding="utf-8")
        elif fmt is ReportFormat.HTML:
            output_path.write_text(self.render_html(bundle, evidence_root), encoding="utf-8")
        elif fmt is ReportFormat.PDF:
            self._write_pdf(self.render_html(bundle, evidence_root), output_path)
        else:  # pragma: no cover - exhaustive
            raise ValueError(f"Unsupported format: {fmt}")

        _LOG.info("Wrote %s report to %s", fmt.value, output_path)
        return output_path

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _write_pdf(html: str, output_path: Path) -> None:
        try:
            from weasyprint import HTML  # imported lazily; heavy + Linux-oriented
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "PDF export requires WeasyPrint (and its system libraries). "
                "Install it or export HTML/Markdown instead."
            ) from exc
        HTML(string=html).write_pdf(str(output_path))

    @staticmethod
    def _severity_counts(findings: list[Finding]) -> list[tuple[str, int]]:
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        ordered = sorted(counts.items(), key=lambda kv: kv[0].rank, reverse=True)
        return [(sev.value, n) for sev, n in ordered]

    @staticmethod
    def _auto_summary(findings: list[Finding]) -> str:
        if not findings:
            return ("This assessment did not identify reportable findings within the "
                    "defined scope.")
        highest = max(findings, key=lambda f: f.severity.rank)
        n = len(findings)
        return (
            f"This assessment identified {n} finding{'s' if n != 1 else ''} across the "
            f"in-scope environment, with a maximum severity of {highest.severity.value}. "
            "Findings, evidence, and prioritized remediation are detailed below."
        )

    def _group_evidence(
        self, evidence: list[Evidence], evidence_root: Path | None
    ) -> dict[int, list[dict[str, str]]]:
        """Group evidence by finding id, embedding screenshots as data URIs."""
        grouped: dict[int, list[dict[str, str]]] = {}
        for ev in evidence:
            if ev.finding_id is None:
                continue
            entry: dict[str, str] = {"caption": ev.caption, "kind": ev.kind, "embedded": ""}
            if ev.kind == "screenshot" and ev.path and evidence_root is not None:
                data_uri = self._embed_image(evidence_root / ev.path)
                if data_uri:
                    entry["embedded"] = data_uri
            grouped.setdefault(ev.finding_id, []).append(entry)
        return grouped

    @staticmethod
    def _embed_image(path: Path) -> str:
        try:
            raw = path.read_bytes()
        except OSError:
            _LOG.warning("Could not read evidence image: %s", path)
            return ""
        mime = mimetypes.guess_type(str(path))[0] or "image/png"
        encoded = base64.b64encode(raw).decode("ascii")
        return f"data:{mime};base64,{encoded}"
